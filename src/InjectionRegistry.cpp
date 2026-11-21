#include "stdafx.h"
#include "InjectionRegistry.h"
#include "AppPaths.h"
#include "InjectionCore.h"
#include "Message.hpp"

#include <BlackBone/src/BlackBone/PE/PEImage.h>
#include <BlackBone/src/BlackBone/Process/RPC/RemoteFunction.hpp>

#include <algorithm>
#include <cstdint>

namespace
{
    const size_t MaxRecords = 100;

    std::wstring Trim( const std::wstring& str )
    {
        const wchar_t* ws = L" \t\r\n";
        auto begin = str.find_first_not_of( ws );
        if (begin == std::wstring::npos)
            return L"";

        auto end = str.find_last_not_of( ws );
        return str.substr( begin, end - begin + 1 );
    }

    uint64_t FileTimeToU64( const FILETIME& ft )
    {
        return (static_cast<uint64_t>( ft.dwHighDateTime ) << 32) | ft.dwLowDateTime;
    }

    uint64_t ProcessStartTime( HANDLE process )
    {
        FILETIME created = { 0 }, exit = { 0 }, kernel = { 0 }, user = { 0 };
        if (!process || !GetProcessTimes( process, &created, &exit, &kernel, &user ))
            return 0;

        return FileTimeToU64( created );
    }

    bool IsImageMapped( blackbone::Process& process, uint64_t baseAddress )
    {
        if (baseAddress == 0 || !process.core().handle())
            return false;

        uint16_t magic = 0;
        SIZE_T read = 0;

        if (!ReadProcessMemory(
            process.core().handle(), reinterpret_cast<LPCVOID>( baseAddress ),
            &magic, sizeof( magic ), &read ))
        {
            return false;
        }

        return read == sizeof( magic ) && magic == IMAGE_DOS_SIGNATURE;
    }

    bool ReadMappedEntry( blackbone::Process& process, uint64_t baseAddress, uint32_t& entryRva )
    {
        entryRva = 0;
        if (!process.core().handle() || baseAddress == 0)
            return false;

        uint32_t lfanew = 0;
        if (!ReadProcessMemory(
            process.core().handle(),
            reinterpret_cast<LPCVOID>( baseAddress + 0x3C ),
            &lfanew, sizeof( lfanew ), nullptr ))
        {
            return false;
        }

        const uint64_t nt = baseAddress + lfanew;

        uint32_t signature = 0;
        if (!ReadProcessMemory(
            process.core().handle(), reinterpret_cast<LPCVOID>( nt ),
            &signature, sizeof( signature ), nullptr ) || signature != 0x00004550)
        {
            return false;
        }

        // OptionalHeader.AddressOfEntryPoint is at offset 16 for PE32 and PE32+
        if (!ReadProcessMemory(
            process.core().handle(),
            reinterpret_cast<LPCVOID>( nt + 4 + 20 + 16 ),
            &entryRva, sizeof( entryRva ), nullptr ))
        {
            return false;
        }

        return true;
    }

    bool ReadMappedImageSize( blackbone::Process& process, uint64_t baseAddress, uint32_t& imageSize )
    {
        imageSize = 0;
        if (!process.core().handle() || baseAddress == 0)
            return false;

        uint32_t lfanew = 0;
        if (!ReadProcessMemory(
            process.core().handle(),
            reinterpret_cast<LPCVOID>( baseAddress + 0x3C ),
            &lfanew, sizeof( lfanew ), nullptr ))
        {
            return false;
        }

        // OptionalHeader.SizeOfImage is at offset 56 for PE32 and PE32+
        return ReadProcessMemory(
            process.core().handle(),
            reinterpret_cast<LPCVOID>( baseAddress + lfanew + 4 + 20 + 56 ),
            &imageSize, sizeof( imageSize ), nullptr ) != FALSE;
    }

    bool SameProcess( blackbone::Process& process, const InjectionRecord& record )
    {
        if (record.processStart == 0)
            return true;

        const uint64_t start = ProcessStartTime( process.core().handle() );
        return start != 0 && start == record.processStart;
    }

    bool LoadImageForReinject( const std::wstring& path, std::shared_ptr<blackbone::pe::PEImage>& image )
    {
        image = std::make_shared<blackbone::pe::PEImage>();
        if (!NT_SUCCESS( image->Load( path ) ))
            return false;

        if (image->pureIL() && image->net().Init( path ))
        {
            blackbone::ImageNET::mapMethodRVA methods;
            image->net().Parse( &methods );
        }
        else
        {
            blackbone::pe::vecExports exports;
            image->GetExports( exports );
        }

        image->Release( true );
        return true;
    }
}

const wchar_t* EjectStatusText( EjectStatus status )
{
    switch (status)
    {
        case EjectStatus::Ok:            return L"ejected";
        case EjectStatus::AlreadyGone:   return L"already unmapped";
        case EjectStatus::NotFound:      return L"unknown handle";
        case EjectStatus::StaleProcess:  return L"target process is gone or was reused";
        case EjectStatus::ModuleMismatch:return L"module identity mismatch";
        case EjectStatus::Unsupported:   return L"eject is not supported for this injection";
        case EjectStatus::Failed:        return L"eject failed";
    }

    return L"eject failed";
}

const wchar_t* InjectionStateText( InjectionState state )
{
    switch (state)
    {
        case InjectionState::Loaded:  return L"loaded";
        case InjectionState::Ejected: return L"ejected";
        case InjectionState::Stale:   return L"stale";
    }

    return L"unknown";
}

InjectionRegistry& InjectionRegistry::Instance()
{
    static InjectionRegistry instance;
    return instance;
}

InjectionRegistry::InjectionRegistry()
    : _path( apppaths::DataFile( L"injections.ini" ) )
{
}

uint64_t InjectionRegistry::ProcessStartTime( DWORD pid ) const
{
    HANDLE process = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
    if (!process)
        return 0;

    const uint64_t start = ::ProcessStartTime( process );
    CloseHandle( process );
    return start;
}

void InjectionRegistry::Load()
{
    std::lock_guard<std::mutex> lock( _lock );
    if (_loaded)
        return;

    _loaded = true;
    auto text = apppaths::ReadTextFile( _path );
    if (text.empty())
        return;

    InjectionRecord current;
    bool inRecord = false;
    size_t start = 0;

    while (start < text.size())
    {
        auto end = text.find( L'\n', start );
        if (end == std::wstring::npos)
            end = text.size();

        std::wstring line = Trim( text.substr( start, end - start ) );
        start = end + 1;

        if (line.empty() || line[0] == L';' || line[0] == L'#')
            continue;

        if (line.front() == L'[' && line.back() == L']')
        {
            if (inRecord && current.id != 0)
                _records.emplace_back( current );

            current = InjectionRecord();
            inRecord = false;

            if (_wcsicmp( line.c_str(), L"[Registry]" ) == 0)
                continue;

            current.id = static_cast<uint32_t>( _wtoi( line.substr( 1, line.size() - 2 ).c_str() ) );
            inRecord = current.id != 0;
            continue;
        }

        if (!inRecord)
        {
            auto eq = line.find( L'=' );
            if (eq != std::wstring::npos && _wcsicmp( Trim( line.substr( 0, eq ) ).c_str(), L"NextId" ) == 0)
                _nextId = (std::max<uint32_t>)( 1, static_cast<uint32_t>( _wtoi( Trim( line.substr( eq + 1 ) ).c_str() ) ) );

            continue;
        }

        auto eq = line.find( L'=' );
        if (eq == std::wstring::npos)
            continue;

        const std::wstring key = Trim( line.substr( 0, eq ) );
        const std::wstring value = Trim( line.substr( eq + 1 ) );

        if (_wcsicmp( key.c_str(), L"Pid" ) == 0)
            current.pid = static_cast<DWORD>( _wtoi( value.c_str() ) );
        else if (_wcsicmp( key.c_str(), L"Start" ) == 0)
            current.processStart = wcstoull( value.c_str(), nullptr, 0 );
        else if (_wcsicmp( key.c_str(), L"Image" ) == 0)
            current.imagePath = value;
        else if (_wcsicmp( key.c_str(), L"Name" ) == 0)
            current.moduleName = value;
        else if (_wcsicmp( key.c_str(), L"Base" ) == 0)
            current.baseAddress = wcstoull( value.c_str(), nullptr, 0 );
        else if (_wcsicmp( key.c_str(), L"Size" ) == 0)
            current.imageSize = static_cast<uint32_t>( _wtoi( value.c_str() ) );
        else if (_wcsicmp( key.c_str(), L"Method" ) == 0)
            current.method = _wtoi( value.c_str() );
        else if (_wcsicmp( key.c_str(), L"Manual" ) == 0)
            current.manual = _wtoi( value.c_str() ) != 0;
        else if (_wcsicmp( key.c_str(), L"Mmap" ) == 0)
            current.mmapFlags = static_cast<uint32_t>( wcstoul( value.c_str(), nullptr, 0 ) );
        else if (_wcsicmp( key.c_str(), L"Init" ) == 0)
            current.initRoutine = value;
        else if (_wcsicmp( key.c_str(), L"Args" ) == 0)
            current.initArgs = value;
        else if (_wcsicmp( key.c_str(), L"Unlink" ) == 0)
            current.unlink = _wtoi( value.c_str() ) != 0;
        else if (_wcsicmp( key.c_str(), L"Hijack" ) == 0)
            current.hijack = _wtoi( value.c_str() ) != 0;
        else if (_wcsicmp( key.c_str(), L"ErasePE" ) == 0)
            current.erasePE = _wtoi( value.c_str() ) != 0;
        else if (_wcsicmp( key.c_str(), L"KrnHandle" ) == 0)
            current.krnHandle = _wtoi( value.c_str() ) != 0;
        else if (_wcsicmp( key.c_str(), L"State" ) == 0)
            current.state = _wtoi( value.c_str() );
        else if (_wcsicmp( key.c_str(), L"Time" ) == 0)
            current.injectedAt = wcstoull( value.c_str(), nullptr, 0 );
        else if (_wcsicmp( key.c_str(), L"Delay" ) == 0)
            current.delay = static_cast<uint32_t>( _wtoi( value.c_str() ) );
        else if (_wcsicmp( key.c_str(), L"Period" ) == 0)
            current.period = static_cast<uint32_t>( _wtoi( value.c_str() ) );
    }

    if (inRecord && current.id != 0)
        _records.emplace_back( current );

    // Keep the id sequence ahead of all loaded entries
    for (auto& record : _records)
        _nextId = (std::max)( _nextId, record.id + 1 );
}

void InjectionRegistry::Save()
{
    std::lock_guard<std::mutex> lock( _lock );
    SaveUnlocked();
}

void InjectionRegistry::SaveUnlocked()
{
    std::wstring text;
    text += L"; Xenos injection handles\n";
    text += L"[Registry]\n";
    text += L"NextId=" + std::to_wstring( _nextId ) + L"\n";

    std::sort( _records.begin(), _records.end(), []( const InjectionRecord& a, const InjectionRecord& b )
    {
        return a.id < b.id;
    } );

    for (auto& record : _records)
    {
        text += L"\n[" + std::to_wstring( record.id ) + L"]\n";
        text += L"Pid=" + std::to_wstring( record.pid ) + L"\n";
        text += L"Start=" + std::to_wstring( record.processStart ) + L"\n";
        text += L"Image=" + record.imagePath + L"\n";
        text += L"Name=" + record.moduleName + L"\n";
        text += L"Base=" + std::to_wstring( record.baseAddress ) + L"\n";
        text += L"Size=" + std::to_wstring( record.imageSize ) + L"\n";
        text += L"Method=" + std::to_wstring( record.method ) + L"\n";
        text += L"Manual=" + std::wstring( record.manual ? L"1" : L"0" ) + L"\n";
        text += L"Mmap=" + std::to_wstring( record.mmapFlags ) + L"\n";
        text += L"Init=" + record.initRoutine + L"\n";
        text += L"Args=" + record.initArgs + L"\n";
        text += L"Unlink=" + std::wstring( record.unlink ? L"1" : L"0" ) + L"\n";
        text += L"Hijack=" + std::wstring( record.hijack ? L"1" : L"0" ) + L"\n";
        text += L"ErasePE=" + std::wstring( record.erasePE ? L"1" : L"0" ) + L"\n";
        text += L"KrnHandle=" + std::wstring( record.krnHandle ? L"1" : L"0" ) + L"\n";
        text += L"State=" + std::to_wstring( record.state ) + L"\n";
        text += L"Time=" + std::to_wstring( record.injectedAt ) + L"\n";
        text += L"Delay=" + std::to_wstring( record.delay ) + L"\n";
        text += L"Period=" + std::to_wstring( record.period ) + L"\n";
    }

    apppaths::WriteTextFile( _path, text );
}

uint32_t InjectionRegistry::Add( const NewInjection& data )
{
    Load();

    std::lock_guard<std::mutex> lock( _lock );

    // A new injection replaces any older loaded record at the same address
    for (auto& record : _records)
    {
        if (record.pid == data.pid && record.baseAddress == data.baseAddress &&
            _wcsicmp( record.imagePath.c_str(), data.imagePath.c_str() ) == 0 &&
            record.state == static_cast<int>( InjectionState::Loaded ))
        {
            record.state = static_cast<int>( InjectionState::Ejected );
        }
    }

    InjectionRecord record;
    record.id = _nextId++;
    record.pid = data.pid;
    record.processStart = ProcessStartTime( data.pid );
    record.imagePath = data.imagePath;
    record.moduleName = data.moduleName;
    record.baseAddress = data.baseAddress;
    record.imageSize = data.imageSize;
    record.method = data.method;
    record.manual = data.manual;
    record.mmapFlags = data.mmapFlags;
    record.initRoutine = data.initRoutine;
    record.initArgs = data.initArgs;
    record.unlink = data.unlink;
    record.hijack = data.hijack;
    record.erasePE = data.erasePE;
    record.krnHandle = data.krnHandle;
    record.delay = data.delay;
    record.period = data.period;
    record.state = static_cast<int>( InjectionState::Loaded );

    FILETIME now = { 0 };
    GetSystemTimeAsFileTime( &now );
    record.injectedAt = FileTimeToU64( now );

    _records.emplace_back( record );

    // Bound the history, dropping finished entries first
    while (_records.size() > MaxRecords)
    {
        auto it = std::find_if( _records.begin(), _records.end(), []( const InjectionRecord& r )
        {
            return r.state != static_cast<int>( InjectionState::Loaded );
        } );

        if (it == _records.end())
            it = _records.begin();

        _records.erase( it );
    }

    SaveUnlocked();
    return record.id;
}

bool InjectionRegistry::Find( uint32_t id, InjectionRecord& out ) const
{
    const_cast<InjectionRegistry*>( this )->Load();

    std::lock_guard<std::mutex> lock( _lock );
    for (auto& record : _records)
    {
        if (record.id == id)
        {
            out = record;
            return true;
        }
    }

    return false;
}

std::vector<InjectionRecord> InjectionRegistry::All() const
{
    const_cast<InjectionRegistry*>( this )->Load();

    std::lock_guard<std::mutex> lock( _lock );
    return _records;
}

std::vector<InjectionRecord> InjectionRegistry::ForPid( DWORD pid ) const
{
    auto all = All();
    all.erase( std::remove_if( all.begin(), all.end(), [&]( const InjectionRecord& r )
    {
        return r.pid != pid;
    } ), all.end() );

    return all;
}

void InjectionRegistry::SetState( uint32_t id, InjectionState state )
{
    Load();

    std::lock_guard<std::mutex> lock( _lock );
    for (auto& record : _records)
    {
        if (record.id == id)
        {
            record.state = static_cast<int>( state );
            SaveUnlocked();
            return;
        }
    }
}

void InjectionRegistry::Remove( uint32_t id )
{
    Load();

    std::lock_guard<std::mutex> lock( _lock );
    _records.erase( std::remove_if( _records.begin(), _records.end(), [&]( const InjectionRecord& r )
    {
        return r.id == id;
    } ), _records.end() );

    SaveUnlocked();
}

bool IsInjectionLive( const InjectionRecord& record )
{
    if (record.baseAddress == 0)
        return false;

    HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, record.pid );

    if (!process)
        return false;

    bool live = false;

    if (record.processStart == 0 || ProcessStartTime( process ) == record.processStart)
    {
        uint16_t magic = 0;
        SIZE_T read = 0;

        live = ReadProcessMemory(
            process, reinterpret_cast<LPCVOID>( record.baseAddress ),
            &magic, sizeof( magic ), &read ) &&
            read == sizeof( magic ) && magic == IMAGE_DOS_SIGNATURE;
    }

    CloseHandle( process );
    return live;
}

EjectStatus UnloadModuleAt( blackbone::Process& process, uint64_t baseAddress,
                            const std::wstring& moduleName, const std::wstring& imagePath,
                            bool manual, uint32_t expectedSize, bool force, std::wstring& message )
{
    message.clear();

    if (!IsImageMapped( process, baseAddress ))
    {
        message = L"module is no longer mapped";
        return EjectStatus::AlreadyGone;
    }

    if (!force && expectedSize != 0)
    {
        uint32_t mappedSize = 0;
        if (ReadMappedImageSize( process, baseAddress, mappedSize ) && mappedSize != expectedSize)
        {
            message = L"image size at the recorded base does not match";
            return EjectStatus::ModuleMismatch;
        }
    }

    if (!manual)
    {
        auto module = process.modules().GetModule(
            static_cast<blackbone::module_t>( baseAddress ), true, blackbone::LdrList );

        if (!module)
            module = process.modules().GetModule(
                static_cast<blackbone::module_t>( baseAddress ), true, blackbone::Sections );

        if (!module)
            module = process.modules().GetModule(
                static_cast<blackbone::module_t>( baseAddress ), true, blackbone::PEHeaders );

        if (!module && !force)
        {
            message = L"module is not present in the target loader lists";
            return EjectStatus::ModuleMismatch;
        }

        if (module && !force && !moduleName.empty() &&
            _wcsicmp( module->name.c_str(), moduleName.c_str() ) != 0)
        {
            message = L"module name mismatch: expected '" + moduleName +
                L"', found '" + module->name + L"'";
            return EjectStatus::ModuleMismatch;
        }

        if (module)
        {
            bool unloaded = false;

            // FreeLibrary performs proper loader refcount bookkeeping.
            // BlackBone's LdrUnloadDll path crashes some targets.
            auto kernel32 = process.modules().GetModule( L"kernel32.dll", blackbone::LdrList );
            if (kernel32)
            {
                auto freeLibrary = process.modules().GetExport( kernel32, "FreeLibrary" );
                if (freeLibrary)
                {
                    using fnFreeLibrary = int( __stdcall* )(void*);

                    blackbone::RemoteFunction<fnFreeLibrary> fn(
                        process, static_cast<blackbone::ptr_t>( freeLibrary->procAddress ) );

                    auto result = fn.Call( reinterpret_cast<void*>( baseAddress ) );
                    unloaded = NT_SUCCESS( result.status ) && result.result( 0 ) != 0;
                }
            }

            if (!unloaded)
            {
                if (!force)
                {
                    message = L"FreeLibrary failed inside the target";
                    return EjectStatus::Failed;
                }

                // Explicitly forced: fall back to BlackBone's LdrUnloadDll path.
                NTSTATUS unloadStatus = process.modules().Unload( module );
                if (!NT_SUCCESS( unloadStatus ))
                {
                    message = L"LdrUnloadDll failed: " + blackbone::Utils::GetErrorDescription( unloadStatus );
                    return EjectStatus::Failed;
                }
            }
        }
    }
    else
    {
        // Manually mapped image: call DllMain(DLL_PROCESS_DETACH) and free the
        // private image. This is best-effort and inherently risky.
        uint32_t entryRva = 0;
        uint64_t entry = 0;

        if (ReadMappedEntry( process, baseAddress, entryRva ) && entryRva != 0)
            entry = baseAddress + entryRva;
        else if (!imagePath.empty())
        {
            blackbone::pe::PEImage image;
            if (NT_SUCCESS( image.Load( imagePath ) ))
                entry = image.entryPoint( static_cast<blackbone::module_t>( baseAddress ) );
        }

        if (entry != 0)
        {
            using fnDllMain = int( __stdcall* )(void*, unsigned long, void*);

            blackbone::RemoteFunction<fnDllMain> dllMain(
                process, static_cast<blackbone::ptr_t>( entry ) );

            auto result = dllMain.Call(
                reinterpret_cast<void*>( baseAddress ),
                static_cast<unsigned long>( 0 /*DLL_PROCESS_DETACH*/ ),
                static_cast<void*>( nullptr ) );

            if (!NT_SUCCESS( result.status ))
            {
                message = L"DllMain(DLL_PROCESS_DETACH) call failed: " +
                    blackbone::Utils::GetErrorDescription( result.status );
                return EjectStatus::Failed;
            }

            if (result.result( 0 ) == 0)
                message = L"warning: DllMain(DLL_PROCESS_DETACH) returned FALSE; ";
        }

        if (!VirtualFreeEx(
            process.core().handle(),
            reinterpret_cast<LPVOID>( baseAddress ),
            0, MEM_RELEASE ))
        {
            message += L"VirtualFreeEx failed (Win32 error " +
                std::to_wstring( GetLastError() ) + L")";
            return EjectStatus::Failed;
        }
    }

    Sleep( 50 ); // Let loader/worker threads settle

    if (IsImageMapped( process, baseAddress ) && !force)
    {
        message += L"module is still mapped (outstanding reference?)";
        return EjectStatus::Failed;
    }

    if (message.empty())
        message = L"module unloaded";

    return EjectStatus::Ok;
}

EjectStatus EjectInjection( uint32_t id, bool force, std::wstring& message )
{
    message.clear();

    InjectionRecord record;
    if (!InjectionRegistry::Instance().Find( id, record ))
    {
        message = L"no injection with handle #" + std::to_wstring( id );
        return EjectStatus::NotFound;
    }

    if (record.state == static_cast<int>( InjectionState::Ejected ))
    {
        message = L"handle #" + std::to_wstring( id ) + L" is already ejected";
        return EjectStatus::AlreadyGone;
    }

    blackbone::Process process;
    NTSTATUS status = process.Attach( record.pid );
    if (!NT_SUCCESS( status ))
    {
        InjectionRegistry::Instance().SetState( id, InjectionState::Stale );
        message = L"can not attach to PID " + std::to_wstring( record.pid ) +
            L" (" + blackbone::Utils::GetErrorDescription( status ) + L")";
        return EjectStatus::StaleProcess;
    }

    if (!SameProcess( process, record ))
    {
        InjectionRegistry::Instance().SetState( id, InjectionState::Stale );
        message = L"PID " + std::to_wstring( record.pid ) + L" was reused by another process";
        return EjectStatus::StaleProcess;
    }

    const EjectStatus result = UnloadModuleAt(
        process, record.baseAddress, record.moduleName, record.imagePath,
        record.manual, record.imageSize, force, message );

    if (result == EjectStatus::Ok || result == EjectStatus::AlreadyGone)
        InjectionRegistry::Instance().SetState( id, InjectionState::Ejected );

    process.Detach();
    return result;
}

bool ReinjectInjection( uint32_t id, HWND owner, uint32_t& newId, std::wstring& message )
{
    newId = 0;
    message.clear();

    InjectionRecord record;
    if (!InjectionRegistry::Instance().Find( id, record ))
    {
        message = L"no injection with handle #" + std::to_wstring( id );
        return false;
    }

    // Never inject into a stale process
    HANDLE check = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, record.pid );
    if (!check)
    {
        message = L"target PID " + std::to_wstring( record.pid ) + L" is not running";
        return false;
    }

    const uint64_t start = ProcessStartTime( check );
    CloseHandle( check );

    if (record.processStart != 0 && start != record.processStart)
    {
        message = L"target PID " + std::to_wstring( record.pid ) + L" was reused by another process";
        return false;
    }

    // Remove any other loaded instance of the same image in this process,
    // otherwise LdrLoadDll would report STATUS_IMAGE_ALREADY_LOADED.
    for (auto& other : InjectionRegistry::Instance().ForPid( record.pid ))
    {
        if (other.id == id)
            continue;

        if (other.state != static_cast<int>( InjectionState::Loaded ))
            continue;

        if (_wcsicmp( other.imagePath.c_str(), record.imagePath.c_str() ) != 0)
            continue;

        std::wstring ignored;
        EjectInjection( other.id, false, ignored );
    }

    if (record.state == static_cast<int>( InjectionState::Loaded ))
    {
        std::wstring ejectMessage;
        EjectStatus status = EjectInjection( id, false, ejectMessage );
        if (status != EjectStatus::Ok && status != EjectStatus::AlreadyGone)
        {
            message = L"can not eject before re-inject: " + ejectMessage;
            return false;
        }
    }

    std::shared_ptr<blackbone::pe::PEImage> image;
    if (!LoadImageForReinject( record.imagePath, image ))
    {
        message = L"can not load image: " + record.imagePath;
        return false;
    }

    InjectContext context;
    context.cfg.processMode = Existing;
    context.cfg.injectMode = record.method;
    context.cfg.procName = record.moduleName;
    context.cfg.initRoutine = record.initRoutine;
    context.cfg.initArgs = record.initArgs;
    context.cfg.mmapFlags = record.mmapFlags;
    context.cfg.hijack = record.hijack;
    context.cfg.unlink = record.unlink;
    context.cfg.erasePE = record.erasePE;
    context.cfg.krnHandle = record.krnHandle;
    context.cfg.delay = record.delay;
    context.cfg.period = record.period;
    context.cfg.images.emplace_back( record.imagePath );

    context.pid = record.pid;
    context.procPath = record.imagePath;
    context.images.emplace_back( image );

    HWND hwnd = owner;
    InjectionCore core( hwnd );

    NTSTATUS status = core.InjectMultiple( &context );
    if (!NT_SUCCESS( status ))
    {
        message = L"re-injection failed: " + blackbone::Utils::GetErrorDescription( status );
        return false;
    }

    if (!context.injectionIds.empty())
        newId = static_cast<uint32_t>( _wtoi( context.injectionIds.back().c_str() ) );

    message = L"re-injected '" + record.moduleName + L"' into PID " + std::to_wstring( record.pid );
    if (newId != 0)
        message += L" (handle #" + std::to_wstring( newId ) + L")";

    return true;
}

