// XenosCli - headless front-end for the process picker and injection core.
//
// The CLI owns discovery / fingerprint / filter / recent-target logic and
// drives the same InjectionCore used by the GUI:
//
//   XenosCli inject --dll payload.dll --mode games --filter mygame
//   XenosCli inject --dll payload.dll --pid 1234 --method manual
//   XenosCli inject --dll payload.dll --new "C:\Games\Game.exe"
//   XenosCli inject --dll payload.dll --wait Game.exe --timeout 60

#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../AppSettings.h"
#include "../EngineDetect.h"
#include "../InjectionCore.h"
#include "../Message.hpp"
#include "../ProcessCatalog.h"
#include "../DriverExtract.h"

namespace
{
    HANDLE g_stdout = INVALID_HANDLE_VALUE;
    HANDLE g_stderr = INVALID_HANDLE_VALUE;
    bool   g_consoleOut = false;
    bool   g_consoleErr = false;

    void InitOutput()
    {
        g_stdout = GetStdHandle( STD_OUTPUT_HANDLE );
        g_stderr = GetStdHandle( STD_ERROR_HANDLE );

        DWORD mode = 0;
        g_consoleOut = GetConsoleMode( g_stdout, &mode ) != FALSE;
        g_consoleErr = GetConsoleMode( g_stderr, &mode ) != FALSE;
    }

    void WriteAll( HANDLE handle, const wchar_t* text, size_t length, bool console )
    {
        if (handle == INVALID_HANDLE_VALUE || handle == nullptr)
            return;

        DWORD written = 0;
        if (console)
        {
            WriteConsoleW( handle, text, static_cast<DWORD>( length ), &written, nullptr );
            return;
        }

        int bytes = WideCharToMultiByte(
            CP_UTF8, 0, text, static_cast<int>( length ), nullptr, 0, nullptr, nullptr );

        if (bytes <= 0)
            return;

        std::string utf8( static_cast<size_t>( bytes ), '\0' );
        WideCharToMultiByte(
            CP_UTF8, 0, text, static_cast<int>( length ), &utf8[0], bytes, nullptr, nullptr );

        WriteFile( handle, utf8.data(), static_cast<DWORD>( utf8.size() ), &written, nullptr );
    }

    void Out( const wchar_t* fmt, ... )
    {
        wchar_t buffer[8192] = { 0 };

        va_list args;
        va_start( args, fmt );
        _vsnwprintf_s( buffer, _TRUNCATE, fmt, args );
        va_end( args );

        WriteAll( g_stdout, buffer, wcslen( buffer ), g_consoleOut );
    }

    void Err( const wchar_t* fmt, ... )
    {
        wchar_t buffer[4096] = { 0 };

        va_list args;
        va_start( args, fmt );
        _vsnwprintf_s( buffer, _TRUNCATE, fmt, args );
        va_end( args );

        WriteAll( g_stderr, buffer, wcslen( buffer ), g_consoleErr );
    }

    void CliMessageHandler( const std::wstring& msg, const std::wstring& /*title*/, Message::MsgType type )
    {
        const wchar_t* kind =
            type == Message::Error ? L"error" :
            type == Message::Warning ? L"warning" : L"info";

        Err( L"[%ls] %ls\n", kind, msg.c_str() );
    }

    std::wstring JsonEscape( const std::wstring& value )
    {
        std::wstring result;
        result.reserve( value.size() + 8 );

        for (wchar_t ch : value)
        {
            switch (ch)
            {
                case L'\\': result += L"\\\\"; break;
                case L'"':  result += L"\\\""; break;
                case L'\n': result += L"\\n";  break;
                case L'\r': result += L"\\r";  break;
                case L'\t': result += L"\\t";  break;
                default:
                    if (ch < 0x20)
                    {
                        wchar_t buf[8] = { 0 };
                        swprintf_s( buf, L"\\u%04x", static_cast<unsigned>( ch ) );
                        result += buf;
                    }
                    else
                    {
                        result += ch;
                    }
            }
        }

        return result;
    }

    std::wstring BaseName( const std::wstring& path )
    {
        auto pos = path.find_last_of( L"\\/" );
        return pos == std::wstring::npos ? path : path.substr( pos + 1 );
    }

    std::wstring AbsolutePath( const std::wstring& path )
    {
        wchar_t buffer[MAX_PATH * 2] = { 0 };
        DWORD len = GetFullPathNameW( path.c_str(), ARRAYSIZE( buffer ), buffer, nullptr );

        return (len > 0 && len < ARRAYSIZE( buffer )) ? std::wstring( buffer ) : path;
    }

    struct Options
    {
        PickerMode mode = PickerMode::Games;
        std::wstring filter;
        bool json = false;
        bool autoRecent = true;
        std::vector<std::wstring> positional;

        // inject
        std::vector<std::wstring> dlls;
        std::wstring targetPid;
        std::wstring targetName;
        std::wstring newExe;
        std::wstring waitExe;
        std::wstring cmdline;
        std::wstring initRoutine;
        std::wstring initArgs;
        int method = Normal;
        uint32_t mmapFlags = 0;
        bool unlink = false;
        bool hijack = false;
        bool erasePE = false;
        bool krnHandle = false;
        int delay = 0;
        int period = 0;
        int timeoutSec = 30;
        bool dryRun = false;
    };

    bool ParseMode( const std::wstring& value, PickerMode& mode )
    {
        if (_wcsicmp( value.c_str(), L"all" ) == 0)
            mode = PickerMode::All;
        else if (_wcsicmp( value.c_str(), L"games" ) == 0)
            mode = PickerMode::Games;
        else if (_wcsicmp( value.c_str(), L"recent" ) == 0)
            mode = PickerMode::Recent;
        else
            return false;

        return true;
    }

    bool ParseMethod( const std::wstring& value, int& method )
    {
        if (_wcsicmp( value.c_str(), L"normal" ) == 0)
            method = Normal;
        else if (_wcsicmp( value.c_str(), L"manual" ) == 0)
            method = Manual;
        else if (_wcsicmp( value.c_str(), L"kernel-thread" ) == 0)
            method = Kernel_Thread;
        else if (_wcsicmp( value.c_str(), L"kernel-apc" ) == 0)
            method = Kernel_APC;
        else if (_wcsicmp( value.c_str(), L"kernel-mmap" ) == 0)
            method = Kernel_MMap;
        else if (_wcsicmp( value.c_str(), L"driver" ) == 0)
            method = Kernel_DriverMap;
        else
            return false;

        return true;
    }

    const wchar_t* MethodName( int method )
    {
        switch (method)
        {
            case Normal:        return L"normal";
            case Manual:        return L"manual";
            case Kernel_Thread: return L"kernel-thread";
            case Kernel_APC:    return L"kernel-apc";
            case Kernel_MMap:   return L"kernel-mmap";
            case Kernel_DriverMap: return L"driver";
        }

        return L"normal";
    }

    bool ParseOptions( int argc, wchar_t** argv, int start, Options& options )
    {
        for (int i = start; i < argc; i++)
        {
            std::wstring arg = argv[i];

            if (arg == L"--mode" && i + 1 < argc)
            {
                if (!ParseMode( argv[++i], options.mode ))
                {
                    Err( L"Unknown mode: %ls\n", argv[i] );
                    return false;
                }
            }
            else if (arg == L"--filter" && i + 1 < argc)
            {
                options.filter = argv[++i];
            }
            else if ((arg == L"--engine" || arg == L"@") && i + 1 < argc)
            {
                options.filter += L" @" + std::wstring( argv[++i] );
            }
            else if (arg == L"--json")
            {
                options.json = true;
            }
            else if (arg == L"--no-recent")
            {
                options.autoRecent = false;
            }
            else if (arg == L"--dll" && i + 1 < argc)
            {
                options.dlls.emplace_back( argv[++i] );
            }
            else if (arg == L"--pid" && i + 1 < argc)
            {
                options.targetPid = argv[++i];
            }
            else if (arg == L"--name" && i + 1 < argc)
            {
                options.targetName = argv[++i];
            }
            else if (arg == L"--new" && i + 1 < argc)
            {
                options.newExe = argv[++i];
            }
            else if (arg == L"--wait" && i + 1 < argc)
            {
                options.waitExe = argv[++i];
            }
            else if (arg == L"--cmdline" && i + 1 < argc)
            {
                options.cmdline = argv[++i];
            }
            else if (arg == L"--init" && i + 1 < argc)
            {
                options.initRoutine = argv[++i];
            }
            else if (arg == L"--arg" && i + 1 < argc)
            {
                options.initArgs = argv[++i];
            }
            else if (arg == L"--method" && i + 1 < argc)
            {
                if (!ParseMethod( argv[++i], options.method ))
                {
                    Err( L"Unknown method: %ls\n", argv[i] );
                    return false;
                }
            }
            else if (arg == L"--manual")
            {
                options.method = Manual;
            }
            else if (arg == L"--mmap-flags" && i + 1 < argc)
            {
                options.mmapFlags |= static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--ldr-ref")
            {
                options.mmapFlags |= blackbone::CreateLdrRef;
            }
            else if (arg == L"--manual-imports")
            {
                options.mmapFlags |= blackbone::ManualImports;
            }
            else if (arg == L"--wipe-header")
            {
                options.mmapFlags |= blackbone::WipeHeader;
            }
            else if (arg == L"--hide-vad")
            {
                options.mmapFlags |= blackbone::HideVAD;
            }
            else if (arg == L"--no-tls")
            {
                options.mmapFlags |= blackbone::NoTLS;
            }
            else if (arg == L"--no-exceptions")
            {
                options.mmapFlags |= blackbone::NoExceptions;
            }
            else if (arg == L"--unlink")
            {
                options.unlink = true;
            }
            else if (arg == L"--hijack")
            {
                options.hijack = true;
            }
            else if (arg == L"--erase-pe")
            {
                options.erasePE = true;
            }
            else if (arg == L"--krn-handle")
            {
                options.krnHandle = true;
            }
            else if (arg == L"--delay" && i + 1 < argc)
            {
                options.delay = _wtoi( argv[++i] );
            }
            else if (arg == L"--period" && i + 1 < argc)
            {
                options.period = _wtoi( argv[++i] );
            }
            else if (arg == L"--timeout" && i + 1 < argc)
            {
                options.timeoutSec = _wtoi( argv[++i] );
            }
            else if (arg == L"--dry-run")
            {
                options.dryRun = true;
            }
            else if (arg == L"--help" || arg == L"-h" || arg == L"/?")
            {
                options.positional.emplace_back( L"--help" );
            }
            else if (!arg.empty() && arg[0] == L'-' && arg != L"-")
            {
                Err( L"Unknown option: %ls\n", arg.c_str() );
                return false;
            }
            else
            {
                options.positional.emplace_back( arg );
            }
        }

        return true;
    }

    void PrintUsage()
    {
        Out(
            L"XenosCli - process picker and injector\n"
            L"\n"
            L"Discovery:\n"
            L"  XenosCli list   [--mode all|games|recent] [--filter TEXT] [--json]  (default: all)\n"
            L"  XenosCli pick   [--mode ...] [--filter ...] [--no-recent] [--json] (default: saved mode)\n"
            L"  XenosCli detect <pid|name>\n"
            L"  XenosCli remember <pid|name>\n"
            L"  XenosCli forget\n"
            L"  XenosCli recent\n"
            L"  XenosCli engines\n"
            L"\n"
            L"Injection:\n"
            L"  XenosCli inject --dll <path> [--dll <path> ...] [target] [options]\n"
            L"\n"
            L"  Target (default: picker result = --mode/--filter + recent target):\n"
            L"    --pid <pid>              attach to a running PID\n"
            L"    --name <image.exe>       attach to a running process by name\n"
            L"    --new <exe>              create the process and inject\n"
            L"    --wait <exe>             wait for a new instance, then inject\n"
            L"    --timeout <sec>          wait timeout (default 30)\n"
            L"\n"
            L"  Options:\n"
            L"    --method normal|manual|kernel-thread|kernel-apc|kernel-mmap|driver\n"
            L"    --manual                 alias for --method manual\n"
            L"    --init <export>          call an exported initialization routine\n"
            L"    --arg <text>             argument passed to the init routine\n"
            L"    --cmdline <text>         command line for --new\n"
            L"    --ldr-ref --manual-imports --wipe-header --hide-vad\n"
            L"    --no-tls --no-exceptions --mmap-flags <hex>\n"
            L"    --unlink --hijack --erase-pe --krn-handle\n"
            L"    --delay <ms> --period <ms>\n"
            L"    --dry-run                resolve and validate, do not inject\n"
            L"    --json                   machine-readable result\n"
            L"\n"
            L"  GUI:\n"
            L"    XenosCli gui [gui arguments...]\n"
            L"\n"
            L"Filter syntax:\n"
            L"  name fragment     substring / prefix / fuzzy subsequence\n"
            L"  @unity            match engine tags (unity, unreal, godot, ...)\n"
            L"  pid:1234          match PID\n"
            L"  -token            exclude matches\n"
            L"\n"
            L"Examples:\n"
            L"  XenosCli list --mode games\n"
            L"  XenosCli list --filter \"@unity mono\"\n"
            L"  XenosCli inject --dll payload.dll --mode games --filter mygame --manual\n"
            L"  XenosCli inject --dll payload.dll --pid 1234 --method normal\n"
            L"  XenosCli inject --dll payload.dll --new \"C:\\Games\\MyGame\\MyGame.exe\" --timeout 60\n" );
    }

    void PrintEntry( const proc::Entry& entry )
    {
        Out(
            L"%6lu  %-22ls  %-34ls  %ls\n",
            entry.pid,
            entry.eng.tag.empty() ? L"-" : entry.eng.tag.c_str(),
            entry.name.c_str(),
            entry.path.c_str() );
    }

    void PrintJsonEntry( const proc::Entry& entry )
    {
        Out(
            L"{\"pid\":%lu,\"name\":\"%ls\",\"path\":\"%ls\","
            L"\"engine\":\"%ls\",\"variant\":\"%ls\",\"game\":%ls,\"score\":%d}",
            entry.pid,
            JsonEscape( entry.name ).c_str(),
            JsonEscape( entry.path ).c_str(),
            JsonEscape( entry.eng.engine ).c_str(),
            JsonEscape( entry.eng.variant ).c_str(),
            entry.eng.game ? L"true" : L"false",
            entry.eng.score );
    }

    int CommandList( const Options& options )
    {
        proc::Catalog catalog;
        catalog.Refresh();

        proc::QueryOptions query;
        query.mode = options.mode;
        query.filter = options.filter;

        auto entries = catalog.Query( query );

        if (options.json)
        {
            Out( L"[\n" );

            for (size_t i = 0; i < entries.size(); i++)
            {
                if (i)
                    Out( L",\n" );

                Out( L"  " );
                PrintJsonEntry( entries[i] );
            }

            Out( L"\n]\n" );
            return 0;
        }

        Out( L"%6ls  %-22ls  %-34ls  %ls\n", L"PID", L"ENGINE", L"NAME", L"PATH" );
        for (auto& entry : entries)
            PrintEntry( entry );

        Out( L"\n%zu process(es), mode=%ls%s%ls\n",
             entries.size(),
             options.mode == PickerMode::All ? L"all" :
             options.mode == PickerMode::Games ? L"games" : L"recent",
             options.filter.empty() ? L"" : L", filter=",
             options.filter.empty() ? L"" : options.filter.c_str() );

        return 0;
    }

    int CommandPick( const Options& options )
    {
        proc::Catalog catalog;
        catalog.Refresh();

        proc::QueryOptions query;
        query.mode = options.mode;
        query.filter = options.filter;

        auto entries = catalog.Query( query );
        if (entries.empty())
        {
            Err( L"no matching process\n" );
            return 1;
        }

        int index = -1;
        if (options.autoRecent)
            index = proc::Catalog::FindRecent( entries, AppSettings::Instance() );

        if (index < 0)
            index = 0;

        const auto& entry = entries[index];

        if (options.json)
        {
            PrintJsonEntry( entry );
            Out( L"\n" );
        }
        else
        {
            Out( L"%lu\t%ls\t%ls\t%ls\n",
                 entry.pid,
                 entry.name.c_str(),
                 entry.path.c_str(),
                 entry.eng.tag.c_str() );
        }

        return 0;
    }

    int CommandDetect( const Options& options )
    {
        if (options.positional.empty())
        {
            Err( L"detect requires <pid|name>\n" );
            return 2;
        }

        proc::Catalog catalog;
        catalog.Refresh();

        proc::Entry entry;
        if (!catalog.Find( options.positional.front(), entry ))
        {
            Err( L"process not found: %ls\n", options.positional.front().c_str() );
            return 1;
        }

        if (options.json)
        {
            PrintJsonEntry( entry );
            Out( L"\n" );
            return 0;
        }

        Out( L"PID:      %lu\n", entry.pid );
        Out( L"Name:     %ls\n", entry.name.c_str() );
        Out( L"Path:     %ls\n", entry.path.c_str() );
        Out( L"Engine:   %ls\n", entry.eng.tag.empty() ? L"-" : entry.eng.tag.c_str() );
        Out( L"Tags:     %ls\n", entry.eng.allTags.empty() ? L"-" : entry.eng.allTags.c_str() );
        Out( L"Is game:  %ls\n", entry.eng.game ? L"yes" : L"no" );
        Out( L"Score:    %d\n", entry.eng.score );

        return 0;
    }

    int CommandRemember( const Options& options )
    {
        if (options.positional.empty())
        {
            Err( L"remember requires <pid|name>\n" );
            return 2;
        }

        proc::Catalog catalog;
        catalog.Refresh();

        proc::Entry entry;
        if (!catalog.Find( options.positional.front(), entry ))
        {
            Err( L"process not found: %ls\n", options.positional.front().c_str() );
            return 1;
        }

        auto& settings = AppSettings::Instance();
        settings.Load();
        settings.RememberTarget( entry.name, entry.path );
        settings.lastPid = entry.pid;
        settings.Save();

        Out( L"remembered: %ls (%lu)\n", entry.name.c_str(), entry.pid );
        return 0;
    }

    int CommandForget( const Options& /*options*/ )
    {
        auto& settings = AppSettings::Instance();
        settings.Load();
        settings.ForgetTargets();
        settings.Save();

        Out( L"recent targets cleared\n" );
        return 0;
    }

    int CommandRecent( const Options& /*options*/ )
    {
        auto& settings = AppSettings::Instance();
        settings.Load();

        proc::Catalog catalog;
        catalog.Refresh();

        if (settings.recent.empty())
        {
            Out( L"no recent targets\n" );
            return 0;
        }

        Out( L"%6ls  %-34ls  %ls\n", L"PID", L"NAME", L"PATH" );

        for (auto& target : settings.recent)
        {
            const proc::Entry* found = nullptr;
            for (auto& entry : catalog.All())
            {
                if (target.Matches( entry.name, entry.path ))
                {
                    found = &entry;
                    break;
                }
            }

            if (found)
                Out( L"%6lu  %-34ls  %ls\n", found->pid, found->name.c_str(), found->path.c_str() );
            else
                Out( L"%6ls  %-34ls  %ls  (not running)\n", L"-", target.name.c_str(), target.path.c_str() );
        }

        return 0;
    }

    int CommandEngines( const Options& /*options*/ )
    {
        Out( L"%zu engine rule(s)\n", engine::Detector::Instance().RuleCount() );
        Out( L"Extend them with engines.ini next to the executable or in %%APPDATA%%\\Xenos.\n" );
        return 0;
    }

    int CommandGui( const Options& options )
    {
        wchar_t module[MAX_PATH] = { 0 };
        GetModuleFileNameW( nullptr, module, ARRAYSIZE( module ) );

        std::wstring dir( module );
        auto pos = dir.find_last_of( L"\\/" );
        if (pos != std::wstring::npos)
            dir.resize( pos );

        std::wstring gui = dir + (sizeof( void* ) == 8 ? L"\\Xenos64.exe" : L"\\Xenos.exe");

        std::wstring args;
        for (auto& arg : options.positional)
        {
            if (!args.empty())
                args += L" ";

            if (arg.find( L' ' ) != std::wstring::npos)
                args += L"\"" + arg + L"\"";
            else
                args += arg;
        }

        if (GetFileAttributesW( gui.c_str() ) == INVALID_FILE_ATTRIBUTES)
        {
            Err( L"GUI not found: %ls\n", gui.c_str() );
            return 1;
        }

        // The GUI requires administrator rights
        HINSTANCE result = ShellExecuteW(
            nullptr, L"runas", gui.c_str(),
            args.empty() ? nullptr : args.c_str(),
            dir.c_str(), SW_SHOWNORMAL );

        if (reinterpret_cast<INT_PTR>( result ) <= 32)
        {
            Err( L"failed to launch GUI (code %lld)\n", static_cast<long long>( reinterpret_cast<INT_PTR>( result ) ) );
            return 1;
        }

        Out( L"launched: %ls\n", gui.c_str() );
        return 0;
    }

    // ---------------------------------------------------------------------
    // Injection
    // ---------------------------------------------------------------------

    struct ResolvedTarget
    {
        DWORD pid = 0;
        std::wstring name;
        std::wstring path;
        ProcMode mode = Existing;
    };

    bool ResolveTarget( const Options& options, ResolvedTarget& target )
    {
        // Driver mapping does not need a process
        if (options.method == Kernel_DriverMap && options.targetPid.empty() &&
            options.targetName.empty() && options.newExe.empty() && options.waitExe.empty())
        {
            if (options.dlls.empty())
                return false;

            target.name = BaseName( options.dlls.front() );
            target.path = AbsolutePath( options.dlls.front() );
            return true;
        }

        if (!options.newExe.empty())
        {
            target.path = AbsolutePath( options.newExe );
            if (GetFileAttributesW( target.path.c_str() ) == INVALID_FILE_ATTRIBUTES)
                return false;

            target.name = BaseName( target.path );
            target.mode = NewProcess;
            return true;
        }

        if (!options.waitExe.empty())
        {
            const std::wstring name = BaseName( options.waitExe );

            proc::Catalog catalog;
            catalog.Refresh();

            std::set<DWORD> known;
            for (auto& entry : catalog.All())
            {
                if (_wcsicmp( entry.name.c_str(), name.c_str() ) == 0)
                    known.insert( entry.pid );
            }

            Err( L"waiting for a new %ls instance (%d s timeout)...\n", name.c_str(), options.timeoutSec );

            const ULONGLONG start = GetTickCount64();
            for (;;)
            {
                Sleep( 250 );
                catalog.Refresh();

                for (auto& entry : catalog.All())
                {
                    if (_wcsicmp( entry.name.c_str(), name.c_str() ) == 0 && known.count( entry.pid ) == 0)
                    {
                        target.pid = entry.pid;
                        target.name = entry.name;
                        target.path = entry.path;
                        target.mode = Existing;
                        return true;
                    }
                }

                if (options.timeoutSec > 0 && GetTickCount64() - start >= static_cast<ULONGLONG>( options.timeoutSec ) * 1000)
                    return false;
            }
        }

        if (!options.targetPid.empty() || !options.targetName.empty())
        {
            proc::Catalog catalog;
            catalog.Refresh();

            proc::Entry entry;
            const std::wstring key = !options.targetPid.empty() ? options.targetPid : options.targetName;
            if (!catalog.Find( key, entry ))
                return false;

            target.pid = entry.pid;
            target.name = entry.name;
            target.path = entry.path;
            target.mode = Existing;
            return true;
        }

        // Picker result (mode/filter + recent target)
        proc::Catalog catalog;
        catalog.Refresh();

        proc::QueryOptions query;
        query.mode = options.mode;
        query.filter = options.filter;

        auto entries = catalog.Query( query );
        if (entries.empty())
            return false;

        int index = options.autoRecent ? proc::Catalog::FindRecent( entries, AppSettings::Instance() ) : -1;
        if (index < 0)
            index = 0;

        target.pid = entries[index].pid;
        target.name = entries[index].name;
        target.path = entries[index].path;
        target.mode = Existing;
        return true;
    }

    bool LoadImages( const Options& options, vecPEImages& images, std::vector<std::wstring>& paths )
    {
        for (auto& dll : options.dlls)
        {
            std::wstring path = AbsolutePath( dll );

            if (GetFileAttributesW( path.c_str() ) == INVALID_FILE_ATTRIBUTES)
            {
                Err( L"image not found: %ls\n", path.c_str() );
                return false;
            }

            auto image = std::make_shared<blackbone::pe::PEImage>();
            NTSTATUS status = image->Load( path );
            if (!NT_SUCCESS( status ))
            {
                Err( L"invalid PE image: %ls (0x%08X)\n", path.c_str(), status );
                return false;
            }

            // Populate exports for --init / pure managed images
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

            images.emplace_back( std::move( image ) );
            paths.emplace_back( std::move( path ) );
        }

        return true;
    }

    bool IsElevated()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &token ))
            return false;

        TOKEN_ELEVATION elevation = { 0 };
        DWORD size = 0;
        bool elevated = GetTokenInformation(
            token, TokenElevation, &elevation, sizeof( elevation ), &size ) &&
            elevation.TokenIsElevated != 0;

        CloseHandle( token );
        return elevated;
    }

    int CommandInject( const Options& options )
    {
        if (options.dlls.empty())
        {
            Err( L"inject requires --dll <path>\n" );
            return 2;
        }

        ResolvedTarget target;
        if (!ResolveTarget( options, target ))
        {
            Err( L"target process not found\n" );
            return 1;
        }

        vecPEImages images;
        std::vector<std::wstring> paths;
        if (!LoadImages( options, images, paths ))
            return 2;

        if (options.dryRun)
        {
            if (options.json)
            {
                Out( L"{\"dryRun\":true,\"pid\":%lu,\"name\":\"%ls\",\"path\":\"%ls\",\"method\":\"%ls\",\"images\":[",
                     target.pid, JsonEscape( target.name ).c_str(), JsonEscape( target.path ).c_str(),
                     MethodName( options.method ) );

                for (size_t i = 0; i < paths.size(); i++)
                {
                    if (i)
                        Out( L"," );

                    Out( L"\"%ls\"", JsonEscape( paths[i] ).c_str() );
                }

                Out( L"]}\n" );
            }
            else
            {
                Out( L"target: %ls (%lu)\n", target.name.c_str(), target.pid );
                Out( L"path:   %ls\n", target.path.c_str() );
                Out( L"method: %ls\n", MethodName( options.method ) );

                for (size_t i = 0; i < paths.size(); i++)
                    Out( L"dll[%zu]: %ls\n", i, paths[i].c_str() );
            }

            return 0;
        }

        if (!IsElevated() && options.method < Kernel_Thread && !options.krnHandle)
            Err( L"note: not running elevated; elevated/protected targets will fail\n" );

        // Kernel methods and handle escalation need the embedded driver
        const bool needsDriver = options.method >= Kernel_Thread || options.krnHandle;
        if (needsDriver)
        {
            if (!IsElevated())
            {
                Err( L"kernel injection / --krn-handle requires administrator rights; run from an elevated prompt\n" );
                return 3;
            }

            DriverExtract::Instance().Extract();

            NTSTATUS driverStatus = blackbone::Driver().EnsureLoaded();
            if (!NT_SUCCESS( driverStatus ))
            {
                DriverExtract::Instance().Cleanup();
                Err( L"failed to load BlackBone driver (0x%08X)\n", driverStatus );

                // Driver state is undefined after a failed load; skip static teardown
                ExitProcess( 3 );
            }
        }

        InjectContext context;
        context.cfg.processMode = target.mode;
        context.cfg.injectMode = options.method;
        context.cfg.procName = target.name;
        context.cfg.procCmdLine = options.cmdline;
        context.cfg.initRoutine = options.initRoutine;
        context.cfg.initArgs = options.initArgs;
        context.cfg.mmapFlags = options.mmapFlags;
        context.cfg.hijack = options.hijack;
        context.cfg.unlink = options.unlink;
        context.cfg.erasePE = options.erasePE;
        context.cfg.krnHandle = options.krnHandle;
        context.cfg.delay = options.delay;
        context.cfg.period = options.period;
        context.cfg.images = paths;

        context.pid = target.pid;
        context.procPath = target.path;
        context.images = images;

        if (target.mode == NewProcess && context.cfg.procCmdLine.empty())
            context.cfg.procCmdLine = L"\"" + target.path + L"\"";

        HWND hwnd = nullptr;
        InjectionCore core( hwnd );

        NTSTATUS status = core.InjectMultiple( &context );
        if (!NT_SUCCESS( status ))
        {
            Err( L"injection failed: 0x%08X %ls\n", status,
                 blackbone::Utils::GetErrorDescription( status ).c_str() );

            if (!IsElevated() && (status == STATUS_ACCESS_DENIED || status == static_cast<NTSTATUS>( 0xC0000022 )))
                Err( L"hint: retry from an elevated prompt\n" );

            return 3;
        }

        if (options.json)
        {
            Out( L"{\"ok\":true,\"pid\":%lu,\"name\":\"%ls\",\"path\":\"%ls\",\"method\":\"%ls\",\"images\":%zu}\n",
                 context.pid,
                 JsonEscape( target.name ).c_str(),
                 JsonEscape( target.path ).c_str(),
                 MethodName( options.method ),
                 paths.size() );
        }
        else
        {
            Out( L"injected %zu image(s) into %ls (%lu) using %ls\n",
                 paths.size(), target.name.c_str(), context.pid, MethodName( options.method ) );
        }

        return 0;
    }
}

int wmain( int argc, wchar_t** argv )
{
    InitOutput();
    Message::SetHandler( &CliMessageHandler );

    AppSettings::Instance().Load();

    std::wstring command = argc > 1 ? argv[1] : L"list";

    // The GUI receives its arguments untouched (--load/--run/...)
    if (command == L"gui")
    {
        Options guiOptions;
        for (int i = 2; i < argc; i++)
            guiOptions.positional.emplace_back( argv[i] );

        return CommandGui( guiOptions );
    }

    Options options;
    options.mode = PickerMode::All;

    // `pick` mirrors the GUI's last used picker mode, `list` defaults to all
    if (command == L"pick" || command == L"select" || command == L"inject")
        options.mode = AppSettings::Instance().pickerMode;

    int start = argc > 1 ? 2 : 1;
    if (command == L"--help" || command == L"-h" || command == L"/?")
    {
        PrintUsage();
        return 0;
    }

    if (!ParseOptions( argc, argv, start, options ))
        return 2;

    if (!options.positional.empty() && options.positional.front() == L"--help")
    {
        PrintUsage();
        return 0;
    }

    if (command == L"list")
        return CommandList( options );
    if (command == L"pick" || command == L"select")
        return CommandPick( options );
    if (command == L"detect")
        return CommandDetect( options );
    if (command == L"remember")
        return CommandRemember( options );
    if (command == L"forget")
        return CommandForget( options );
    if (command == L"recent")
        return CommandRecent( options );
    if (command == L"engines")
        return CommandEngines( options );
    if (command == L"inject")
        return CommandInject( options );
    if (command == L"help")
    {
        PrintUsage();
        return 0;
    }

    Err( L"Unknown command: %ls\n\n", command.c_str() );
    PrintUsage();
    return 2;
}
