#include "WatchInjector.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>
#include <random>
#include <set>
#include <utility>

namespace watch
{
    namespace
    {
        std::wstring Lower( std::wstring value )
        {
            std::transform( value.begin(), value.end(), value.begin(),
                []( wchar_t ch ) { return static_cast<wchar_t>( std::towlower( ch ) ); } );
            return value;
        }

        std::wstring BaseName( const std::wstring& path )
        {
            const auto pos = path.find_last_of( L"\\/" );
            return pos == std::wstring::npos ? path : path.substr( pos + 1 );
        }

        std::wstring AbsolutePath( const std::wstring& path )
        {
            wchar_t buffer[MAX_PATH * 2] = { 0 };
            const DWORD length = GetFullPathNameW(
                path.c_str(), ARRAYSIZE( buffer ), buffer, nullptr );

            return (length > 0 && length < ARRAYSIZE( buffer )) ? std::wstring( buffer ) : path;
        }

        bool SamePath( const std::wstring& left, const std::wstring& right )
        {
            if (left.empty() || right.empty())
                return false;

            return _wcsicmp( AbsolutePath( left ).c_str(), AbsolutePath( right ).c_str() ) == 0;
        }

        uint64_t FileTimeToU64( const FILETIME& value )
        {
            return (static_cast<uint64_t>( value.dwHighDateTime ) << 32) | value.dwLowDateTime;
        }

        struct SeenKey
        {
            DWORD    pid = 0;
            uint64_t startTime = 0;

            bool operator<( const SeenKey& other ) const
            {
                if (pid != other.pid)
                    return pid < other.pid;

                return startTime < other.startTime;
            }
        };

        SeenKey KeyOf( const ProcessRef& process )
        {
            return SeenKey{ process.pid, process.startTime };
        }
    }

    Watcher::Watcher( Options options, InjectFn inject, LogFn log )
        : _options( std::move( options ) )
        , _inject( std::move( inject ) )
        , _log( std::move( log ) )
    {
        if (_options.readiness.stableChecks == 0)
            _options.readiness.stableChecks = 1;

        if (_options.readiness.intervalMs == 0)
            _options.readiness.intervalMs = 100;

        if (_options.pollMs == 0)
            _options.pollMs = 250;

        if (_options.retry.attempts == 0)
            _options.retry.attempts = 1;
    }

    Watcher::~Watcher() = default;

    void Watcher::Stop()
    {
        _stop = true;
    }

    void Watcher::Log( const std::wstring& text ) const
    {
        if (_log)
            _log( text );
        else
            OutputDebugStringW( (text + L"\n").c_str() );
    }

    bool Watcher::Sleep( uint32_t ms ) const
    {
        // Wake up regularly so Stop() is honored even with long delays.
        const uint32_t slice = 50;
        uint32_t remaining = ms;

        while (remaining > 0 && !_stop)
        {
            const uint32_t chunk = (std::min)( remaining, slice );
            ::Sleep( chunk );
            remaining -= chunk;
        }

        return !_stop;
    }

    bool Watcher::TargetAlive( const ProcessRef& target ) const
    {
        HANDLE process = OpenProcess(
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.pid );

        if (process == nullptr)
        {
            // Access denied does not mean the process is gone.
            return GetLastError() != ERROR_INVALID_PARAMETER;
        }

        const DWORD wait = WaitForSingleObject( process, 0 );
        CloseHandle( process );

        if (wait != WAIT_TIMEOUT)
            return false;

        // Protect against PID reuse when the target creation time is known.
        if (target.startTime != 0)
        {
            ProcessRef current;
            if (QueryProcess( target.pid, current ) &&
                 current.startTime != 0 &&
                 current.startTime != target.startTime)
            {
                return false;
            }
        }

        return true;
    }

    bool Watcher::Scan( std::vector<ProcessRef>& targets ) const
    {
        targets.clear();

        HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W entry = { 0 };
        entry.dwSize = sizeof( entry );

        const std::wstring wantedName = Lower( _options.target.name );
        const std::wstring wantedPath = _options.target.path;

        if (Process32FirstW( snapshot, &entry ))
        {
            do
            {
                if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4 ||
                    entry.th32ProcessID == GetCurrentProcessId())
                {
                    continue;
                }

                if (!wantedName.empty() && Lower( entry.szExeFile ) != wantedName)
                    continue;

                ProcessRef process;
                const bool detailed = QueryProcess( entry.th32ProcessID, process );
                if (!detailed)
                {
                    process.pid = entry.th32ProcessID;
                    process.name = entry.szExeFile;
                }

                if (!wantedPath.empty() && !SamePath( process.path, wantedPath ))
                    continue;

                targets.emplace_back( std::move( process ) );
            }
            while (Process32NextW( snapshot, &entry ));
        }

        CloseHandle( snapshot );
        return true;
    }

    bool Watcher::WaitUntilReady( const ProcessRef& target, std::wstring& reason )
    {
        const uint64_t start = GetTickCount64();
        uint32_t stable = 0;
        std::wstring lastReason;

        for (;;)
        {
            if (_stop)
            {
                reason = L"canceled";
                return false;
            }

            if (_options.runTimeoutMs != 0 &&
                GetTickCount64() - _start >= _options.runTimeoutMs)
            {
                reason = L"watch timed out";
                return false;
            }

            if (!TargetAlive( target ))
            {
                reason = L"process exited before it became ready";
                return false;
            }

            if (IsProcessReady( target.pid, _options.readiness, reason ))
            {
                stable++;

                if (stable >= _options.readiness.stableChecks)
                {
                    // AmalgamLoader waits an extra few seconds after the game
                    // looks ready so late initialization (anti-cheat, engine
                    // subsystems) is not raced.
                    if (_options.readiness.settleMs != 0)
                    {
                        Log( L"PID " + std::to_wstring( target.pid ) +
                             L" is stable; waiting " +
                             std::to_wstring( _options.readiness.settleMs ) +
                             L" ms before injecting" );

                        if (!Sleep( _options.readiness.settleMs ))
                        {
                            reason = L"canceled";
                            return false;
                        }

                        if (!TargetAlive( target ))
                        {
                            reason = L"process exited during the settle delay";
                            return false;
                        }
                    }

                    return true;
                }

                lastReason = L"stability check " + std::to_wstring( stable ) + L"/" +
                    std::to_wstring( _options.readiness.stableChecks );
            }
            else
            {
                stable = 0;
                lastReason = reason;
            }

            if (_options.readiness.timeoutMs != 0 &&
                GetTickCount64() - start >= _options.readiness.timeoutMs)
            {
                reason = L"timed out waiting for readiness";
                if (!lastReason.empty())
                    reason += L" (" + lastReason + L")";

                return false;
            }

            if (!Sleep( _options.readiness.intervalMs ))
            {
                reason = L"canceled";
                return false;
            }
        }
    }

    bool Watcher::InjectWithRetry( const ProcessRef& target, std::wstring& message )
    {
        uint32_t delay = _options.retry.baseDelayMs;
        std::mt19937 rng( static_cast<uint32_t>( GetTickCount64() ^ target.pid ) );

        for (uint32_t attempt = 1; attempt <= _options.retry.attempts; attempt++)
        {
            if (_stop)
            {
                message = L"canceled";
                return false;
            }

            if (_options.runTimeoutMs != 0 &&
                GetTickCount64() - _start >= _options.runTimeoutMs)
            {
                message = L"watch timed out";
                return false;
            }

            if (!TargetAlive( target ))
            {
                message = L"process exited before injection";
                return false;
            }

            Log( L"injecting into " + target.name + L" (PID " +
                 std::to_wstring( target.pid ) + L"), attempt " +
                 std::to_wstring( attempt ) + L"/" +
                 std::to_wstring( _options.retry.attempts ) );

            if (_inject( target, message ))
                return true;

            if (!message.empty())
                Log( L"injection failed: " + message );
            else
                Log( L"injection failed" );

            if (attempt < _options.retry.attempts)
            {
                const uint32_t jitter = _options.retry.jitterMs == 0 ? 0 :
                    rng() % (_options.retry.jitterMs + 1);

                Log( L"retrying in " + std::to_wstring( delay + jitter ) + L" ms" );

                if (!Sleep( delay + jitter ))
                {
                    message = L"canceled";
                    return false;
                }

                delay = (std::min)( delay * 2, 30000u );
            }
        }

        return false;
    }

    bool Watcher::Run()
    {
        _start = GetTickCount64();

        if (_options.target.name.empty() && _options.target.path.empty())
        {
            _last.message = L"no target process specified";
            Log( _last.message );
            return false;
        }

        if (!_options.target.path.empty() && _options.target.name.empty())
            _options.target.name = BaseName( _options.target.path );

        std::set<SeenKey> seen;
        std::vector<ProcessRef> pending;
        bool firstScan = true;
        bool injectedAny = false;

        for (;;)
        {
            if (_stop)
                break;

            if (_options.runTimeoutMs != 0 &&
                GetTickCount64() - _start >= _options.runTimeoutMs)
            {
                _last.message = L"watch timed out";
                Log( _last.message );
                break;
            }

            std::vector<ProcessRef> current;
            if (!Scan( current ))
            {
                Log( L"failed to enumerate processes" );
            }

            for (auto& process : current)
            {
                const SeenKey key = KeyOf( process );
                if (seen.count( key ) != 0)
                    continue;

                seen.insert( key );

                // Existing instances are optionally ignored on the first scan;
                // later scans only contain newly started processes.
                if (firstScan && !_options.includeExisting)
                    continue;

                pending.emplace_back( process );
            }

            firstScan = false;

            while (!pending.empty() && !_stop)
            {
                ProcessRef target = pending.front();
                pending.erase( pending.begin() );

                if (!TargetAlive( target ))
                    continue;

                Log( L"target " + target.name + L" detected (PID " +
                     std::to_wstring( target.pid ) + L")" );

                std::wstring reason;
                if (!WaitUntilReady( target, reason ))
                {
                    Log( L"not injecting PID " + std::to_wstring( target.pid ) +
                         L": " + reason );

                    if (_options.once)
                    {
                        _last.process = target;
                        _last.message = reason;
                        return false;
                    }

                    continue;
                }

                std::wstring message;
                if (InjectWithRetry( target, message ))
                {
                    injectedAny = true;
                    _last.injected = true;
                    _last.process = target;
                    _last.message = message;

                    if (_options.once)
                        return true;
                }
                else
                {
                    _last.injected = false;
                    _last.process = target;
                    _last.message = message;

                    if (_options.once)
                        return false;
                }
            }

            if (_options.exitWhenGone && current.empty())
                break;

            if (!Sleep( _options.pollMs ))
                break;
        }

        if (_last.message.empty())
            _last.message = _stop ? L"stopped" : L"no target process found";

        return injectedAny;
    }

    bool QueryProcess( DWORD pid, ProcessRef& out )
    {
        out = ProcessRef();
        out.pid = pid;

        HANDLE process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );

        if (process == nullptr)
            return false;

        wchar_t path[MAX_PATH * 2] = { 0 };
        DWORD size = ARRAYSIZE( path );

        if (QueryFullProcessImageNameW( process, 0, path, &size ))
        {
            out.path.assign( path, size );
            out.name = BaseName( out.path );
        }

        FILETIME creation = { 0 }, exitTime = { 0 }, kernel = { 0 }, user = { 0 };
        if (GetProcessTimes( process, &creation, &exitTime, &kernel, &user ))
            out.startTime = FileTimeToU64( creation );

        CloseHandle( process );

        return !out.name.empty();
    }

    bool IsProcessReady( DWORD pid, const Readiness& options, std::wstring& reason )
    {
        HANDLE snapshot = INVALID_HANDLE_VALUE;

        // A process that is still loading modules can make the module
        // snapshot fail with ERROR_BAD_LENGTH. Retry briefly.
        for (int attempt = 0; attempt < 5; attempt++)
        {
            snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid );

            if (snapshot != INVALID_HANDLE_VALUE)
                break;

            if (GetLastError() != ERROR_BAD_LENGTH)
                break;

            ::Sleep( 10 );
        }

        if (snapshot == INVALID_HANDLE_VALUE)
        {
            reason = L"module list is not available yet";
            return false;
        }

        std::vector<std::wstring> modules;
        MODULEENTRY32W entry = { 0 };
        entry.dwSize = sizeof( entry );

        if (Module32FirstW( snapshot, &entry ))
        {
            do
            {
                modules.emplace_back( Lower( entry.szModule ) );
            }
            while (Module32NextW( snapshot, &entry ));
        }

        CloseHandle( snapshot );

        if (options.minModules != 0 && modules.size() < options.minModules)
        {
            reason = L"loaded modules " + std::to_wstring( modules.size() ) +
                L"/" + std::to_wstring( options.minModules );
            return false;
        }

        for (auto& required : options.modules)
        {
            const std::wstring needle = Lower( required );
            const bool found = std::any_of(
                modules.begin(), modules.end(),
                [&needle]( const std::wstring& name )
                {
                    return name.find( needle ) != std::wstring::npos;
                } );

            if (!found)
            {
                reason = L"waiting for module " + required;
                return false;
            }
        }

        reason.clear();
        return true;
    }
}
