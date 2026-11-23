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
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../AppSettings.h"
#include "../EngineDetect.h"
#include "../InjectionCore.h"
#include "../InjectionRegistry.h"
#include "../Message.hpp"
#include "../ProcessCatalog.h"
#include "../DriverExtract.h"
#include "../WatchInjector.h"
#include "../PeHardener.h"

namespace
{
    HANDLE g_stdout = INVALID_HANDLE_VALUE;
    HANDLE g_stderr = INVALID_HANDLE_VALUE;
    bool   g_consoleOut = false;
    bool   g_consoleErr = false;

    std::atomic<watch::Watcher*> g_activeWatcher{ nullptr };

    BOOL WINAPI WatchCtrlHandler( DWORD type )
    {
        if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT)
        {
            if (auto* watcher = g_activeWatcher.load())
                watcher->Stop();

            return TRUE;
        }

        return FALSE;
    }

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
        bool force = false;

        // watch / AmalgamLoader-style auto-injection
        bool watch = false;
        bool watchOnce = false;
        bool watchExisting = true;
        bool watchExitWhenGone = false;
        std::wstring watchExe;
        std::vector<std::wstring> readyModules;
        uint32_t minModules = 0;
        uint32_t stableChecks = 2;
        uint32_t settleMs = 0;
        uint32_t watchInterval = 500;
        uint32_t watchPoll = 1000;
        uint32_t watchTimeoutSec = 0;
        uint32_t retryCount = 3;
        uint32_t retryDelay = 500;
        uint32_t retryJitter = 100;

        // PE fingerprint randomization (AmalgamLoader-style, safe subset)
        bool hardenTimestamp = true;
        uint32_t hardenOverlay = 1024;
        bool hardenInPlace = false;
        std::wstring hardenOutput;
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
            else if (arg == L"--force")
            {
                options.force = true;
            }
            else if (arg == L"--watch")
            {
                options.watch = true;
            }
            else if (arg == L"--once")
            {
                options.watchOnce = true;
            }
            else if (arg == L"--watch-existing")
            {
                options.watchExisting = true;
            }
            else if (arg == L"--no-watch-existing")
            {
                options.watchExisting = false;
            }
            else if (arg == L"--exit-when-gone" || arg == L"--watch-exit")
            {
                options.watchExitWhenGone = true;
            }
            else if (arg == L"--exe" && i + 1 < argc)
            {
                options.watchExe = argv[++i];
            }
            else if (arg == L"--module" && i + 1 < argc)
            {
                options.readyModules.emplace_back( argv[++i] );
            }
            else if (arg == L"--min-modules" && i + 1 < argc)
            {
                options.minModules = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--stable-checks" && i + 1 < argc)
            {
                options.stableChecks = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--settle" && i + 1 < argc)
            {
                options.settleMs = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--watch-interval" && i + 1 < argc)
            {
                options.watchInterval = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--watch-poll" && i + 1 < argc)
            {
                options.watchPoll = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--watch-timeout" && i + 1 < argc)
            {
                options.watchTimeoutSec = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--retry" && i + 1 < argc)
            {
                options.retryCount = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--retry-delay" && i + 1 < argc)
            {
                options.retryDelay = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--jitter" && i + 1 < argc)
            {
                options.retryJitter = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--timestamp")
            {
                options.hardenTimestamp = true;
            }
            else if (arg == L"--no-timestamp")
            {
                options.hardenTimestamp = false;
            }
            else if (arg == L"--overlay" && i + 1 < argc)
            {
                options.hardenOverlay = static_cast<uint32_t>( wcstoul( argv[++i], nullptr, 0 ) );
            }
            else if (arg == L"--in-place")
            {
                options.hardenInPlace = true;
            }
            else if (arg == L"--output" && i + 1 < argc)
            {
                options.hardenOutput = argv[++i];
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
            L"  XenosCli injections [--pid N] [--json]\n"
            L"  XenosCli eject <handle> [--force] [--json]\n"
            L"  XenosCli reinject <handle> [--json]\n"
            L"\n"
            L"Watch (AmalgamLoader-style auto-injection):\n"
            L"  XenosCli watch --dll <path> --exe <exe> [options]\n"
            L"  XenosCli watch --dll <path> --name <image.exe> [options]\n"
            L"\n"
            L"  Readiness:\n"
            L"    --module <name>          require a loaded module (repeatable)\n"
            L"    --min-modules <n>        minimum number of loaded modules\n"
            L"    --stable-checks <n>      consecutive ready checks (default 2)\n"
            L"    --watch-interval <ms>    readiness poll interval (default 500)\n"
            L"    --settle <ms>            extra wait after the process is ready\n"
            L"    --watch-existing         inject instances that are already running (default)\n"
            L"    --no-watch-existing      only inject instances started after the watcher\n"
            L"    --watch-timeout <sec>    give up after N seconds (default: forever)\n"
            L"    --once                   stop after the first successful injection\n"
            L"    --exit-when-gone         stop when no target instance is running\n"
            L"\n"
            L"  Retry:\n"
            L"    --retry <n>              injection attempts (default 3)\n"
            L"    --retry-delay <ms>       first retry delay, doubled per attempt (default 500)\n"
            L"    --jitter <ms>            random retry jitter (default 100)\n"
            L"\n"
            L"  --watch may also be added to `inject`.\n"
            L"\n"
            L"PE fingerprint (AmalgamLoader-style, safe subset):\n"
            L"  XenosCli harden <file> [--timestamp|--no-timestamp] [--overlay N]\n"
            L"                         [--output <path>] [--in-place] [--force] [--json]\n"
            L"\n"
            L"  --timestamp randomizes the PE TimeDateStamp (default: on)\n"
            L"  --overlay N appends N random overlay bytes (default: 1024, 0 = off)\n"
            L"  --in-place replaces the input file (refuses to touch the running exe)\n"
            L"  --output writes to an explicit path (default: <name>.hardened<ext>)\n"
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
            L"  XenosCli inject --dll payload.dll --new \"C:\\Games\\MyGame\\MyGame.exe\" --timeout 60\n"
            L"  XenosCli watch --dll payload.dll --name MyGame.exe --module engine.dll --min-modules 16 --settle 3000\n"
            L"  XenosCli watch --dll payload.dll --exe \"C:\\Games\\MyGame\\MyGame.exe\" --once --json\n"
            L"  XenosCli harden payload.dll --output payload.hardened.dll\n" );
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

    int CommandInjections( const Options& options )
    {
        auto records = InjectionRegistry::Instance().All();

        const DWORD pidFilter = options.targetPid.empty() ? 0 :
            static_cast<DWORD>( _wtoi( options.targetPid.c_str() ) );

        if (options.json)
        {
            Out( L"[\n" );
            bool first = true;

            for (auto& record : records)
            {
                if (pidFilter != 0 && record.pid != pidFilter)
                    continue;

                if (!first)
                    Out( L",\n" );
                first = false;

                const bool live = IsInjectionLive( record );
                const wchar_t* state = record.state == static_cast<int>( InjectionState::Ejected ) ? L"ejected" :
                    live ? L"loaded" : L"stale";

                Out(
                    L"  {\"handle\":%u,\"pid\":%lu,\"module\":\"%ls\",\"base\":\"0x%llx\","
                    L"\"method\":\"%ls\",\"manual\":%ls,\"state\":\"%ls\",\"path\":\"%ls\"}",
                    record.id,
                    record.pid,
                    JsonEscape( record.moduleName ).c_str(),
                    static_cast<unsigned long long>( record.baseAddress ),
                    MethodName( record.method ),
                    record.manual ? L"true" : L"false",
                    state,
                    JsonEscape( record.imagePath ).c_str() );
            }

            Out( L"\n]\n" );
            return 0;
        }

        Out( L"%6ls  %6ls  %-28ls  %-12ls  %-9ls  %-8ls  %ls\n",
             L"HANDLE", L"PID", L"MODULE", L"BASE", L"METHOD", L"STATE", L"IMAGE" );

        for (auto& record : records)
        {
            if (pidFilter != 0 && record.pid != pidFilter)
                continue;

            const bool live = IsInjectionLive( record );
            const wchar_t* state = record.state == static_cast<int>( InjectionState::Ejected ) ? L"ejected" :
                live ? L"loaded" : L"stale";

            wchar_t base[32] = { 0 };
            swprintf_s( base, L"0x%llx", static_cast<unsigned long long>( record.baseAddress ) );

            Out( L"#%-5u  %6lu  %-28ls  %-12ls  %-9ls  %-8ls  %ls\n",
                 record.id,
                 record.pid,
                 record.moduleName.c_str(),
                 base,
                 MethodName( record.method ),
                 state,
                 record.imagePath.c_str() );
        }

        return 0;
    }

    int CommandEject( const Options& options )
    {
        if (options.positional.empty())
        {
            Err( L"eject requires a handle (use 'injections' to list them)\n" );
            return 2;
        }

        const uint32_t id = static_cast<uint32_t>( _wtoi( options.positional.front().c_str() ) );
        std::wstring message;
        const EjectStatus status = EjectInjection( id, options.force, message );
        const bool ok = status == EjectStatus::Ok || status == EjectStatus::AlreadyGone;

        if (options.json)
        {
            Out( L"{\"handle\":%u,\"ok\":%ls,\"status\":\"%ls\",\"message\":\"%ls\"}\n",
                 id,
                 ok ? L"true" : L"false",
                 EjectStatusText( status ),
                 JsonEscape( message ).c_str() );
        }
        else if (ok)
        {
            Out( L"%ls\n", message.c_str() );
        }
        else
        {
            Err( L"%ls\n", message.c_str() );
        }

        if (ok)
            return 0;

        return status == EjectStatus::NotFound ? 1 : 3;
    }

    int CommandReinject( const Options& options )
    {
        if (options.positional.empty())
        {
            Err( L"reinject requires a handle (use 'injections' to list them)\n" );
            return 2;
        }

        const uint32_t id = static_cast<uint32_t>( _wtoi( options.positional.front().c_str() ) );
        uint32_t newId = 0;
        std::wstring message;
        const bool ok = ReinjectInjection( id, nullptr, newId, message );

        if (options.json)
        {
            Out( L"{\"handle\":%u,\"ok\":%ls,\"newHandle\":%u,\"message\":\"%ls\"}\n",
                 id,
                 ok ? L"true" : L"false",
                 newId,
                 JsonEscape( message ).c_str() );
        }
        else if (ok)
        {
            Out( L"%ls\n", message.c_str() );
        }
        else
        {
            Err( L"%ls\n", message.c_str() );
        }

        return ok ? 0 : 3;
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

    bool NeedsDriver( const Options& options )
    {
        return options.method >= Kernel_Thread || options.krnHandle ||
            (options.mmapFlags & blackbone::HideVAD) != 0;
    }

    bool PrepareDriver( const Options& options, bool exitOnFailure )
    {
        const bool needsDriver = NeedsDriver( options );

        if (!IsElevated() && !needsDriver)
            Err( L"note: not running elevated; elevated/protected targets will fail\n" );

        if (!needsDriver)
            return true;

        if (!IsElevated())
        {
            Err( L"kernel injection / --krn-handle / --hide-vad requires administrator rights; run from an elevated prompt\n" );
            return false;
        }

        DriverExtract::Instance().Extract();

        NTSTATUS driverStatus = blackbone::Driver().EnsureLoaded();
        if (!NT_SUCCESS( driverStatus ))
        {
            DriverExtract::Instance().Cleanup();
            Err( L"failed to load BlackBone driver (0x%08X)\n", driverStatus );

            // Driver state is undefined after a failed load; skip static teardown.
            if (exitOnFailure)
                ExitProcess( 3 );

            return false;
        }

        return true;
    }

    NTSTATUS ExecuteInjection(
        const Options& options,
        InjectionCore& core,
        DWORD pid,
        const std::wstring& name,
        const std::wstring& path,
        ProcMode mode,
        vecPEImages& images,
        const std::vector<std::wstring>& paths,
        std::vector<std::wstring>& handles )
    {
        InjectContext context;
        context.cfg.processMode = mode;
        context.cfg.injectMode = options.method;
        context.cfg.procName = name;
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

        context.pid = pid;
        context.procPath = path;
        context.images = images;

        if (mode == NewProcess && context.cfg.procCmdLine.empty())
            context.cfg.procCmdLine = L"\"" + path + L"\"";

        const NTSTATUS status = core.InjectMultiple( &context );
        handles = context.injectionIds;
        return status;
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

        if (!PrepareDriver( options, true ))
            return 3;

        HWND hwnd = nullptr;
        InjectionCore core( hwnd );

        std::vector<std::wstring> injectionIds;
        NTSTATUS status = ExecuteInjection(
            options, core, target.pid, target.name, target.path, target.mode,
            images, paths, injectionIds );

        if (!NT_SUCCESS( status ))
        {
            Err( L"injection failed: 0x%08X %ls\n", status,
                 blackbone::Utils::GetErrorDescription( status ).c_str() );

            if (!IsElevated() && (status == STATUS_ACCESS_DENIED || status == static_cast<NTSTATUS>( 0xC0000022 )))
                Err( L"hint: retry from an elevated prompt\n" );

            return 3;
        }

        std::wstring handles;
        for (auto& id : injectionIds)
        {
            if (!handles.empty())
                handles += L", ";

            handles += L"#" + id;
        }

        if (options.json)
        {
            Out( L"{\"ok\":true,\"pid\":%lu,\"name\":\"%ls\",\"path\":\"%ls\",\"method\":\"%ls\",\"images\":%zu,\"handles\":[",
                 target.pid,
                 JsonEscape( target.name ).c_str(),
                 JsonEscape( target.path ).c_str(),
                 MethodName( options.method ),
                 paths.size() );

            for (size_t i = 0; i < injectionIds.size(); i++)
            {
                if (i)
                    Out( L"," );

                Out( L"%ls", injectionIds[i].c_str() );
            }

            Out( L"]}\n" );
        }
        else
        {
            Out( L"injected %zu image(s) into %ls (%lu) using %ls\n",
                 paths.size(), target.name.c_str(), target.pid, MethodName( options.method ) );

            if (!handles.empty())
                Out( L"handles: %ls\n", handles.c_str() );
        }

        return 0;
    }

    int CommandWatch( const Options& options )
    {
        if (options.dlls.empty())
        {
            Err( L"watch requires --dll <path>\n" );
            return 2;
        }

        if (!options.newExe.empty() || !options.waitExe.empty())
        {
            Err( L"watch cannot be combined with --new/--wait; it watches running instances\n" );
            return 2;
        }

        if (options.method == Kernel_DriverMap)
        {
            Err( L"watch requires a process target; kernel driver mapping is not supported\n" );
            return 2;
        }

        std::wstring targetName = options.targetName;
        std::wstring targetPath;

        if (!options.watchExe.empty())
            targetPath = AbsolutePath( options.watchExe );

        if (targetName.empty() && !targetPath.empty())
            targetName = BaseName( targetPath );

        // --pid narrows the initial target; new instances are matched by name.
        if (targetName.empty() && !options.targetPid.empty())
        {
            proc::Catalog catalog;
            catalog.Refresh();

            proc::Entry entry;
            if (!catalog.Find( options.targetPid, entry ))
            {
                Err( L"target process not found: %ls\n", options.targetPid.c_str() );
                return 1;
            }

            targetName = entry.name;
            targetPath = entry.path;
        }

        if (targetName.empty())
        {
            Err( L"watch requires --exe <path>, --name <image.exe>, or --pid <pid>\n" );
            return 2;
        }

        vecPEImages images;
        std::vector<std::wstring> paths;
        if (!LoadImages( options, images, paths ))
            return 2;

        if (options.dryRun)
        {
            Out( L"target: %ls\n", targetName.c_str() );
            if (!targetPath.empty())
                Out( L"path:   %ls\n", targetPath.c_str() );

            for (size_t i = 0; i < paths.size(); i++)
                Out( L"dll[%zu]: %ls\n", i, paths[i].c_str() );

            return 0;
        }

        if (!PrepareDriver( options, false ))
            ExitProcess( 3 );

        watch::Options watchOptions;
        watchOptions.target.name = targetName;
        watchOptions.target.path = targetPath;
        watchOptions.readiness.modules = options.readyModules;
        watchOptions.readiness.minModules = options.minModules;
        watchOptions.readiness.stableChecks = options.stableChecks;
        watchOptions.readiness.intervalMs = options.watchInterval;
        watchOptions.readiness.settleMs = options.settleMs;
        watchOptions.readiness.timeoutMs = options.watchTimeoutSec * 1000;
        watchOptions.retry.attempts = options.retryCount;
        watchOptions.retry.baseDelayMs = options.retryDelay;
        watchOptions.retry.jitterMs = options.retryJitter;
        watchOptions.pollMs = options.watchPoll;
        watchOptions.runTimeoutMs = options.watchTimeoutSec * 1000;
        watchOptions.once = options.watchOnce;
        watchOptions.includeExisting = options.watchExisting;
        watchOptions.exitWhenGone = options.watchExitWhenGone;

        HWND hwnd = nullptr;
        InjectionCore core( hwnd );

        auto logFn = []( const std::wstring& text )
        {
            Err( L"%ls\n", text.c_str() );
        };

        auto injectFn = [&]( const watch::ProcessRef& target, std::wstring& message ) -> bool
        {
            // Do not stack a second copy of the same image into a process that
            // already has a live tracked injection (watch may be restarted).
            for (auto& record : InjectionRegistry::Instance().ForPid( target.pid ))
            {
                if (record.state != static_cast<int>( InjectionState::Loaded ))
                    continue;

                for (auto& path : paths)
                {
                    if (_wcsicmp( record.imagePath.c_str(), path.c_str() ) == 0 && IsInjectionLive( record ))
                    {
                        message = L"already injected as #" + std::to_wstring( record.id );

                        if (options.json)
                        {
                            Out( L"{\"event\":\"skipped\",\"pid\":%lu,\"name\":\"%ls\","
                                 L"\"handle\":%u,\"reason\":\"already-injected\"}\n",
                                 target.pid,
                                 JsonEscape( target.name ).c_str(),
                                 record.id );
                        }
                        else
                        {
                            Err( L"PID %lu already has %ls (handle #%u); skipping\n",
                                 target.pid, record.moduleName.c_str(), record.id );
                        }

                        return true;
                    }
                }
            }

            std::vector<std::wstring> handles;
            const NTSTATUS status = ExecuteInjection(
                options, core, target.pid, target.name, target.path, Existing,
                images, paths, handles );

            if (!NT_SUCCESS( status ))
            {
                message = blackbone::Utils::GetErrorDescription( status );

                if (options.json)
                {
                    Out( L"{\"event\":\"injection-failed\",\"pid\":%lu,\"name\":\"%ls\","
                         L"\"message\":\"%ls\",\"status\":\"0x%08X\"}\n",
                         target.pid,
                         JsonEscape( target.name ).c_str(),
                         JsonEscape( message ).c_str(),
                         status );
                }

                return false;
            }

            if (options.json)
            {
                Out( L"{\"event\":\"injected\",\"ok\":true,\"pid\":%lu,\"name\":\"%ls\","
                     L"\"path\":\"%ls\",\"method\":\"%ls\",\"images\":%zu,\"handles\":[",
                     target.pid,
                     JsonEscape( target.name ).c_str(),
                     JsonEscape( target.path ).c_str(),
                     MethodName( options.method ),
                     paths.size() );

                for (size_t i = 0; i < handles.size(); i++)
                {
                    if (i)
                        Out( L"," );

                    Out( L"%ls", handles[i].c_str() );
                }

                Out( L"]}\n" );
            }
            else
            {
                std::wstring joined;
                for (auto& id : handles)
                {
                    if (!joined.empty())
                        joined += L", ";

                    joined += L"#" + id;
                }

                Out( L"injected %zu image(s) into %ls (%lu) using %ls%s%ls\n",
                     paths.size(), target.name.c_str(), target.pid, MethodName( options.method ),
                     joined.empty() ? L"" : L", handles: ", joined.c_str() );
            }

            return true;
        };

        if (options.json)
        {
            Out( L"{\"event\":\"watch\",\"target\":\"%ls\",\"path\":\"%ls\","
                 L"\"once\":%ls,\"includeExisting\":%ls}\n",
                 JsonEscape( targetName ).c_str(),
                 JsonEscape( targetPath ).c_str(),
                 options.watchOnce ? L"true" : L"false",
                 options.watchExisting ? L"true" : L"false" );
        }
        else
        {
            Out( L"watching for %ls%s%ls\n",
                 targetName.c_str(),
                 targetPath.empty() ? L"" : L" at ", targetPath.c_str() );
        }

        watch::Watcher watcher( watchOptions, injectFn, logFn );
        g_activeWatcher = &watcher;

        SetConsoleCtrlHandler( WatchCtrlHandler, TRUE );
        const bool ok = watcher.Run();
        SetConsoleCtrlHandler( WatchCtrlHandler, FALSE );

        g_activeWatcher = nullptr;

        if (ok)
            return 0;

        const std::wstring& message = watcher.LastResult().message;
        if (message.find( L"no target" ) != std::wstring::npos ||
            message.find( L"timed out" ) != std::wstring::npos)
        {
            return 1;
        }

        return 3;
    }

    int CommandHarden( const Options& options )
    {
        if (options.positional.empty())
        {
            Err( L"harden requires a PE file path\n" );
            return 2;
        }

        if (!options.watchExe.empty() || options.watch)
        {
            Err( L"harden cannot be combined with watch options\n" );
            return 2;
        }

        peh::Options hardenOptions;
        hardenOptions.timestamp = options.hardenTimestamp;
        hardenOptions.overlayBytes = options.hardenOverlay;
        hardenOptions.inPlace = options.hardenInPlace;
        hardenOptions.force = options.force;
        hardenOptions.output = options.hardenOutput.empty() ?
            L"" : AbsolutePath( options.hardenOutput );

        peh::Result result;
        const bool ok = peh::Harden(
            AbsolutePath( options.positional.front() ), hardenOptions, result );

        if (options.json)
        {
            Out( L"{\"ok\":%ls,\"input\":\"%ls\",\"output\":\"%ls\","
                 L"\"oldTimestamp\":%lu,\"newTimestamp\":%lu,"
                 L"\"oldSize\":%llu,\"newSize\":%llu,\"overlay\":%lu,"
                 L"\"message\":\"%ls\"}\n",
                 ok ? L"true" : L"false",
                 JsonEscape( result.inputPath ).c_str(),
                 JsonEscape( result.outputPath ).c_str(),
                 result.oldTimestamp,
                 result.newTimestamp,
                 static_cast<unsigned long long>( result.oldSize ),
                 static_cast<unsigned long long>( result.newSize ),
                 result.overlayBytes,
                 JsonEscape( result.message ).c_str() );
        }
        else if (ok)
        {
            Out( L"hardened: %ls\n", result.outputPath.c_str() );
            Out( L"  %ls\n", result.message.c_str() );
        }
        else
        {
            Err( L"harden failed: %ls\n", result.message.c_str() );
        }

        return ok ? 0 : 3;
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
    if (command == L"injections" || command == L"handles")
        return CommandInjections( options );
    if (command == L"eject")
        return CommandEject( options );
    if (command == L"reinject")
        return CommandReinject( options );
    if (command == L"watch")
        return CommandWatch( options );
    if (command == L"harden")
        return CommandHarden( options );
    if (command == L"inject")
        return options.watch ? CommandWatch( options ) : CommandInject( options );
    if (command == L"help")
    {
        PrintUsage();
        return 0;
    }

    Err( L"Unknown command: %ls\n\n", command.c_str() );
    PrintUsage();
    return 2;
}
