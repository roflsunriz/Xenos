// XenosCli - headless front-end for the process picker core.
//
// The CLI owns the discovery / fingerprint / filter / recent-target logic
// (shared with the GUI through ProcessCatalog). The GUI is launched with
// `XenosCli gui` and is a thin wrapper around the same selection model.

#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

#include "../AppSettings.h"
#include "../EngineDetect.h"
#include "../ProcessCatalog.h"

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

    struct Options
    {
        PickerMode mode = PickerMode::Games;
        std::wstring filter;
        bool json = false;
        bool autoRecent = true;
        std::vector<std::wstring> positional;
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
            L"XenosCli - process picker core\n"
            L"\n"
            L"Usage:\n"
            L"  XenosCli list   [--mode all|games|recent] [--filter TEXT] [--json]  (default: all)\n"
            L"  XenosCli pick   [--mode ...] [--filter ...] [--no-recent] [--json] (default: saved mode)\n"
            L"  XenosCli detect <pid|name>\n"
            L"  XenosCli remember <pid|name>\n"
            L"  XenosCli forget\n"
            L"  XenosCli recent\n"
            L"  XenosCli engines\n"
            L"  XenosCli gui [gui arguments...]\n"
            L"\n"
            L"Filter syntax:\n"
            L"  name fragment     substring / prefix / fuzzy subsequence\n"
            L"  @unity            match engine tags (unity, unreal, godot, ...)\n"
            L"  pid:1234          match PID\n"
            L"  -token            exclude matches\n"
            L"\n"
            L"Examples:\n"
            L"  XenosCli list --mode games\n"
            L"  XenosCli list --mode all --filter unreal\n"
            L"  XenosCli list --filter \"@unity mono\"\n"
            L"  XenosCli pick --filter mygame --json\n" );
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

    int CommandForget( const Options& options )
    {
        auto& settings = AppSettings::Instance();
        settings.Load();
        settings.ForgetTargets();
        settings.Save();

        Out( L"recent targets cleared\n" );
        return 0;
    }

    int CommandRecent( const Options& options )
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
}

int wmain( int argc, wchar_t** argv )
{
    InitOutput();

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
    if (command == L"pick" || command == L"select")
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
    if (command == L"help")
    {
        PrintUsage();
        return 0;
    }

    Err( L"Unknown command: %ls\n\n", command.c_str() );
    PrintUsage();
    return 2;
}
