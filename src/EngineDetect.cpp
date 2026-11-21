#include "stdafx.h"
#include "EngineDetect.h"

#include <tlhelp32.h>
#include <shlwapi.h>

#include <algorithm>
#include <cwctype>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

namespace engine
{
namespace
{
    // ---------------------------------------------------------------------
    // Small string / path helpers
    // ---------------------------------------------------------------------

    std::wstring ToLower( std::wstring str )
    {
        for (auto& ch : str)
            ch = static_cast<wchar_t>(towlower( ch ));

        return str;
    }

    bool HasWildcard( const std::wstring& str )
    {
        return str.find_first_of( L"*?" ) != std::wstring::npos;
    }

    std::wstring JoinPath( const std::wstring& dir, const std::wstring& name )
    {
        if (dir.empty())
            return name;

        if (dir.back() == L'\\' || dir.back() == L'/')
            return dir + name;

        return dir + L"\\" + name;
    }

    std::wstring StripFile( const std::wstring& path )
    {
        auto pos = path.find_last_of( L"\\/" );
        return pos == std::wstring::npos ? std::wstring() : path.substr( 0, pos );
    }

    std::wstring BaseName( const std::wstring& path )
    {
        auto pos = path.find_last_of( L"\\/" );
        return pos == std::wstring::npos ? path : path.substr( pos + 1 );
    }

    std::vector<std::wstring> Split( const std::wstring& str, wchar_t sep )
    {
        std::vector<std::wstring> parts;
        size_t start = 0;

        for (;;)
        {
            auto pos = str.find( sep, start );
            if (pos == std::wstring::npos)
            {
                parts.emplace_back( str.substr( start ) );
                break;
            }

            parts.emplace_back( str.substr( start, pos - start ) );
            start = pos + 1;
        }

        return parts;
    }

    std::wstring Trim( const std::wstring& str )
    {
        const wchar_t* ws = L" \t\r\n";
        auto begin = str.find_first_not_of( ws );
        if (begin == std::wstring::npos)
            return L"";

        auto end = str.find_last_not_of( ws );
        return str.substr( begin, end - begin + 1 );
    }

    std::wstring ModuleDirectory()
    {
        wchar_t path[MAX_PATH] = { 0 };
        GetModuleFileNameW( nullptr, path, ARRAYSIZE( path ) );

        return StripFile( path );
    }

    std::wstring AppDataDirectory()
    {
        wchar_t path[MAX_PATH] = { 0 };
        DWORD len = GetEnvironmentVariableW( L"APPDATA", path, ARRAYSIZE( path ) );
        if (len == 0 || len >= ARRAYSIZE( path ))
            return L"";

        return std::wstring( path ) + L"\\Xenos";
    }

    // ---------------------------------------------------------------------
    // Path existence with wildcard support and relative components
    // ---------------------------------------------------------------------

    bool PathExists( const std::wstring& baseDir, const std::wstring& relative )
    {
        if (relative.empty())
            return false;

        auto parts = Split( relative, L'\\' );
        std::vector<std::wstring> current{ baseDir };

        for (size_t i = 0; i < parts.size(); i++)
        {
            const std::wstring& part = parts[i];
            if (part.empty() || part == L".")
                continue;

            const bool last = (i + 1 == parts.size());
            std::vector<std::wstring> next;

            for (auto& dir : current)
            {
                std::wstring candidate = JoinPath( dir, part );

                if (!HasWildcard( part ))
                {
                    DWORD attrib = GetFileAttributesW( candidate.c_str() );
                    if (attrib == INVALID_FILE_ATTRIBUTES)
                        continue;

                    if (!last && !(attrib & FILE_ATTRIBUTE_DIRECTORY))
                        continue;

                    next.emplace_back( std::move( candidate ) );
                }
                else
                {
                    WIN32_FIND_DATAW fd = { 0 };
                    HANDLE find = FindFirstFileW( candidate.c_str(), &fd );
                    if (find == INVALID_HANDLE_VALUE)
                        continue;

                    do
                    {
                        if (wcscmp( fd.cFileName, L"." ) == 0 || wcscmp( fd.cFileName, L".." ) == 0)
                            continue;

                        const bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                        if (!last && !isDir)
                            continue;

                        next.emplace_back( JoinPath( dir, fd.cFileName ) );
                    }
                    while (FindNextFileW( find, &fd ));

                    FindClose( find );
                }

                // Guard against pathological wildcard expansion
                if (next.size() >= 64)
                    break;
            }

            if (next.empty())
                return false;

            current.swap( next );
        }

        return !current.empty();
    }

    // ---------------------------------------------------------------------
    // Process information
    // ---------------------------------------------------------------------

    bool GetProcessCreationTime( DWORD pid, FILETIME& created )
    {
        HANDLE process = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
        if (!process)
            return false;

        FILETIME exitTime = { 0 }, kernelTime = { 0 }, userTime = { 0 };
        BOOL ok = GetProcessTimes( process, &created, &exitTime, &kernelTime, &userTime );
        CloseHandle( process );

        return ok != FALSE;
    }

    void EnumModules( DWORD pid, std::vector<std::wstring>& modules )
    {
        HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid );
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W entry = { 0 };
            entry.dwSize = sizeof( entry );

            if (Module32FirstW( snapshot, &entry ))
            {
                do
                {
                    modules.emplace_back( entry.szModule );
                }
                while (Module32NextW( snapshot, &entry ));
            }

            CloseHandle( snapshot );
        }

        if (!modules.empty())
            return;

        // Fallback for processes that Toolhelp refuses to expose
        HANDLE process = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid );
        if (!process)
            return;

        HMODULE handles[1024] = { 0 };
        DWORD needed = 0;
        if (EnumProcessModulesEx( process, handles, sizeof( handles ), &needed, LIST_MODULES_ALL ))
        {
            const DWORD count = needed / sizeof( HMODULE );
            for (DWORD i = 0; i < count && i < ARRAYSIZE( handles ); i++)
            {
                wchar_t name[MAX_PATH] = { 0 };
                if (GetModuleBaseNameW( process, handles[i], name, ARRAYSIZE( name ) ))
                    modules.emplace_back( name );
            }
        }

        CloseHandle( process );
    }

    bool FileStartsWith( const std::wstring& path, const std::wstring& prefix )
    {
        if (path.size() < prefix.size())
            return false;

        return _wcsnicmp( path.c_str(), prefix.c_str(), prefix.size() ) == 0;
    }

    // Engine built-in helper executables (overlays, crash reporters) that
    // would otherwise show up as "games" in the filtered list.
    bool IsHelperImage( const std::wstring& exeName )
    {
        static const wchar_t* patterns[] =
        {
            L"EOSOverlayRenderer-*.exe",
            L"UnityCrashHandler*.exe",
            L"*CrashReportClient*.exe",
            L"*-Win64-Shipping-Cmd.exe",
            L"UnrealVersionSelector-*.exe",
        };

        for (auto pattern : patterns)
        {
            if (PathMatchSpecW( exeName.c_str(), pattern ))
                return true;
        }

        return false;
    }

    // ---------------------------------------------------------------------
    // Godot: embedded PCK magic at the end of the executable
    // ---------------------------------------------------------------------

    bool HasEmbeddedPck( const std::wstring& imagePath )
    {
        HANDLE file = CreateFileW(
            imagePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr );

        if (file == INVALID_HANDLE_VALUE)
            return false;

        LARGE_INTEGER size = { 0 };
        bool found = false;

        if (GetFileSizeEx( file, &size ) && size.QuadPart > 32)
        {
            const DWORD scanSize = 4096;
            DWORD toRead = static_cast<DWORD>(size.QuadPart < scanSize ? size.QuadPart : scanSize);
            LARGE_INTEGER offset = { 0 };
            offset.QuadPart = size.QuadPart - toRead;

            if (SetFilePointerEx( file, offset, nullptr, FILE_BEGIN ))
            {
                std::vector<char> buffer( toRead, 0 );
                DWORD read = 0;

                if (ReadFile( file, buffer.data(), toRead, &read, nullptr ) && read >= 4)
                {
                    for (DWORD i = 0; i + 4 <= read; i++)
                    {
                        if (buffer[i + 0] == 'G' && buffer[i + 1] == 'D' &&
                            buffer[i + 2] == 'P' && buffer[i + 3] == 'C')
                        {
                            found = true;
                            break;
                        }
                    }
                }
            }
        }

        CloseHandle( file );
        return found;
    }
}

// -------------------------------------------------------------------------
// Detector
// -------------------------------------------------------------------------

struct Detector::Impl
{
    struct Rule
    {
        std::wstring engine;
        std::wstring variant;
        bool         game = true;

        std::vector<std::wstring> modules;
        std::vector<std::wstring> files;
        std::vector<std::wstring> dirs;
        std::vector<std::wstring> exes;

        int wModule = 70;
        int wFile   = 45;
        int wDir    = 35;
        int wExe    = 65;
        int minScore = 40;
    };

    struct Hit
    {
        const Rule* rule = nullptr;
        int score = 0;
    };

    struct CacheEntry
    {
        FILETIME created = { 0 };
        DWORD    tick = 0;
        Info     info;
        bool     hasCreationTime = false;
    };

    std::vector<Rule> rules;
    std::unordered_map<DWORD, CacheEntry> cache;
    bool loaded = false;

    static std::vector<std::wstring> ListValue( const std::wstring& value )
    {
        std::vector<std::wstring> result;
        for (auto& item : Split( value, L',' ))
        {
            auto trimmed = Trim( item );
            if (!trimmed.empty())
                result.emplace_back( std::move( trimmed ) );
        }

        return result;
    }

    static int IntValue( const std::wstring& value, int def )
    {
        if (value.empty())
            return def;

        wchar_t* end = nullptr;
        long parsed = wcstol( value.c_str(), &end, 10 );
        return end == value.c_str() ? def : static_cast<int>( parsed );
    }

    void AddBuiltinRules()
    {
        // ---- Unity -------------------------------------------------------
        rules.push_back( Rule{
            L"Unity", L"IL2CPP", true,
            { L"GameAssembly.dll" },
            { L"*_Data\\il2cpp_data\\Metadata\\global-metadata.dat" },
            { L"*_Data\\il2cpp_data" },
            {},
            80, 55, 45, 65, 40
        } );

        rules.push_back( Rule{
            L"Unity", L"Mono", true,
            { L"mono-2.0-bdwgc.dll", L"mono-2.0-sgen.dll", L"mono-2.0.dll", L"mono.dll" },
            { L"*_Data\\Managed\\Assembly-CSharp.dll" },
            { L"*_Data\\Managed" },
            {},
            80, 55, 45, 65, 40
        } );

        rules.push_back( Rule{
            L"Unity", L"", true,
            { L"UnityPlayer.dll" },
            { L"*_Data\\globalgamemanagers", L"*_Data\\data.unity3d", L"*_Data\\resources.assets" },
            { L"*_Data" },
            {},
            75, 50, 45, 65, 40
        } );

        // ---- Unreal Engine ----------------------------------------------
        const std::vector<std::wstring> ueExes = {
            L"*-Win64-Shipping.exe", L"*-Win64-Development.exe",
            L"*-Win64-DebugGame.exe", L"*-Win64-Test.exe"
        };

        rules.push_back( Rule{
            L"Unreal Engine", L"5", true,
            { L"UE5-*.dll" },
            {
                L"..\\..\\..\\Content\\Paks\\*.utoc",
                L"..\\..\\..\\Content\\Paks\\*.ucas",
                L"..\\..\\..\\Content\\Paks\\*.pak"
            },
            { L"..\\..\\..\\Content\\Paks" },
            ueExes,
            70, 55, 35, 65, 40
        } );

        rules.push_back( Rule{
            L"Unreal Engine", L"4", true,
            { L"UE4-*.dll" },
            {
                L"..\\..\\..\\Content\\Paks\\*.pak",
                L"..\\..\\..\\Content\\Paks\\*.sigl"
            },
            { L"..\\..\\..\\Content\\Paks" },
            ueExes,
            70, 55, 35, 60, 40
        } );

        // ---- Unreal Engine 3 --------------------------------------------
        rules.push_back( Rule{
            L"Unreal Engine 3", L"", true,
            {},
            { L"CookedPC\\*.upk", L"CookedPCConsole\\*.upk" },
            { L"CookedPC", L"CookedPCConsole" },
            {},
            60, 55, 55, 60, 45
        } );

        // ---- Godot -------------------------------------------------------
        rules.push_back( Rule{
            L"Godot", L"", true,
            {},
            { L"*.pck" },
            { L"GodotSharp" },
            {},
            60, 55, 45, 60, 45
        } );

        // ---- GameMaker ---------------------------------------------------
        rules.push_back( Rule{
            L"GameMaker", L"", true,
            {},
            { L"data.win" },
            {},
            {},
            60, 55, 40, 60, 50
        } );

        // ---- RPG Maker ---------------------------------------------------
        rules.push_back( Rule{
            L"RPG Maker", L"XP/VX/Ace", true,
            { L"RGSS*.dll" },
            { L"Game.rgssad", L"Game.rgss2a", L"Game.rgss3a" },
            {},
            {},
            75, 55, 40, 60, 45
        } );

        rules.push_back( Rule{
            L"RPG Maker", L"MV/MZ", true,
            { L"nw.dll" },
            { L"www\\package.json" },
            { L"www" },
            {},
            60, 45, 50, 55, 70
        } );

        // ---- Ren'Py ------------------------------------------------------
        rules.push_back( Rule{
            L"Ren'Py", L"", true,
            {},
            { L"game\\*.rpa", L"game\\script.rpyc" },
            { L"renpy", L"lib\\py3-windows-*" },
            {},
            60, 55, 55, 60, 45
        } );

        // ---- Source / Source 2 / CryEngine ------------------------------
        rules.push_back( Rule{
            L"Source", L"", true,
            { L"engine.dll" },
            {},
            {},
            {},
            70, 45, 35, 60, 45
        } );

        rules.push_back( Rule{
            L"Source 2", L"", true,
            { L"engine2.dll" },
            {},
            {},
            {},
            75, 45, 35, 60, 45
        } );

        rules.push_back( Rule{
            L"CryEngine", L"", true,
            { L"CrySystem.dll" },
            {},
            {},
            {},
            75, 45, 35, 60, 45
        } );

        // ---- Runtimes (not considered games) -----------------------------
        rules.push_back( Rule{
            L"Electron", L"", false,
            { L"libEGL.dll", L"ffmpeg.dll" },
            { L"resources\\app.asar", L"resources\\app\\package.json" },
            { L"resources\\app" },
            {},
            15, 55, 50, 60, 55
        } );

        rules.push_back( Rule{
            L"NW.js", L"", false,
            { L"nw.dll" },
            { L"package.json" },
            {},
            {},
            70, 20, 35, 60, 70
        } );

        rules.push_back( Rule{
            L"Java", L"", false,
            { L"jvm.dll" },
            {},
            {},
            {},
            75, 45, 35, 60, 70
        } );

        rules.push_back( Rule{
            L".NET", L"", false,
            { L"coreclr.dll", L"clrjit.dll" },
            {},
            {},
            {},
            75, 45, 35, 60, 70
        } );
    }

    void LoadIniRules( const std::wstring& path )
    {
        if (GetFileAttributesW( path.c_str() ) == INVALID_FILE_ATTRIBUTES)
            return;

        std::vector<wchar_t> buffer( 65536, 0 );
        DWORD chars = GetPrivateProfileSectionNamesW( buffer.data(), static_cast<DWORD>( buffer.size() ), path.c_str() );
        if (chars == 0)
            return;

        for (const wchar_t* section = buffer.data(); *section; section += wcslen( section ) + 1)
        {
            auto Get = [&]( const wchar_t* key, const wchar_t* def ) -> std::wstring
            {
                std::vector<wchar_t> value( 4096, 0 );
                GetPrivateProfileStringW( section, key, def, value.data(), static_cast<DWORD>( value.size() ), path.c_str() );
                return Trim( value.data() );
            };

            Rule rule;
            rule.engine  = Get( L"engine", section );
            rule.variant = Get( L"variant", L"" );
            rule.game    = IntValue( Get( L"game", L"1" ), 1 ) != 0;

            rule.modules = ListValue( Get( L"modules", L"" ) );
            rule.files   = ListValue( Get( L"files",   L"" ) );
            rule.dirs    = ListValue( Get( L"dirs",    L"" ) );
            rule.exes    = ListValue( Get( L"exes",    L"" ) );

            rule.wModule  = IntValue( Get( L"weight.modules", L"70" ), 70 );
            rule.wFile    = IntValue( Get( L"weight.files",   L"45" ), 45 );
            rule.wDir     = IntValue( Get( L"weight.dirs",    L"35" ), 35 );
            rule.wExe     = IntValue( Get( L"weight.exes",    L"65" ), 65 );
            rule.minScore = IntValue( Get( L"minscore",       L"40" ), 40 );

            if (rule.engine.empty())
                rule.engine = section;

            if (rule.modules.empty() && rule.files.empty() && rule.dirs.empty() && rule.exes.empty())
                continue;

            rules.emplace_back( std::move( rule ) );
        }
    }

    void Load()
    {
        if (loaded)
            return;

        loaded = true;
        AddBuiltinRules();

        LoadIniRules( ModuleDirectory() + L"\\engines.ini" );

        auto appData = AppDataDirectory();
        if (!appData.empty())
            LoadIniRules( appData + L"\\engines.ini" );
    }

    Info Evaluate( DWORD pid, const std::wstring& imagePath )
    {
        Info info;

        std::vector<std::wstring> modules;
        EnumModules( pid, modules );

        const std::wstring baseDir = StripFile( imagePath );
        const std::wstring exeName = BaseName( imagePath );

        std::vector<Hit> hits;
        for (auto& rule : rules)
        {
            int score = 0;

            if (!rule.modules.empty() && !modules.empty())
            {
                for (auto& pattern : rule.modules)
                {
                    bool matched = false;
                    for (auto& module : modules)
                    {
                        if (PathMatchSpecW( module.c_str(), pattern.c_str() ))
                        {
                            matched = true;
                            break;
                        }
                    }

                    if (matched)
                    {
                        score += rule.wModule;
                        break;
                    }
                }
            }

            if (!rule.exes.empty())
            {
                for (auto& pattern : rule.exes)
                {
                    if (PathMatchSpecW( exeName.c_str(), pattern.c_str() ))
                    {
                        score += rule.wExe;
                        break;
                    }
                }
            }

            if (!rule.files.empty())
            {
                for (auto& pattern : rule.files)
                {
                    if (PathExists( baseDir, pattern ))
                    {
                        score += rule.wFile;
                        break;
                    }
                }
            }

            if (!rule.dirs.empty())
            {
                for (auto& pattern : rule.dirs)
                {
                    if (PathExists( baseDir, pattern ))
                    {
                        score += rule.wDir;
                        break;
                    }
                }
            }

            if (score >= rule.minScore)
                hits.push_back( Hit{ &rule, score } );
        }

        // Godot can embed the PCK at the end of the executable
        if (HasEmbeddedPck( imagePath ))
        {
            static const Rule godotEmbedded = Rule{
                L"Godot", L"embedded PCK", true,
                {}, {}, {}, {},
                60, 55, 45, 60, 45
            };

            hits.push_back( Hit{ &godotEmbedded, 55 } );
        }

        if (hits.empty())
            return info;

        // Collapse variants of the same engine, keeping the strongest match
        std::vector<Hit> byEngine;
        for (auto& hit : hits)
        {
            auto it = std::find_if( byEngine.begin(), byEngine.end(), [&]( const Hit& other )
            {
                return other.rule->engine == hit.rule->engine;
            } );

            if (it == byEngine.end())
                byEngine.push_back( hit );
            else if (hit.score > it->score)
                *it = hit;
        }

        const Hit* bestGame = nullptr;
        const Hit* bestAny = nullptr;

        for (auto& hit : byEngine)
        {
            if (hit.rule->game && (!bestGame || hit.score > bestGame->score))
                bestGame = &hit;

            if (!bestAny || hit.score > bestAny->score)
                bestAny = &hit;
        }

        const Hit* primary = bestGame ? bestGame : bestAny;
        if (!primary)
            return info;

        info.valid   = true;
        info.game    = bestGame != nullptr;
        info.score   = primary->score;
        info.engine  = primary->rule->engine;
        info.variant = primary->rule->variant;

        for (auto& hit : byEngine)
        {
            auto tag = hit.rule->engine;
            if (!hit.rule->variant.empty())
                tag += L" " + hit.rule->variant;

            if (!info.allTags.empty())
                info.allTags += L", ";

            info.allTags += tag;
        }

        info.tag = info.DisplayTag();

        if (IsHelperImage( exeName ))
            info.game = false;

        return info;
    }
};

Detector& Detector::Instance()
{
    static Detector instance;
    return instance;
}

Detector::Detector()
    : _impl( new Impl )
{
}

Detector::~Detector()
{
}

Info Detector::Detect( DWORD pid, const std::wstring& imagePath /*= L""*/ )
{
    if (pid <= 4 || pid == GetCurrentProcessId())
        return Info{};

    _impl->Load();

    FILETIME created = { 0 };
    const bool hasCreationTime = GetProcessCreationTime( pid, created );

    const DWORD now = GetTickCount();
    auto cached = _impl->cache.find( pid );
    if (cached != _impl->cache.end())
    {
        const auto& entry = cached->second;
        const bool sameProcess = hasCreationTime && entry.hasCreationTime &&
            memcmp( &entry.created, &created, sizeof( FILETIME ) ) == 0;

        const DWORD ttl = entry.info.valid ? 300000 : 30000;
        if ((sameProcess || (!hasCreationTime && !entry.hasCreationTime)) && (now - entry.tick) < ttl)
            return entry.info;
    }

    std::wstring path = imagePath.empty() ? QueryImagePath( pid ) : imagePath;
    Info info;

    if (!path.empty())
        info = _impl->Evaluate( pid, path );

    if (hasCreationTime)
    {
        Impl::CacheEntry entry;
        entry.created = created;
        entry.hasCreationTime = true;
        entry.tick = now;
        entry.info = info;
        _impl->cache[pid] = entry;
    }

    return info;
}

void Detector::ClearCache()
{
    _impl->cache.clear();
}

size_t Detector::RuleCount()
{
    _impl->Load();
    return _impl->rules.size();
}

// -------------------------------------------------------------------------
// Free helpers
// -------------------------------------------------------------------------

std::wstring QueryImagePath( DWORD pid )
{
    HANDLE process = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
    if (!process)
        return L"";

    std::vector<wchar_t> buffer( MAX_PATH * 2, 0 );
    DWORD size = static_cast<DWORD>( buffer.size() );
    std::wstring result;

    if (QueryFullProcessImageNameW( process, 0, buffer.data(), &size ))
        result.assign( buffer.data(), size );

    CloseHandle( process );
    return result;
}

std::vector<DWORD> EnumWindowPids()
{
    struct Context
    {
        std::vector<DWORD> pids;
    } context;

    EnumWindows( []( HWND window, LPARAM param ) -> BOOL
    {
        auto ctx = reinterpret_cast<Context*>( param );

        if (!IsWindowVisible( window ) || GetWindowTextLengthW( window ) == 0)
            return TRUE;

        HWND owner = GetWindow( window, GW_OWNER );
        if (owner != nullptr)
            return TRUE;

        LONG exStyle = GetWindowLongW( window, GWL_EXSTYLE );
        if (exStyle & WS_EX_TOOLWINDOW)
            return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId( window, &pid );
        if (pid != 0)
            ctx->pids.push_back( pid );

        return TRUE;
    }, reinterpret_cast<LPARAM>( &context ) );

    std::sort( context.pids.begin(), context.pids.end() );
    context.pids.erase( std::unique( context.pids.begin(), context.pids.end() ), context.pids.end() );

    return context.pids;
}

bool IsSystemImage( const std::wstring& path )
{
    wchar_t windowsDir[MAX_PATH] = { 0 };
    UINT len = GetWindowsDirectoryW( windowsDir, ARRAYSIZE( windowsDir ) );
    if (len == 0)
        return false;

    std::wstring prefix = ToLower( std::wstring( windowsDir ) + L"\\" );
    return FileStartsWith( ToLower( path ), prefix );
}
}
