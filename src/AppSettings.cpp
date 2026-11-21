#include "stdafx.h"
#include "AppSettings.h"
#include "AppPaths.h"

#include <algorithm>
#include <vector>

namespace
{
    const size_t MaxRecentTargets = 8;

    std::wstring Trim( const std::wstring& str )
    {
        const wchar_t* ws = L" \t\r\n";
        auto begin = str.find_first_not_of( ws );
        if (begin == std::wstring::npos)
            return L"";

        auto end = str.find_last_not_of( ws );
        return str.substr( begin, end - begin + 1 );
    }

    std::wstring Sanitize( const std::wstring& value )
    {
        std::wstring result = value;
        for (auto& ch : result)
        {
            if (ch == L'\r' || ch == L'\n')
                ch = L' ';
        }

        return result;
    }

    bool ParseBool( const std::wstring& value, bool def )
    {
        if (value.empty())
            return def;

        return _wtoi( value.c_str() ) != 0;
    }

    PickerMode ParseMode( const std::wstring& value, PickerMode def )
    {
        if (_wcsicmp( value.c_str(), L"All" ) == 0)
            return PickerMode::All;
        if (_wcsicmp( value.c_str(), L"Games" ) == 0)
            return PickerMode::Games;
        if (_wcsicmp( value.c_str(), L"Recent" ) == 0)
            return PickerMode::Recent;

        return def;
    }

    const wchar_t* ModeName( PickerMode mode )
    {
        switch (mode)
        {
            case PickerMode::All:    return L"All";
            case PickerMode::Games:  return L"Games";
            case PickerMode::Recent: return L"Recent";
        }

        return L"Games";
    }
}

AppSettings& AppSettings::Instance()
{
    static AppSettings instance;
    return instance;
}

AppSettings::AppSettings()
    : _path( apppaths::DataFile( L"settings.ini" ) )
{
}

void AppSettings::Load()
{
    auto text = apppaths::ReadTextFile( _path );
    if (text.empty())
        return;

    bool inTarget = false;
    size_t start = 0;

    std::wstring legacyName, legacyPath;
    std::vector<std::pair<int, TargetRef>> stored;

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
            inTarget = _wcsicmp( line.c_str(), L"[Target]" ) == 0;
            continue;
        }

        if (!inTarget)
            continue;

        auto eq = line.find( L'=' );
        if (eq == std::wstring::npos)
            continue;

        std::wstring key = Trim( line.substr( 0, eq ) );
        std::wstring value = Trim( line.substr( eq + 1 ) );

        if (_wcsicmp( key.c_str(), L"Mode" ) == 0)
        {
            pickerMode = ParseMode( value, pickerMode );
        }
        else if (_wcsicmp( key.c_str(), L"AutoSelectLast" ) == 0)
        {
            autoSelectRecent = ParseBool( value, autoSelectRecent );
        }
        else if (_wcsicmp( key.c_str(), L"LastPid" ) == 0)
        {
            lastPid = static_cast<DWORD>( _wtoi( value.c_str() ) );
        }
        else if (_wcsicmp( key.c_str(), L"LastName" ) == 0)
        {
            legacyName = value;
        }
        else if (_wcsicmp( key.c_str(), L"LastPath" ) == 0)
        {
            legacyPath = value;
        }
        else if (key.size() > 4 && _wcsnicmp( key.c_str(), L"Rec", 3 ) == 0)
        {
            // Rec<N>Name / Rec<N>Path
            auto suffix = key.find( L"Name", 3 );
            bool isName = suffix != std::wstring::npos;
            if (!isName)
                suffix = key.find( L"Path", 3 );

            if (suffix == std::wstring::npos)
                continue;

            int index = _wtoi( key.substr( 3, suffix - 3 ).c_str() );
            auto it = std::find_if( stored.begin(), stored.end(), [&]( const std::pair<int, TargetRef>& item )
            {
                return item.first == index;
            } );

            if (it == stored.end())
            {
                stored.emplace_back( index, TargetRef() );
                it = stored.end() - 1;
            }

            if (isName)
                it->second.name = value;
            else
                it->second.path = value;
        }
    }

    std::sort( stored.begin(), stored.end(), []( const std::pair<int, TargetRef>& a, const std::pair<int, TargetRef>& b )
    {
        return a.first < b.first;
    } );

    recent.clear();
    for (auto& item : stored)
    {
        if (!item.second.name.empty())
            recent.emplace_back( std::move( item.second ) );
    }

    if (recent.empty() && !legacyName.empty())
        recent.emplace_back( TargetRef{ legacyName, legacyPath } );

    if (recent.size() > MaxRecentTargets)
        recent.resize( MaxRecentTargets );
}

void AppSettings::Save()
{
    std::wstring text;
    text += L"; Xenos fork preferences\n";
    text += L"[Target]\n";
    text += L"Mode=" + std::wstring( ModeName( pickerMode ) ) + L"\n";
    text += L"AutoSelectLast=" + std::wstring( autoSelectRecent ? L"1" : L"0" ) + L"\n";
    text += L"LastPid=" + std::to_wstring( lastPid ) + L"\n";

    for (size_t i = 0; i < recent.size() && i < MaxRecentTargets; i++)
    {
        auto index = std::to_wstring( i );
        text += L"Rec" + index + L"Name=" + Sanitize( recent[i].name ) + L"\n";
        text += L"Rec" + index + L"Path=" + Sanitize( recent[i].path ) + L"\n";
    }

    apppaths::WriteTextFile( _path, text );
}

void AppSettings::RememberTarget( const std::wstring& name, const std::wstring& path )
{
    if (name.empty())
        return;

    recent.erase(
        std::remove_if( recent.begin(), recent.end(), [&]( const TargetRef& item )
        {
            return item.Matches( name, path );
        } ),
        recent.end() );

    recent.insert( recent.begin(), TargetRef{ name, path } );

    if (recent.size() > MaxRecentTargets)
        recent.resize( MaxRecentTargets );
}

void AppSettings::ForgetTargets()
{
    recent.clear();
    lastPid = 0;
}
