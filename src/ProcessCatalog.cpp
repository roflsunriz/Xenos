#include "stdafx.h"
#include "ProcessCatalog.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>

namespace proc
{
namespace
{
    std::wstring ToLower( std::wstring str )
    {
        for (auto& ch : str)
            ch = static_cast<wchar_t>(towlower( ch ));

        return str;
    }

    bool IsSubsequence( const std::wstring& haystack, const std::wstring& needle )
    {
        size_t pos = 0;
        for (wchar_t ch : needle)
        {
            pos = haystack.find( ch, pos );
            if (pos == std::wstring::npos)
                return false;

            pos++;
        }

        return true;
    }

    std::vector<std::wstring> Tokenize( const std::wstring& filter )
    {
        std::vector<std::wstring> tokens;
        size_t start = 0;

        while (start < filter.size())
        {
            auto end = filter.find_first_of( L" \t", start );
            if (end == std::wstring::npos)
                end = filter.size();

            auto token = filter.substr( start, end - start );
            if (!token.empty())
                tokens.emplace_back( std::move( token ) );

            start = end + 1;
        }

        return tokens;
    }

    bool SameTarget( const Entry& entry, const TargetRef& target )
    {
        return target.Matches( entry.name, entry.path );
    }
}

void Catalog::Refresh()
{
    std::vector<Entry> list;

    HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        _all.clear();
        return;
    }

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof( entry );

    if (Process32FirstW( snapshot, &entry ))
    {
        do
        {
            if (entry.th32ProcessID <= 4 || entry.th32ProcessID == GetCurrentProcessId())
                continue;

            Entry item;
            item.pid  = entry.th32ProcessID;
            item.name = entry.szExeFile;
            item.path = engine::QueryImagePath( item.pid );

            list.emplace_back( std::move( item ) );
        }
        while (Process32NextW( snapshot, &entry ));
    }

    CloseHandle( snapshot );

    for (auto& item : list)
    {
        if (!item.path.empty())
            item.eng = engine::Detector::Instance().Detect( item.pid, item.path );
    }

    _all.swap( list );
}

int Catalog::MatchScore( const Entry& entry, const std::wstring& filter )
{
    const auto tokens = Tokenize( filter );
    if (tokens.empty())
        return 1;

    const std::wstring name = ToLower( entry.name );
    const std::wstring path = ToLower( entry.path );
    const std::wstring tags = ToLower( entry.eng.allTags );
    int total = 0;

    for (auto& raw : tokens)
    {
        const bool negate = !raw.empty() && raw.front() == L'-';
        const std::wstring token = ToLower( negate ? raw.substr( 1 ) : raw );
        if (token.empty())
            continue;

        int score = 0;

        if (token.front() == L'@')
        {
            const auto want = token.substr( 1 );
            if (!want.empty() && tags.find( want ) != std::wstring::npos)
                score = 600;
        }
        else if (token.rfind( L"pid:", 0 ) == 0)
        {
            const auto digits = token.substr( 4 );
            if (!digits.empty() && std::to_wstring( entry.pid ) == digits)
                score = 1200;
        }
        else if (name == token)
            score = 1000;
        else if (name.rfind( token, 0 ) == 0)
            score = 900;
        else if (name.find( token ) != std::wstring::npos)
            score = 800;
        else if (path.find( token ) != std::wstring::npos)
            score = 600;
        else if (tags.find( token ) != std::wstring::npos)
            score = 500;
        else if (token.size() >= 2 && IsSubsequence( name, token ))
            score = 300;

        if (negate)
        {
            if (score > 0)
                return -1;
        }
        else
        {
            if (score == 0)
                return -1;

            total += score;
        }
    }

    return total;
}

std::vector<Entry> Catalog::Query( const QueryOptions& options ) const
{
    std::vector<Entry> result;

    if (options.mode == PickerMode::Recent)
    {
        const auto& recent = AppSettings::Instance().recent;

        for (size_t rank = 0; rank < recent.size(); rank++)
        {
            for (auto& item : _all)
            {
                if (!SameTarget( item, recent[rank] ))
                    continue;

                if (MatchScore( item, options.filter ) < 0)
                    break;

                Entry copy = item;
                copy.match = 10000 - static_cast<int>( rank );
                result.emplace_back( std::move( copy ) );
                break;
            }
        }

        return result;
    }

    result.reserve( _all.size() );

    for (auto& item : _all)
    {
        if (options.mode == PickerMode::Games && !item.eng.game)
            continue;

        const int score = MatchScore( item, options.filter );
        if (score < 0)
            continue;

        Entry copy = item;
        copy.match = score;
        result.emplace_back( std::move( copy ) );
    }

    std::sort( result.begin(), result.end(), []( const Entry& left, const Entry& right )
    {
        if (left.match != right.match)
            return left.match > right.match;

        if (left.eng.game != right.eng.game)
            return left.eng.game > right.eng.game;

        int cmp = _wcsicmp( left.name.c_str(), right.name.c_str() );
        if (cmp != 0)
            return cmp < 0;

        return left.pid < right.pid;
    } );

    return result;
}

int Catalog::FindPid( const std::vector<Entry>& list, DWORD pid )
{
    for (size_t i = 0; i < list.size(); i++)
    {
        if (list[i].pid == pid)
            return static_cast<int>( i );
    }

    return -1;
}

int Catalog::FindRecent( const std::vector<Entry>& list, const AppSettings& settings )
{
    // Prefer the exact instance that was selected last time (validated against
    // the remembered name/path so PID reuse cannot select an unrelated image).
    if (settings.lastPid != 0)
    {
        for (size_t i = 0; i < list.size(); i++)
        {
            if (list[i].pid != settings.lastPid)
                continue;

            for (auto& target : settings.recent)
            {
                if (target.Matches( list[i].name, list[i].path ))
                    return static_cast<int>( i );
            }
        }
    }

    for (auto& target : settings.recent)
    {
        for (size_t i = 0; i < list.size(); i++)
        {
            if (target.Matches( list[i].name, list[i].path ))
                return static_cast<int>( i );
        }
    }

    return -1;
}

std::wstring Catalog::DisplayText( const Entry& entry )
{
    std::wstring text = entry.name + L" (" + std::to_wstring( entry.pid ) + L")";
    if (!entry.eng.tag.empty())
        text += L"  [" + entry.eng.tag + L"]";

    return text;
}

bool Catalog::Find( const std::wstring& nameOrPid, Entry& out ) const
{
    if (nameOrPid.empty())
        return false;

    // Numeric input is treated as a PID
    wchar_t* end = nullptr;
    unsigned long pid = wcstoul( nameOrPid.c_str(), &end, 10 );
    if (end != nameOrPid.c_str() && *end == L'\0' && pid > 0)
    {
        for (auto& item : _all)
        {
            if (item.pid == pid)
            {
                out = item;
                return true;
            }
        }
    }

    const std::wstring lower = ToLower( nameOrPid );

    for (auto& item : _all)
    {
        if (ToLower( item.path ) == lower)
        {
            out = item;
            return true;
        }
    }

    for (auto& item : _all)
    {
        if (ToLower( item.name ) == lower )
        {
            out = item;
            return true;
        }
    }

    for (auto& item : _all)
    {
        if (ToLower( item.name ).find( lower ) != std::wstring::npos)
        {
            out = item;
            return true;
        }
    }

    return false;
}
}
