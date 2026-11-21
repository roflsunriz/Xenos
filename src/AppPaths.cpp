#include "stdafx.h"
#include "AppPaths.h"

#include <vector>

namespace apppaths
{
    std::wstring SettingsDirectory()
    {
        wchar_t appData[MAX_PATH] = { 0 };
        DWORD len = GetEnvironmentVariableW( L"APPDATA", appData, ARRAYSIZE( appData ) );

        std::wstring dir;
        if (len > 0 && len < ARRAYSIZE( appData ))
        {
            dir = std::wstring( appData ) + L"\\Xenos";
        }
        else
        {
            wchar_t module[MAX_PATH] = { 0 };
            GetModuleFileNameW( nullptr, module, ARRAYSIZE( module ) );

            auto pos = std::wstring( module ).find_last_of( L"\\/" );
            dir = pos == std::wstring::npos ? std::wstring( module ) : std::wstring( module ).substr( 0, pos );
        }

        CreateDirectoryW( dir.c_str(), nullptr );
        return dir;
    }

    std::wstring DataFile( const wchar_t* name )
    {
        return SettingsDirectory() + L"\\" + name;
    }

    std::wstring ReadTextFile( const std::wstring& path )
    {
        HANDLE file = CreateFileW(
            path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

        if (file == INVALID_HANDLE_VALUE)
            return L"";

        LARGE_INTEGER size = { 0 };
        std::wstring result;

        if (GetFileSizeEx( file, &size ) && size.QuadPart > 0 && size.QuadPart < 4 * 1024 * 1024)
        {
            std::vector<char> bytes( static_cast<size_t>( size.QuadPart ) );
            DWORD read = 0;

            if (ReadFile( file, bytes.data(), static_cast<DWORD>( bytes.size() ), &read, nullptr ))
            {
                if (read >= 2 && static_cast<unsigned char>( bytes[0] ) == 0xFF &&
                    static_cast<unsigned char>( bytes[1] ) == 0xFE)
                {
                    result.assign(
                        reinterpret_cast<const wchar_t*>( bytes.data() + 2 ),
                        (read - 2) / sizeof( wchar_t ) );
                }
                else if (read >= 3 && static_cast<unsigned char>( bytes[0] ) == 0xEF &&
                         static_cast<unsigned char>( bytes[1] ) == 0xBB &&
                         static_cast<unsigned char>( bytes[2] ) == 0xBF)
                {
                    int chars = MultiByteToWideChar(
                        CP_UTF8, 0, bytes.data() + 3, static_cast<int>( read - 3 ), nullptr, 0 );

                    result.resize( chars );
                    MultiByteToWideChar(
                        CP_UTF8, 0, bytes.data() + 3, static_cast<int>( read - 3 ),
                        &result[0], chars );
                }
                else
                {
                    int chars = MultiByteToWideChar(
                        CP_ACP, 0, bytes.data(), static_cast<int>( read ), nullptr, 0 );

                    result.resize( chars );
                    MultiByteToWideChar(
                        CP_ACP, 0, bytes.data(), static_cast<int>( read ), &result[0], chars );
                }
            }
        }

        CloseHandle( file );
        return result;
    }

    bool WriteTextFile( const std::wstring& path, const std::wstring& text )
    {
        HANDLE file = CreateFileW(
            path.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );

        if (file == INVALID_HANDLE_VALUE)
            return false;

        const wchar_t bom = 0xFEFF;
        const std::wstring data = std::wstring( 1, bom ) + text;

        DWORD written = 0;
        BOOL ok = WriteFile(
            file, data.c_str(),
            static_cast<DWORD>( data.size() * sizeof( wchar_t ) ),
            &written, nullptr );

        CloseHandle( file );
        return ok != FALSE;
    }
}
