#pragma once

#include <string>

/// <summary>
/// Shared UTF-16 file and per-user data directory helpers.
/// </summary>
namespace apppaths
{
    /// <summary>
    /// %APPDATA%\Xenos (created on demand). Falls back to the exe directory.
    /// </summary>
    std::wstring SettingsDirectory();

    /// <summary>
    /// Full path of a file inside the settings directory.
    /// </summary>
    std::wstring DataFile( const wchar_t* name );

    /// <summary>
    /// Read a UTF-16 (BOM) / UTF-8 / ANSI text file.
    /// </summary>
    std::wstring ReadTextFile( const std::wstring& path );

    /// <summary>
    /// Write a UTF-16LE file with BOM.
    /// </summary>
    bool WriteTextFile( const std::wstring& path, const std::wstring& text );
}
