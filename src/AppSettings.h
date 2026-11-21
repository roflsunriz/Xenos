#pragma once

#include <windows.h>
#include <string>
#include <vector>

/// <summary>
/// How the "Existing" process picker is filtered.
/// </summary>
enum class PickerMode
{
    All = 0,      // every process
    Games = 1,    // game-engine fingerprints only
    Recent = 2,   // recently used targets that are currently running
};

struct TargetRef
{
    std::wstring name;
    std::wstring path;

    bool Matches( const std::wstring& otherName, const std::wstring& otherPath ) const
    {
        if (_wcsicmp( name.c_str(), otherName.c_str() ) != 0)
            return false;

        // Empty path in a stored entry means "match by name only"
        return path.empty() || _wcsicmp( path.c_str(), otherPath.c_str() ) == 0;
    }
};

/// <summary>
/// Persistent UI / target-selection preferences.
/// Stored as UTF-16 INI under %APPDATA%\Xenos\settings.ini.
/// </summary>
class AppSettings
{
public:
    static AppSettings& Instance();

    void Load();
    void Save();

    PickerMode pickerMode = PickerMode::Games;  // last used existing-process filter
    bool autoSelectRecent = true;               // re-select the last target when running
    DWORD lastPid = 0;                          // last explicitly selected PID (validated by name/path)

    std::vector<TargetRef> recent;              // most recent first, max 8

    const TargetRef* LastTarget() const
    {
        return recent.empty() ? nullptr : &recent.front();
    }

    void RememberTarget( const std::wstring& name, const std::wstring& path );
    void ForgetTargets();

private:
    AppSettings();

    std::wstring _path;
};
