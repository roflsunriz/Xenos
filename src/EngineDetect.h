#pragma once

#include <windows.h>
#include <memory>
#include <string>
#include <vector>

/// <summary>
/// Game engine fingerprinting for running processes.
///
/// Detection is based on loaded module names, sidecar files/directories in the
/// image directory and executable naming conventions. Results are cached per
/// PID (invalidated on PID reuse and periodically for negative results).
/// </summary>
namespace engine
{
    struct Info
    {
        bool         valid = false;   // fingerprint succeeded
        bool         game  = false;   // best match is a game engine (not a runtime)
        int          score = 0;
        std::wstring engine;          // "Unity", "Unreal Engine", ...
        std::wstring variant;         // "IL2CPP", "UE5", ...
        std::wstring tag;             // "Unity IL2CPP"
        std::wstring allTags;         // every engine that matched, "Unity IL2CPP, .NET"

        std::wstring DisplayTag() const
        {
            if (engine.empty())
                return tag;

            return variant.empty() ? engine : (engine + L" " + variant);
        }
    };

    class Detector
    {
    public:
        static Detector& Instance();

        /// <summary>
        /// Fingerprint a process. imagePath may be empty (will be queried).
        /// </summary>
        Info Detect( DWORD pid, const std::wstring& imagePath = L"" );

        /// <summary>
        /// Drop all cached fingerprints.
        /// </summary>
        void ClearCache();

        /// <summary>
        /// Number of active rules (built-in + engines.ini).
        /// </summary>
        size_t RuleCount();

    private:
        Detector();
        ~Detector();
        Detector( const Detector& ) = delete;
        Detector& operator=( const Detector& ) = delete;

        struct Impl;
        std::unique_ptr<Impl> _impl;
    };

    /// <summary>
    /// Full image path of a running process (empty on failure).
    /// </summary>
    std::wstring QueryImagePath( DWORD pid );

    /// <summary>
    /// PID of every process that owns a visible, titled top-level window.
    /// </summary>
    std::vector<DWORD> EnumWindowPids();

    /// <summary>
    /// true if the image lives under the Windows directory.
    /// </summary>
    bool IsSystemImage( const std::wstring& path );
}
