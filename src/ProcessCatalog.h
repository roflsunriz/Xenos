#pragma once

#include "AppSettings.h"
#include "EngineDetect.h"

#include <windows.h>
#include <string>
#include <vector>

/// <summary>
/// GUI-independent process discovery, engine fingerprinting, filtering and
/// recent-target selection. Shared by the CLI and the GUI.
/// </summary>
namespace proc
{
    struct Entry
    {
        DWORD        pid = 0;
        std::wstring name;
        std::wstring path;
        engine::Info eng;
        int          match = 0;
    };

    struct QueryOptions
    {
        PickerMode   mode = PickerMode::Games;
        std::wstring filter;
    };

    class Catalog
    {
    public:
        /// <summary>
        /// Enumerate running processes and fingerprint their engines.
        /// </summary>
        void Refresh();

        const std::vector<Entry>& All() const { return _all; }
        bool Empty() const { return _all.empty(); }

        /// <summary>
        /// Apply mode + text filter, return entries in display order.
        /// </summary>
        std::vector<Entry> Query( const QueryOptions& options ) const;

        /// <summary>
        /// Match score for a filter string. 1 = no filter, -1 = no match.
        /// Supports:  name fragments, fuzzy subsequence, "@unity", "pid:123",
        /// and "-token" negation.
        /// </summary>
        static int MatchScore( const Entry& entry, const std::wstring& filter );

        /// <summary>
        /// Index of a PID in a list, or -1.
        /// </summary>
        static int FindPid( const std::vector<Entry>& list, DWORD pid );

        /// <summary>
        /// Index of the most recent running target in a list, or -1.
        /// </summary>
        static int FindRecent( const std::vector<Entry>& list, const AppSettings& settings );

        /// <summary>
        /// "name.exe (1234)  [Unity IL2CPP]"
        /// </summary>
        static std::wstring DisplayText( const Entry& entry );

        /// <summary>
        /// Find a process by PID, image name or full path (first match).
        /// </summary>
        bool Find( const std::wstring& nameOrPid, Entry& out ) const;

    private:
        std::vector<Entry> _all;
    };
}
