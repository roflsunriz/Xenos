#pragma once

#include "resource.h"
#include "DlgModules.h"
#include "DlgInjections.h"
#include "DlgWait.h"
#include "DlgSettings.h"
#include "ProfileMgr.h"
#include "ComboBox.hpp"
#include "EditBox.hpp"
#include "Button.hpp"
#include "StatusBar.hpp"
#include "Message.hpp"
#include "InjectionCore.h"
#include "EngineDetect.h"
#include "AppSettings.h"
#include "ProcessCatalog.h"
#include "InjectionRegistry.h"

#include "Log.h"

#define WM_APP_REFRESH_PROCESSES (WM_APP + 1)

class MainDlg : public Dialog
{
public:
    enum StartAction
    {
        Nothing = 0,
        LoadProfile,
        RunProfile
    };

public:
    MainDlg( StartAction action, const std::wstring& defConfig = L"" );
    ~MainDlg();

    /// <summary>
    /// Run injection profile
    /// </summary>
    /// <returns>Error code</returns>
    int LoadAndInject()
    {
        AppSettings::Instance().Load();
        LoadConfig( _defConfig );
        Inject();
        return 0;
    }

private:
    /// <summary>
    /// Load configuration from file
    /// </summary>
    /// <returns>Error code</returns>
    DWORD LoadConfig( const std::wstring& path = L"" );

    /// <summary>
    /// Save Configuration.
    /// </summary>
    /// <returns>Error code</returns>
    DWORD SaveConfig( const std::wstring& path = L"" );

    /// <summary>
    /// Async inject routine
    /// </summary>
    void Inject();

    /// <summary>
    /// Enumerate processes
    /// </summary>
    /// <returns>Error code</returns>
    DWORD FillProcessList();

    /// <summary>
    /// Rebuild combo contents from the cached process catalog, applying the
    /// current picker mode and text filter.
    /// </summary>
    /// <param name="keepPid">PID to keep selected if it is still visible</param>
    /// <param name="allowRestore">Allow restoring the remembered target</param>
    void RebuildProcessList( DWORD keepPid, bool allowRestore );

    /// <summary>
    /// PID of the current combo selection (0 if none)
    /// </summary>
    DWORD SelectedPid() const;

    /// <summary>
    /// Find the visible combo index for a PID (-1 if not present)
    /// </summary>
    int IndexOfPid( DWORD pid ) const;

    /// <summary>
    /// Select a visible entry and make it the active target
    /// </summary>
    void SelectVisibleItem( int index, bool remember );

    /// <summary>
    /// Select the first entry matching the typed filter (Enter key)
    /// </summary>
    void CommitFilterSelection();

    /// <summary>
    /// Current existing-process picker mode (All/Games/Recent)
    /// </summary>
    PickerMode CurrentPickerMode() const;

    /// <summary>
    /// Switch the picker mode and update the radio buttons
    /// </summary>
    void SetPickerMode( PickerMode mode );

    /// <summary>
    /// Select the whole combo edit text (so typing replaces it)
    /// </summary>
    void SelectAllComboText();

    /// Set current process
    /// </summary>
    /// <param name="pid">Target PID</param>
    /// <param name="path">Process path.</param>
    /// <returns>Error code</returns>
    DWORD SetActiveProcess( DWORD pid, const std::wstring& name );

    /// <summary>
    /// Update interface controls
    /// </summary>
    /// <returns>Error code</returns>
    DWORD UpdateInterface();

    /// <summary>
    /// Load selected image and do some validation
    /// </summary>
    /// <param name="path">Full qualified image path</param>
    /// <returns>Error code </returns>
    DWORD LoadImageFile( const std::wstring& path );

    /// <summary>
    /// Add module to module list
    /// </summary>
    /// <param name="path">Loaded image</param>
    void AddToModuleList( std::shared_ptr<blackbone::pe::PEImage>& img );

    /// <summary>
    /// Invoke Open/Save file dialog
    /// </summary>
    /// <param name="filter">File filter</param>
    /// <param name="defIndex">Default filter index</param>
    /// <param name="selectedPath">Target file path</param>
    /// <param name="bSave">true to Save file, false to open</param>
    /// <param name="defExt">Default file extension for file save</param>
    /// <returns>true on success, false if operation was canceled by user</returns>
    bool OpenSaveDialog(
        const wchar_t* filter,
        int defIndex,
        std::wstring& selectedPath,
        bool bSave = false,
        const std::wstring& defExt = L""
        );

    //
    // Message handlers
    //
    MSG_HANDLER( OnInit );
    MSG_HANDLER( OnCommand );
    MSG_HANDLER( OnDeferredInit );
    MSG_HANDLER( OnClose );
    MSG_HANDLER( OnLoadImage );
    MSG_HANDLER( OnRemoveImage );
    MSG_HANDLER( OnClearImages );
    MSG_HANDLER( OnSelectExecutable );
    MSG_HANDLER( OnExecute );
    MSG_HANDLER( OnSettings);
    MSG_HANDLER( OnDropDown );
    MSG_HANDLER( OnSelChange );
    MSG_HANDLER( OnDragDrop );
    MSG_HANDLER( OnExistingProcess );
    MSG_HANDLER( OnGamesProcess );
    MSG_HANDLER( OnRecentProcess );

    // Process picker helpers
    MSG_HANDLER( OnFilterChange );
    MSG_HANDLER( OnFilterFocus );
    MSG_HANDLER( OnComboEditKey );
    MSG_HANDLER( OnCommitFilter );
    MSG_HANDLER( OnCancelFilter );
    MSG_HANDLER( OnRefreshProcessList );
    MSG_HANDLER( OnClearEngineCache );

    MSG_HANDLER( OnLoadProfile );
    MSG_HANDLER( OnSaveProfile );

    MSG_HANDLER( OnEjectModules );
    MSG_HANDLER( OnTrackedInjections );
    MSG_HANDLER( OnEjectTracked );
    MSG_HANDLER( OnProtectSelf );

private:
    StartAction     _action;        // Starting action
    std::wstring    _defConfig;     // Profile to load on start
    InjectionCore   _core;          // Injection implementation
    ProfileMgr      _profileMgr;    // Configuration manager
    std::wstring    _processPath;   // Target process path
    vecPEImages     _images;        // Loaded module exports
    vecImageExports _exports;       // Exports list
    std::mutex      _lock;          // Injection lock

    std::vector<proc::Entry> _visible;  // Processes currently in the combo
    proc::Catalog   _catalog;           // Process enumeration + fingerprint core
    std::wstring    _filterText;        // Typed filter (independent of combo text)
    std::wstring    _restoreName;       // Target to restore (profile/last target)
    bool            _rebuilding = false;
    bool            _suppressFilter = false;

    //
    // Interface controls
    //  
    ctrl::ComboBox _procList;       // Process list
    ctrl::EditBox  _comboEdit;      // Edit portion of the process combo
    ctrl::ListView _modules;        // Image list

    ctrl::StatusBar _status;        // Status bar

    ctrl::Button _exProc;           // Existing process radio-button
    ctrl::Button _gamesProc;        // Existing -> game engines only
    ctrl::Button _recentProc;       // Existing -> recent targets
    ctrl::Button _newProc;          // New process radio-button
    ctrl::Button _autoProc;         // Manual launch radio-button
    ctrl::Button _selectProc;       // Select process path
    ctrl::Button _inject;           // Inject button
    ctrl::Button _eject;            // Eject tracked DLLs button
};