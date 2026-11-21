#include "MainDlg.h"

#include <thread>
#include <future>
#include <shellapi.h>

MainDlg::MainDlg( MainDlg::StartAction action, const std::wstring& defConfig /*= L""*/ )
    : Dialog( IDD_MAIN )
    , _core( _hwnd )
    , _action( action )
    , _defConfig( defConfig )
{
    _messages[WM_INITDIALOG]        = static_cast<Dialog::fnDlgProc>(&MainDlg::OnInit);
    _messages[WM_COMMAND]           = static_cast<Dialog::fnDlgProc>(&MainDlg::OnCommand);
    _messages[WM_CLOSE]             = static_cast<Dialog::fnDlgProc>(&MainDlg::OnClose);
    _messages[WM_DROPFILES]         = static_cast<Dialog::fnDlgProc>(&MainDlg::OnDragDrop);

    _events[IDC_EXECUTE]            = static_cast<Dialog::fnDlgProc>(&MainDlg::OnExecute);
    _events[IDC_SETTINGS]           = static_cast<Dialog::fnDlgProc>(&MainDlg::OnSettings);
    _events[IDC_NEW_PROC]           = static_cast<Dialog::fnDlgProc>(&MainDlg::OnSelectExecutable);
    _events[IDC_EXISTING_PROC]      = static_cast<Dialog::fnDlgProc>(&MainDlg::OnExistingProcess);
    _events[IDC_GAMES_PROC]         = static_cast<Dialog::fnDlgProc>(&MainDlg::OnGamesProcess);
    _events[IDC_RECENT_PROC]        = static_cast<Dialog::fnDlgProc>(&MainDlg::OnRecentProcess);
    _events[IDC_AUTO_PROC]          = static_cast<Dialog::fnDlgProc>(&MainDlg::OnSelectExecutable);
    _events[IDC_SELECT_PROC]        = static_cast<Dialog::fnDlgProc>(&MainDlg::OnSelectExecutable);
    _events[IDC_ADD_MOD]            = static_cast<Dialog::fnDlgProc>(&MainDlg::OnLoadImage);
    _events[IDC_REMOVE_MOD]         = static_cast<Dialog::fnDlgProc>(&MainDlg::OnRemoveImage);
    _events[IDC_CLEAR_MODS]         = static_cast<Dialog::fnDlgProc>(&MainDlg::OnClearImages);
    _events[CBN_DROPDOWN]           = static_cast<Dialog::fnDlgProc>(&MainDlg::OnDropDown);
    _events[CBN_SELCHANGE]          = static_cast<Dialog::fnDlgProc>(&MainDlg::OnSelChange);
    _events[CBN_EDITCHANGE]         = static_cast<Dialog::fnDlgProc>(&MainDlg::OnFilterChange);
    _events[CBN_SETFOCUS]           = static_cast<Dialog::fnDlgProc>(&MainDlg::OnFilterFocus);
    _events[ID_VIEW_REFRESH]        = static_cast<Dialog::fnDlgProc>(&MainDlg::OnRefreshProcessList);
    _events[ID_VIEW_CLEARCACHE]     = static_cast<Dialog::fnDlgProc>(&MainDlg::OnClearEngineCache);
    _messages[WM_APP_REFRESH_PROCESSES] = static_cast<Dialog::fnDlgProc>(&MainDlg::OnDeferredInit);
    _events[ID_PROFILES_OPEN]       = static_cast<Dialog::fnDlgProc>(&MainDlg::OnLoadProfile);
    _events[ID_PROFILES_SAVE]       = static_cast<Dialog::fnDlgProc>(&MainDlg::OnSaveProfile);
    _events[ID_TOOLS_PROTECT]       = static_cast<Dialog::fnDlgProc>(&MainDlg::OnProtectSelf);
    _events[ID_TOOLS_EJECTMODULES]  = static_cast<Dialog::fnDlgProc>(&MainDlg::OnEjectModules);

    // Accelerators
    _events[ID_ACCEL_OPEN]          = static_cast<Dialog::fnDlgProc>(&MainDlg::OnLoadProfile);
    _events[ID_ACCEL_SAVE]          = static_cast<Dialog::fnDlgProc>(&MainDlg::OnSaveProfile);
}

MainDlg::~MainDlg()
{
}

INT_PTR MainDlg::OnInit( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    Dialog::OnInit( hDlg, message, wParam, lParam );

    //
    // Setup controls
    //
    _procList.Attach( _hwnd, IDC_COMBO_PROC );
    _exProc.Attach( _hwnd, IDC_EXISTING_PROC );
    _gamesProc.Attach( _hwnd, IDC_GAMES_PROC );
    _recentProc.Attach( _hwnd, IDC_RECENT_PROC );
    _newProc.Attach( _hwnd, IDC_NEW_PROC );
    _autoProc.Attach(_hwnd, IDC_AUTO_PROC );
    _selectProc.Attach( _hwnd, IDC_SELECT_PROC );
    _modules.Attach( _hwnd, IDC_MODS );
    _inject.Attach( _hwnd, IDC_EXECUTE );

    // Wide drop-down so engine tags are readable
    SendMessageW( _procList.hwnd(), CB_SETDROPPEDWIDTH, 560, 0 );

    // Subclass the combo edit so Enter/Esc work while typing a filter
    COMBOBOXINFO comboInfo = { 0 };
    comboInfo.cbSize = sizeof( comboInfo );
    if (GetComboBoxInfo( _procList.hwnd(), &comboInfo ) && comboInfo.hwndItem)
    {
        _comboEdit.Attach( comboInfo.hwndItem );
        _comboEdit.Subclass(
            WM_KEYDOWN,
            static_cast<Window::fnWndProc>(&MainDlg::OnComboEditKey),
            this );
    }

    AppSettings::Instance().Load();

    // Setup modules view
    _modules.AddColumn( L"Name", 150, 0 );
    _modules.AddColumn( L"Architecture", 100, 1 );

    ListView_SetExtendedListViewStyle( _modules.hwnd(), LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER );

    // Set dialog title
    SetWindowTextW( _hwnd, blackbone::Utils::RandomANString().c_str() );

    // UAC drop-down bypass
    ChangeWindowMessageFilterEx( hDlg, WM_DROPFILES, MSGFLT_ADD, nullptr );
    ChangeWindowMessageFilterEx( hDlg, 0x49/*WM_COPYGLOBALDATA*/, MSGFLT_ADD, nullptr );

    // Protection option
    if (blackbone::Driver().loaded())
        EnableMenuItem( GetMenu( _hwnd ), ID_TOOLS_PROTECT, MF_ENABLED );

    // Set icon
    HICON hIcon = LoadIcon( GetModuleHandle( NULL ), MAKEINTRESOURCE( IDI_ICON1 ) );
    SendMessage( hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon );
    SendMessage( hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon );
    DestroyIcon( hIcon );

    // Setup status bar
    _status.Attach( CreateWindowW ( STATUSCLASSNAME, L"", WS_CHILD | WS_VISIBLE,
        0, 0, 0, 10, hDlg, NULL, GetModuleHandle( NULL ), NULL ) );

    _status.SetParts( { 150, 200, -1 } );
    _status.SetText( 0, L"Default profile" );

#ifdef USE64
    _status.SetText( 1, L"x64" );
#else
    _status.SetText( 1, L"x86" );
#endif
    _status.SetText( 2, L"Idle" );

    LoadConfig( _defConfig );

    PostMessageW( _hwnd, WM_APP_REFRESH_PROCESSES, 0, 0 );

    return TRUE;
}

INT_PTR MainDlg::OnCommand( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    // IDOK/IDCANCEL are small integers that collide with combo-box
    // notification codes, so handle them before the generic dispatcher.
    if (HIWORD( wParam ) == 0)
    {
        if (LOWORD( wParam ) == IDOK)
            return OnCommitFilter( hDlg, message, wParam, lParam );

        if (LOWORD( wParam ) == IDCANCEL)
            return OnCancelFilter( hDlg, message, wParam, lParam );
    }

    return Dialog::OnCommand( hDlg, message, wParam, lParam );
}

INT_PTR MainDlg::OnDeferredInit( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    FillProcessList();
    UpdateInterface();

    return TRUE;
}

INT_PTR MainDlg::OnFilterFocus( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    // Replace the displayed selection with the next typed character
    SelectAllComboText();
    return TRUE;
}

INT_PTR MainDlg::OnComboEditKey( HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam )
{
    if (wParam == VK_RETURN)
    {
        CommitFilterSelection();
        return 0;
    }

    if (wParam == VK_ESCAPE)
    {
        if (!_filterText.empty())
        {
            _filterText.clear();

            _suppressFilter = true;
            _procList.selectedText( L"" );
            _suppressFilter = false;

            RebuildProcessList( 0, true );
            return 0;
        }
    }

    return CallWindowProcW( _comboEdit.oldProc(), hWnd, message, wParam, lParam );
}

INT_PTR MainDlg::OnFilterChange( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    if (_suppressFilter || _rebuilding)
        return TRUE;

    _filterText = _procList.selectedText();
    RebuildProcessList( SelectedPid(), false );

    return TRUE;
}

INT_PTR MainDlg::OnCommitFilter( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    CommitFilterSelection();
    return TRUE;
}

INT_PTR MainDlg::OnCancelFilter( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    // First Esc clears the filter, second one closes the dialog
    if (!_filterText.empty())
    {
        _filterText.clear();
        _suppressFilter = true;
        _procList.selectedText( L"" );
        _suppressFilter = false;

        RebuildProcessList( 0, true );
        return TRUE;
    }

    return FALSE;
}

INT_PTR MainDlg::OnExistingProcess( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    SetPickerMode( PickerMode::All );
    return TRUE;
}

INT_PTR MainDlg::OnGamesProcess( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    SetPickerMode( PickerMode::Games );
    return TRUE;
}

INT_PTR MainDlg::OnRecentProcess( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    SetPickerMode( PickerMode::Recent );
    return TRUE;
}

PickerMode MainDlg::CurrentPickerMode() const
{
    if (_gamesProc.checked())
        return PickerMode::Games;

    if (_recentProc.checked())
        return PickerMode::Recent;

    return PickerMode::All;
}

void MainDlg::SetPickerMode( PickerMode mode )
{
    auto& settings = AppSettings::Instance();
    settings.pickerMode = mode;
    settings.Save();

    _exProc.checked( mode == PickerMode::All );
    _gamesProc.checked( mode == PickerMode::Games );
    _recentProc.checked( mode == PickerMode::Recent );
    _newProc.checked( false );
    _autoProc.checked( false );

    _profileMgr.config().processMode = Existing;
    _filterText.clear();

    if (_catalog.Empty())
        FillProcessList();
    else
        RebuildProcessList( 0, true );

    UpdateInterface();
}

INT_PTR MainDlg::OnRefreshProcessList( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    FillProcessList();
    return TRUE;
}

INT_PTR MainDlg::OnClearEngineCache( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    engine::Detector::Instance().ClearCache();
    FillProcessList();
    return TRUE;
}

INT_PTR MainDlg::OnClose( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    if(_procList.selection() != -1 && !_images.empty())
        SaveConfig();

    AppSettings::Instance().Save();

    return Dialog::OnClose( hDlg, message, wParam, lParam );
}

INT_PTR MainDlg::OnDropDown( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    if (LOWORD( wParam ) == IDC_COMBO_PROC)
        FillProcessList();

    return TRUE;
}

INT_PTR MainDlg::OnSelChange( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    // Process selection
    if (LOWORD( wParam ) == IDC_COMBO_PROC && !_rebuilding)
    {
        const DWORD pid = SelectedPid();
        if (pid != 0)
        {
            const int index = IndexOfPid( pid );
            if (index >= 0)
                SelectVisibleItem( index, true );
        }
    }

    return TRUE;
}

int MainDlg::IndexOfPid( DWORD pid ) const
{
    return proc::Catalog::FindPid( _visible, pid );
}

DWORD MainDlg::SelectedPid() const
{
    const int index = ComboBox_GetCurSel( _procList.hwnd() );
    if (index < 0)
        return 0;

    return static_cast<DWORD>( ComboBox_GetItemData( _procList.hwnd(), index ) );
}

void MainDlg::SelectVisibleItem( int index, bool remember )
{
    if (index < 0 || index >= (int)_visible.size())
        return;

    const auto& entry = _visible[index];

    _rebuilding = true;
    ComboBox_SetCurSel( _procList.hwnd(), index );
    _rebuilding = false;

    SetActiveProcess( entry.pid, entry.path.empty() ? entry.name : entry.path );

    if (remember)
    {
        auto& settings = AppSettings::Instance();
        settings.RememberTarget( entry.name, entry.path );
        settings.lastPid = entry.pid;
        settings.Save();

        _restoreName.clear();
        _filterText.clear();
        SelectAllComboText();
    }

    UpdateInterface();
}

void MainDlg::SelectAllComboText()
{
    COMBOBOXINFO info = { 0 };
    info.cbSize = sizeof( info );

    if (GetComboBoxInfo( _procList.hwnd(), &info ) && info.hwndItem)
        SendMessageW( info.hwndItem, EM_SETSEL, 0, -1 );
}

void MainDlg::CommitFilterSelection()
{
    // Enter while the list is open is handled by the combo box itself
    if (ComboBox_GetDroppedState( _procList.hwnd() ))
        return;

    if (_filterText.empty() && SelectedPid() != 0)
        return;

    if (!_visible.empty())
        SelectVisibleItem( 0, true );
}

INT_PTR MainDlg::OnLoadImage( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    std::wstring path;
    EnableWindow( GetDlgItem( hDlg, IDC_ADD_MOD ), FALSE );
    bool res = OpenSaveDialog(
        L"All (*.*)\0*.*\0Dynamic link library (*.dll)\0*.dll\0System driver (*.sys)\0*.sys\0",
        (_profileMgr.config().injectMode == Kernel_DriverMap) ? 3 : 2,
        path 
        );

    // Reset init routine upon load
    if (res && LoadImageFile( path ) == ERROR_SUCCESS)
        _profileMgr.config().initRoutine = L"";

    EnableWindow( GetDlgItem( hDlg, IDC_ADD_MOD ), TRUE );
    return TRUE;
}

INT_PTR MainDlg::OnRemoveImage( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    auto idx = _modules.selection();
    if (idx >= 0)
    {
        _modules.RemoveItem( idx );
        _images.erase( _images.begin() + idx );
        _exports.erase( _exports.begin() + idx );
    }

    // Disable inject if no images
    if (_images.empty())
        _inject.disable();

    return TRUE;
}

INT_PTR MainDlg::OnClearImages( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    _profileMgr.config().images.clear();
    _images.clear();
    _exports.clear();
    _modules.reset();
    _inject.disable();

    return TRUE;
}

INT_PTR MainDlg::OnExecute( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    // Attach modes require a live PID
    if (!_newProc.checked() && !_autoProc.checked() && SelectedPid() == 0)
        return TRUE;

    std::lock_guard<std::mutex> lg( _lock );
    std::thread( &MainDlg::Inject, this ).detach();
    return TRUE;
}

INT_PTR MainDlg::OnSettings( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    blackbone::pe::vecExports diff, tmp;

    // Get mutual exports for all modules
    if (!_exports.empty())
    {
        diff = tmp = _exports[0];
        for (size_t i = 1; i < _exports.size(); i++)
        {
            diff.clear();
            std::set_intersection( _exports[i].begin(), _exports[i].end(), tmp.begin(), tmp.end(), std::inserter( diff, diff.begin() ) );
            tmp = diff;
        }
    }

    DlgSettings dlg( _profileMgr );
    dlg.SetExports( diff );

    _profileMgr.config().processMode =
        (_newProc.checked() ? NewProcess : (_autoProc.checked() ? ManualLaunch : Existing));

    dlg.RunModal( hDlg );
    UpdateInterface();
    return TRUE;
}

INT_PTR MainDlg::OnSelectExecutable( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    std::wstring path;

    EnableWindow( GetDlgItem( hDlg, IDC_SELECT_PROC ), FALSE );
    if (OpenSaveDialog( L"All (*.*)\0*.*\0Executable image (*.exe)\0*.exe\0", 2, path ))
        SetActiveProcess( 0, path );
    else
        _procList.reset();

    _profileMgr.config().processMode = _newProc.checked() ? NewProcess : ManualLaunch;
    UpdateInterface();
    EnableWindow( GetDlgItem( hDlg, IDC_SELECT_PROC ), TRUE );
    return TRUE;
}

INT_PTR MainDlg::OnDragDrop( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    wchar_t path[MAX_PATH] = { 0 };
    HDROP hDrop = (HDROP)wParam;

    if (DragQueryFile( hDrop, 0, path, ARRAYSIZE( path ) ) != 0)
    {
        // Reset init routine
        if (LoadImageFile( path ) == ERROR_SUCCESS)
            _profileMgr.config().initRoutine = L"";
    }

    return 0;
}

INT_PTR MainDlg::OnLoadProfile( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    std::wstring path;
#ifdef USE64
    if (OpenSaveDialog( L"Xenos profiles (*.xpr64)\0*.xpr64\0", 1, path ))
#else
    if (OpenSaveDialog( L"Xenos profiles (*.xpr)\0*.xpr\0", 1, path ))
#endif
    {
        // Reset loaded images
        _profileMgr.config().images.clear();
        _images.clear();
        _modules.reset();
        _exports.clear();

        LoadConfig( path );
        _status.SetText( 0, blackbone::Utils::StripPath( path ) );
    }

    return TRUE;
}

INT_PTR MainDlg::OnSaveProfile( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    std::wstring path;
#ifdef USE64
    if (OpenSaveDialog( L"Xenos profiles (*.xpr64)\0*.xpr64\0", 1, path, true, L"xpr64" ))
#else
    if (OpenSaveDialog( L"Xenos profiles (*.xpr)\0*.xpr\0", 1, path, true, L"xpr" ))
#endif
    {
        SaveConfig( path );
        _status.SetText( 0, blackbone::Utils::StripPath( path ) );
    }

    return TRUE;
}

INT_PTR MainDlg::OnProtectSelf( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    NTSTATUS status = STATUS_SUCCESS;

    // Protect current process
    if (blackbone::Driver().loaded())
    {
        //status = blackbone::Driver().ProtectProcess( GetCurrentProcessId(), true );
        status |= blackbone::Driver().UnlinkHandleTable( GetCurrentProcessId() );
    }

    if (!NT_SUCCESS( status ))
        Message::ShowError( hDlg, L"Failed to protect current process.\n" + blackbone::Utils::GetErrorDescription( status ) );
    else
        Message::ShowInfo( hDlg, L"Successfully protected" );

    return TRUE;
}


INT_PTR MainDlg::OnEjectModules( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    auto pid = SelectedPid();

    // Try attaching to current selection
    if (pid > 0 && _core.process().pid() != pid)
    {
        auto status = _core.process().Attach( pid );
        if (status != STATUS_SUCCESS)
        {
            std::wstring errmsg = L"Can not attach to process.\n" + blackbone::Utils::GetErrorDescription( status );
            Message::ShowError( hDlg, errmsg );
            return TRUE;
        }
    }

    if (!_core.process().valid())
    {
        Message::ShowError( hDlg, L"Please select valid process before unloading modules" );
        return TRUE;
    }

    ModulesDlg dlg( _core.process() );
    return dlg.RunModal( hDlg );
}
