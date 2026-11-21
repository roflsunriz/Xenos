#include "DlgInjections.h"
#include "InjectionCore.h"
#include "Message.hpp"

#include <algorithm>

namespace
{
    const wchar_t* MethodText( int method )
    {
        switch (method)
        {
            case Normal:           return L"Normal";
            case Manual:           return L"Manual";
            case Kernel_Thread:    return L"Kernel Thr";
            case Kernel_APC:       return L"Kernel APC";
            case Kernel_MMap:      return L"Kernel Map";
            case Kernel_DriverMap: return L"Driver";
        }

        return L"Unknown";
    }
}

DlgInjections::DlgInjections()
    : Dialog( IDD_INJECTIONS )
{
    _messages[WM_INITDIALOG]        = static_cast<Dialog::fnDlgProc>(&DlgInjections::OnInit);

    _events[IDC_TRACKED_EJECT]      = static_cast<Dialog::fnDlgProc>(&DlgInjections::OnEject);
    _events[IDC_TRACKED_REINJECT]   = static_cast<Dialog::fnDlgProc>(&DlgInjections::OnReinject);
    _events[IDC_TRACKED_REFRESH]    = static_cast<Dialog::fnDlgProc>(&DlgInjections::OnRefresh);
    _events[IDC_TRACKED_CLOSE]      = static_cast<Dialog::fnDlgProc>(&DlgInjections::OnClose);
}

DlgInjections::~DlgInjections()
{
}

INT_PTR DlgInjections::OnInit( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    Dialog::OnInit( hDlg, message, wParam, lParam );

    _list.Attach( GetDlgItem( hDlg, IDC_TRACKED_LIST ) );
    ListView_SetExtendedListViewStyle( _list.hwnd(), LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER );

    _list.AddColumn( L"Handle", 60,  0 );
    _list.AddColumn( L"PID",    55,  1 );
    _list.AddColumn( L"Module", 160, 2 );
    _list.AddColumn( L"Base",   120, 3 );
    _list.AddColumn( L"Method", 70,  4 );
    _list.AddColumn( L"State",  60,  5 );
    _list.AddColumn( L"Image",  260, 6 );

    RefreshList();
    return TRUE;
}

void DlgInjections::RefreshList()
{
    _list.reset();
    _ids.clear();

    auto records = InjectionRegistry::Instance().All();
    std::sort( records.begin(), records.end(), []( const InjectionRecord& left, const InjectionRecord& right )
    {
        return left.id > right.id;
    } );

    for (auto& record : records)
    {
        const bool live = IsInjectionLive( record );
        const wchar_t* state = record.state == static_cast<int>( InjectionState::Ejected ) ? L"ejected" :
            live ? L"loaded" : L"stale";

        wchar_t base[32] = { 0 };
        swprintf_s( base, L"0x%llx", static_cast<unsigned long long>( record.baseAddress ) );

        wchar_t handle[32] = { 0 };
        swprintf_s( handle, L"#%u", record.id );

        wchar_t pid[32] = { 0 };
        swprintf_s( pid, L"%lu", record.pid );

        _ids.emplace_back( record.id );
        _list.AddItem(
            record.moduleName,
            static_cast<LPARAM>( record.id ),
            { handle, pid, base, MethodText( record.method ), state, record.imagePath } );
    }
}

INT_PTR DlgInjections::OnEject( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    const int index = _list.selection();
    if (index < 0 || index >= static_cast<int>( _ids.size() ))
        return TRUE;

    std::wstring error;
    const EjectStatus status = EjectInjection( _ids[index], false, error );

    if (status == EjectStatus::Ok || status == EjectStatus::AlreadyGone)
        RefreshList();
    else
        Message::ShowError( hDlg, error );

    return TRUE;
}

INT_PTR DlgInjections::OnReinject( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    const int index = _list.selection();
    if (index < 0 || index >= static_cast<int>( _ids.size() ))
        return TRUE;

    uint32_t newId = 0;
    std::wstring messageText;
    if (ReinjectInjection( _ids[index], hDlg, newId, messageText ))
    {
        Message::ShowInfo( hDlg, messageText );
        RefreshList();
    }
    else
    {
        Message::ShowError( hDlg, messageText );
    }

    return TRUE;
}

INT_PTR DlgInjections::OnRefresh( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    RefreshList();
    return TRUE;
}

INT_PTR DlgInjections::OnClose( HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam )
{
    return CloseDialog();
}
