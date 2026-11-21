#pragma once

#include "Dialog.hpp"
#include "resource.h"
#include "ListView.hpp"

#include <BlackBone/src/BlackBone/Process/Process.h>
#include <BlackBone/src/BlackBone/Misc/Utils.h>

#include <map>
#include <string>

class ModulesDlg : public Dialog
{
    enum ColumnID
    {
        Name = 0,
        ImageBase,
        Platform,
        LoadType
    };

public:
    ModulesDlg( blackbone::Process& proc );
    ~ModulesDlg();

private:
    /// <summary>
    /// Refresh module list
    /// </summary>
    void RefreshList();

    MSG_HANDLER( OnInit );
    MSG_HANDLER( OnCloseBtn );
    MSG_HANDLER( OnUnload );

private:
    struct ModuleInfo
    {
        std::wstring name;
        std::wstring path;
        bool manual = false;
    };

    ctrl::ListView _modList;
    blackbone::Process& _process;
    std::map<uint64_t, ModuleInfo> _moduleInfo;
};