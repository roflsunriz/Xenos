#pragma once

#include "Dialog.hpp"
#include "resource.h"
#include "ListView.hpp"
#include "InjectionRegistry.h"

#include <vector>

class DlgInjections : public Dialog
{
public:
    DlgInjections();
    ~DlgInjections();

private:
    void RefreshList();

    MSG_HANDLER( OnInit );
    MSG_HANDLER( OnEject );
    MSG_HANDLER( OnReinject );
    MSG_HANDLER( OnRefresh );
    MSG_HANDLER( OnClose );

private:
    ctrl::ListView _list;
    std::vector<uint32_t> _ids;
};
