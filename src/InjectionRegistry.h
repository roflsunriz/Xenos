#pragma once

#include <windows.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace blackbone { class Process; }

/// <summary>
/// One tracked injection. The numeric id is the user-visible handle ("#3").
/// </summary>
struct InjectionRecord
{
    uint32_t     id = 0;
    DWORD        pid = 0;
    uint64_t     processStart = 0;    // FILETIME of the target at injection time
    std::wstring imagePath;           // injected DLL/SYS
    std::wstring moduleName;          // image name in the target
    uint64_t     baseAddress = 0;     // remote module base
    uint32_t     imageSize = 0;
    int          method = 0;          // MapMode
    bool         manual = false;      // manually mapped
    uint32_t     mmapFlags = 0;
    std::wstring initRoutine;
    std::wstring initArgs;
    bool         unlink = false;
    bool         hijack = false;
    bool         erasePE = false;
    bool         krnHandle = false;
    uint64_t     injectedAt = 0;      // FILETIME
    int          state = 0;           // InjectionState
    uint32_t     delay = 0;
    uint32_t     period = 0;
};

enum class InjectionState
{
    Loaded = 0,
    Ejected = 1,
    Stale = 2,
};

struct NewInjection
{
    DWORD        pid = 0;
    std::wstring imagePath;
    std::wstring moduleName;
    uint64_t     baseAddress = 0;
    uint32_t     imageSize = 0;
    int          method = 0;
    bool         manual = false;
    uint32_t     mmapFlags = 0;
    std::wstring initRoutine;
    std::wstring initArgs;
    bool         unlink = false;
    bool         hijack = false;
    bool         erasePE = false;
    bool         krnHandle = false;
    uint32_t     delay = 0;
    uint32_t     period = 0;
};

enum class EjectStatus
{
    Ok,
    AlreadyGone,
    NotFound,
    StaleProcess,
    ModuleMismatch,
    Unsupported,
    Busy,       // DLL still has live threads/code; unloading would crash the target
    Failed,
};

const wchar_t* EjectStatusText( EjectStatus status );
const wchar_t* InjectionStateText( InjectionState state );

/// <summary>
/// Persistent list of injections performed by this tool.
/// Stored as UTF-16 INI in %APPDATA%\Xenos\injections.ini.
/// </summary>
class InjectionRegistry
{
public:
    static InjectionRegistry& Instance();

    void Load();
    void Save();

    uint32_t Add( const NewInjection& data );
    bool Find( uint32_t id, InjectionRecord& out ) const;
    std::vector<InjectionRecord> All() const;
    std::vector<InjectionRecord> ForPid( DWORD pid ) const;

    void SetState( uint32_t id, InjectionState state );
    void Remove( uint32_t id );

private:
    InjectionRegistry();

    void SaveUnlocked();
    uint64_t ProcessStartTime( DWORD pid ) const;

    mutable std::mutex _lock;
    std::vector<InjectionRecord> _records;
    uint32_t _nextId = 1;
    bool _loaded = false;
    std::wstring _path;
};

/// <summary>
/// true if the target process still exists (same start time) and the recorded
/// module base still contains a mapped PE image.
/// </summary>
bool IsInjectionLive( const InjectionRecord& record );

/// <summary>
/// Safely unload a module at a known base address.
/// Normal modules use FreeLibrary in the target; manual modules call
/// DllMain(DLL_PROCESS_DETACH) and release the mapped image.
/// Before freeing the image the target is checked for threads that were
/// started by the module (or are executing inside it). Freeing a DLL while
/// its code is still running is what makes the target crash. A payload can
/// export XenosUnload() to stop its threads; when that export is missing and
/// the module still has live threads, the eject is refused (Busy) instead of
/// unmapping the image. Pass force = true to bypass the check.
/// </summary>
EjectStatus UnloadModuleAt(
    blackbone::Process& process,
    uint64_t baseAddress,
    const std::wstring& moduleName,
    const std::wstring& imagePath,
    bool manual,
    uint32_t expectedSize,
    bool force,
    std::wstring& message );

/// <summary>
/// Safely unload a tracked injection.
/// Verifies PID + process start time + module base/name before unloading.
/// </summary>
EjectStatus EjectInjection( uint32_t id, bool force, std::wstring& message );

/// <summary>
/// Eject (if still loaded) and inject the same image with the same options.
/// The old handle is kept as history; the new injection receives a new handle.
/// </summary>
bool ReinjectInjection( uint32_t id, HWND owner, uint32_t& newId, std::wstring& message );
