Xenos
=====

Windows dll injector. Based on Blackbone library - https://github.com/DarthTon/Blackbone

## Features ##

- Supports x86 and x64 processes and modules
- Kernel-mode injection feature (driver required)
- Manual map of kernel drivers (driver required)
- Injection of pure managed images without proxy dll
- Windows 7 cross-session and cross-desktop injection
- Injection into native processes (those having only ntdll loaded)
- Calling custom initialization routine after injection
- Unlinking module after injection
- Injection using thread hijacking
- Injection of x64 images into WOW64 process
- Image manual mapping
- Injection profiles

Manual map features:
- Relocations, import, delayed import, bound import
- Hiding allocated image memory (driver required)
- Static TLS and TLS callbacks
- Security cookie
- Image manifests and SxS
- Make module visible to GetModuleHandle, GetProcAddress, etc.
- Support for exceptions in private memory under DEP
- C++/CLI images are supported (use 'Add loader reference' in this case)

Supported OS: Win7 - Win10 x64

## Fork additions: fast target selection ##

This fork keeps the injection engine intact and adds a headless process-picker
core plus a game-engine-aware GUI.

### Process selection types ###

The **Type** group in the GUI is split into:

| Type | Behaviour |
| --- | --- |
| **Existing** | Every running process (name, PID, engine tag). |
| **Games** | Only processes with a game-engine fingerprint. |
| **Recent** | Recently used targets that are currently running (MRU order). |
| **New** | Choose an executable and launch it (original behaviour). |
| **Manual launch** | Wait for a new process and attach (original behaviour). |

The last used Existing sub-mode is persisted and restored at startup. The most
recent target is auto-selected as soon as its process is running, so relaunching
Xenos and pressing Inject is usually enough.

### Type-to-filter ###

Click the process box and start typing. The list is filtered live and sorted by
match quality:

- `game` — substring / prefix / fuzzy subsequence of the image name
- `mygame` — also matches the full path
- `@unity`, `@unreal`, `@godot`, `@electron` — engine tags
- `pid:1234` — exact PID
- `-@electron` — exclude matches (space-separated tokens are ANDed)
- `Enter` selects the first match, `Esc` clears the filter, `F5` refreshes,
  `View > Clear engine cache` re-runs fingerprinting.

### Engine fingerprints ###

Built-in detection uses loaded modules, sidecar files/directories next to the
image and executable naming conventions:

- Unity (IL2CPP / Mono), Unreal Engine 4/5, Unreal Engine 3
- Godot (`.pck`, embedded PCK), GameMaker (`data.win`)
- RPG Maker (RGSS, MV/MZ), Ren'Py
- Source, Source 2, CryEngine
- Runtimes: Electron, NW.js, Java, .NET

Extra rules can be added in `engines.ini` (next to the executable or in
`%APPDATA%\Xenos\`); see `engines.ini.example`.

### Headless CLI (`XenosCli`) ###

The picker core (`EngineDetect`, `ProcessCatalog`, `AppSettings`) and the
injection engine (`InjectionCore`) have no GUI dependency and are exposed
through a console front-end:

```text
XenosCli64 list   [--mode all|games|recent] [--filter TEXT] [--json]
XenosCli64 pick   [--mode ...] [--filter ...] [--no-recent] [--json]
XenosCli64 detect <pid|name>
XenosCli64 remember <pid|name>
XenosCli64 forget
XenosCli64 recent
XenosCli64 engines
XenosCli64 injections [--pid N] [--json]
XenosCli64 eject <handle> [--force] [--json]
XenosCli64 reinject <handle> [--json]
XenosCli64 inject --dll <path> [--dll <path> ...] [target] [options]
XenosCli64 gui [--load profile.xpr64]
```

Examples:

```text
XenosCli64 list --mode games
XenosCli64 list --mode all --filter "unreal -@electron"
XenosCli64 pick --filter mygame --json
XenosCli64 remember mygame
```

`pick` prints `pid<TAB>name<TAB>path<TAB>engine` and exits with code 1 when
nothing matches. `gui` launches the GUI (elevation prompt included) and passes
its arguments through, so it can be used as a drop-in launcher.

#### Injection ####

`inject` drives the same `InjectionCore` as the GUI:

```text
# picker result (--mode/--filter + recent target)
XenosCli64 inject --dll payload.dll --mode games --filter mygame --manual

# explicit target
XenosCli64 inject --dll payload.dll --pid 1234 --method normal
XenosCli64 inject --dll payload.dll --name Game.exe --unlink

# launch or wait for a process
XenosCli64 inject --dll payload.dll --new "C:\Games\MyGame\MyGame.exe"
XenosCli64 inject --dll payload.dll --wait MyGame.exe --timeout 60

# manual map with an init routine, multiple images
XenosCli64 inject --dll a.dll --dll b.dll --pid 1234 --method manual \
  --init Initialize --arg "config.json"
```

Target selection (default: picker result):

| Option | Meaning |
| --- | --- |
| `--pid <n>` | Attach to a running PID. |
| `--name <exe>` | First running process with that image name. |
| `--new <exe>` | Create the process, inject, resume it. |
| `--wait <exe>` | Wait for a **new** instance (with `--timeout`). |

Injection options:

| Option | Meaning |
| --- | --- |
| `--method normal\|manual\|kernel-thread\|kernel-apc\|kernel-mmap\|driver` | Injection type (default normal). |
| `--init <export>`, `--arg <text>` | Call an init routine after mapping. |
| `--unlink`, `--hijack`, `--erase-pe`, `--krn-handle` | Native injection switches. |
| `--ldr-ref`, `--manual-imports`, `--wipe-header`, `--hide-vad`, `--no-tls`, `--no-exceptions`, `--mmap-flags <hex>` | Manual map flags. |
| `--delay <ms>`, `--period <ms>` | Pre-injection delay / delay between images. |
| `--dry-run` | Resolve the target, validate the images, do nothing. |
| `--json` | JSON result on stdout (progress/diagnostics go to stderr). |

Exit codes: `0` success, `1` target not found, `2` usage/validation error,
`3` injection failure. Kernel methods, `--krn-handle` and `--hide-vad` require
an elevated prompt; normal and manual mapping work at the caller's integrity
level.

#### Injection handles (safe eject / re-inject) ####

Every successful injection is assigned a numeric handle and recorded in
`%APPDATA%\Xenos\injections.ini`:

```text
> XenosCli64 inject --dll payload.dll --mode games --filter mygame
injected 1 image(s) into MyGame.exe (4242) using manual
handles: #7

> XenosCli64 injections
HANDLE     PID  MODULE              BASE          METHOD     STATE     IMAGE
#7        4242  payload.dll         0x7ffc2b790000  manual    loaded    C:\...\payload.dll

> XenosCli64 eject 7
handle #7 ejected

> XenosCli64 reinject 7
re-injected 'payload.dll' into PID 4242 (handle #8)
```

Safety checks before ejecting:

- PID **and** process creation time must match (PID reuse is detected).
- The module base must still contain a PE image with the recorded size.
- The loader name must match before `FreeLibrary`.
- Threads started by the module (and target threads currently executing inside
  it) are detected. Freeing an image under a running thread is the usual cause
  of an `0xC0000005` execute fault in the unloaded module
  (`FSD-Win64-Shipping` is one such target).
- Stale handles are marked `stale`; `--force` bypasses the identity checks.

Normal modules are unloaded with `FreeLibrary` inside the target.
Manually mapped modules get `DllMain(DLL_PROCESS_DETACH)` and are then released
with `VirtualFreeEx`.

#### Cooperative unload (`XenosUnload`) ####

Calling `DllMain(DLL_PROCESS_DETACH)` from outside the loader is not safe while
the DLL still has worker threads: the CRT is torn down under them. DLLs that
start threads should export a no-argument routine named `XenosUnload`:

```cpp
extern "C" __declspec(dllexport) void XenosUnload()
{
    g_stop = true;                       // signal worker threads
    WaitForSingleObject(g_worker, 5000); // and wait for them to exit
    CloseHandle(g_worker);
}
```

Before ejecting, Xenos calls this export, waits for the module's threads to
exit, and only then unloads it. If a DLL has live threads but no `XenosUnload`
export, eject reports `Busy` and leaves the image mapped instead of crashing
the target. `--force` skips the check and performs a plain unload.

Re-inject first ejects the old handle and any other tracked instance of the
same image in that process, then injects with the original method/options.
The old handle remains in the history; the new injection gets a new handle.

The GUI exposes the same list under **Tools > Tracked injections...** with
**Eject** and **Re-inject** buttons. The main window also has an **Eject**
button that safely unloads every tracked DLL of the selected process (with a
confirmation prompt). The Modules dialog uses the same safe unload path. The
status bar shows the handle after a successful injection.

Both the CLI and the GUI are front-ends to the same core; the GUI is a thin
shell around the picker and `InjectionCore`.

### Building ###

The upstream projects target v142. With newer toolsets (v143+) the
`Directory.Build.props` shim relaxes two C++17 conformance defaults and adds a
missing standard-header include; nothing else changes.

Requirements: Visual Studio C++ toolset, Windows 10 SDK, and the **C++ ATL**
component (BlackBone uses `CComPtr`). Build with:

```text
msbuild Xenos.sln /p:Configuration=Release /p:Platform=x64
```

Outputs: `build\x64\Release\Xenos64.exe` and `XenosCli64.exe`.

## License ##
Xenos is licensed under the MIT License. Dependencies are under their respective licenses.

[![Build status](https://ci.appveyor.com/api/projects/status/eu6lpbla89gjgy5m?svg=true)](https://ci.appveyor.com/project/DarthTon/xenos)