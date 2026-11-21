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

The picker core (`EngineDetect`, `ProcessCatalog`, `AppSettings`) has no GUI
dependency and is exposed through a console front-end:

```text
XenosCli64 list   [--mode all|games|recent] [--filter TEXT] [--json]
XenosCli64 pick   [--mode ...] [--filter ...] [--no-recent] [--json]
XenosCli64 detect <pid|name>
XenosCli64 remember <pid|name>
XenosCli64 forget
XenosCli64 recent
XenosCli64 engines
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

Injection itself is still performed by the GUI; the CLI is the authoritative
implementation of discovery, fingerprinting, filtering and target history.

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