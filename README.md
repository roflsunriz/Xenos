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
`3` injection failure. Kernel methods require an elevated prompt; normal and
manual mapping work at the caller's integrity level.

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