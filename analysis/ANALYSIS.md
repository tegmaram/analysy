# Static Analysis Report — `linou free.exe`

**Subject:** "Linou Free" — unsigned Fortnite cheat loader with an embedded
WHQL-signed kernel driver and an embedded in-process cheat DLL.
**Report date:** 2026-11-07
**Analyst:** Arena agent (automated static analysis, no execution)
**Classification:** Potentially Unwanted Program / game cheat with
kernel-level anti-cheat bypass (rootkit-capable by design). **Not** observed to
contain credential theft, ransomware or persistence features.
**Handling:** static analysis only — the sample was never executed and none of
its URLs were requested.

---

## 1. Executive summary

`linou free.exe` is a 64-bit console loader that turns a Windows machine into a
host for a Fortnite "internal" cheat. It performs five distinct jobs:

1. **Elevates** itself to Administrator (`ShellExecuteExW` + `"runas"`,
   `requireAdministrator` manifest) and refuses to continue without it.
2. **Silences** the user's capture/overlay/GPU tooling — 42 fire-and-forget
   `system("taskkill /f /im … /t")` commands covering OBS-adjacent helpers,
   Overwolf (16 processes), Medal, RTSS, MSI Afterburner, NVIDIA App/container,
   AMD Radeon Software, Xbox Game Bar/DVR and generic ffmpeg/crashpad helpers.
3. **Installs a kernel driver.** The driver is embedded in the loader's
   `.rdata`, is written to `%TEMP%`, registered as a service
   (`SYSTEM\CurrentControlSet\Services\<name>` with `ImagePath` = `\??\…` and
   `Type`) and started through `ntdll` (`NtLoadDriver`). The driver is **not**
   authored by the cheat's developer: it is a WHQL-signed third-party KMDF
   driver signed under *Microsoft Windows Hardware Compatibility Publisher* for
   vendor *PAutel Intelligent Technology Corp., Ltd* (signature timestamps
   2025-11-10). Its import surface (`MmGetVirtualForPhysical`,
   `MmMapLockedPagesSpecifyCache`, `KeStackAttachProcess`,
   `ZwProtectVirtualMemory`, `ZwAllocateVirtualMemory`) is the classic profile
   of a **BYOVD** memory-access driver used to read/patch the protected game
   process from Ring 0.
4. **Rewrites Easy Anti-Cheat's splash image.** It downloads
   `https://files.catbox.moe/pvtjo9.png` (User-Agent `FortniteInjector/1.0`)
   into `%TEMP%\fortnite_splash_download.png.tmp` and then
   `MoveFileExW`-replaces
   `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\SplashScreen.png`.
5. **Injects the cheat.** An embedded carrier DLL (whose `.data` section is a
   byte-for-byte copy of the real cheat DLL) is injected into the game; the
   cheat DLL then opens a console, reads hotkeys with `GetAsyncKeyState`, dumps
   the game's `UObject` table and patches a large set of movement abilities.

The only social/branding strings are the console title
`linou free internal but cuter`, a message box titled `linou free internal`, and
the invite `https://discord.gg/linouservices` together with the taunt
`you just got kicked cutie!! dont forget that … is the cutest discord server of
all time`.

**Answer to "is it malware?":** It is not benign. It is a cheat that requires
kernel code and deliberately disables the anti-cheat and the user's recording
software; it is distributed anonymously, is unsigned, and can be silently
updated (remote-controlled splash asset). It is *malicious-equivalent* in
behaviour even though this build shows no stealer/exfiltration logic. Treat any
copy as untrusted.

---

## 2. Sample metadata

| Item | Value |
|---|---|
| File name | `linou free.exe` |
| Size | 681,984 bytes (0xA6800) |
| MD5 | `d7e9be44fd922161220380a97e88a837` |
| SHA-1 | `6bf3169071b31f7d722cb22bd3cd443833b2c652` |
| SHA-256 | `7d2c55b9d95203e966f70e5de8a04aa48daccd7a1b5ff9d0b17f5a9a06bc085a` |
| Format | PE32+ (AMD64), console subsystem, GUI-less |
| Compiler | MSVC 19.x (linker 14.44), C++ (MSVCP140/VCRUNTIME140), Rich header present |
| Build time | 2026-11-05 21:06:53 UTC (header), 21:06:48 UTC (carrier DLL), 21:00:42 UTC (cheat DLL) |
| Signed? | **No** — `IMAGE_DIRECTORY_ENTRY_SECURITY` = 0 |
| Manifest | `requestedExecutionLevel level='requireAdministrator'` |
| SizeOfImage | 0xAB000 |
| PDB | `C:\Users\admin\Desktop\all src latest 04.11.26\all src latest\no sideload injector\New injector\Newinjector.pdb` |
| Overlay | none (everything is packed into `.rdata`) |

### Sections

| Name | VA | VirtSize | RawSize | Entropy | Note |
|---|---|---|---|---|---|
| `.text` | 0x1000 | 0xD61C | 0xD800 | 6.42 | loader logic (~55 KB) |
| `.rdata` | 0xF000 | 0x97A2C | 0x97C00 | 6.52 | strings **+ all three embedded PEs** |
| `.data` | 0xA7000 | 0x9A8 | 0x200 | 2.23 | globals |
| `.pdata` | 0xA8000 | 0x99C | 0xA00 | 4.73 | 205 unwind entries (function map) |
| `.rsrc` | 0xA9000 | 0x1E8 | 0x200 | 4.76 | manifest only |
| `.reloc` | 0xAA000 | 0x7C | 0x200 | 1.56 | — |

### Imports (grouped by purpose)

* **Network:** `WININET` — `InternetOpenW`, `InternetOpenUrlA`,
  `InternetReadFile`, `InternetCloseHandle`.
* **Memory manipulation:** `OpenProcess`, `ReadProcessMemory`,
  `WriteProcessMemory`, `DeviceIoControl`, `VirtualAlloc`/`VirtualProtect`
  (in payload).
* **Process/thread enumeration:** `CreateToolhelp32Snapshot`,
  `Process32FirstW/NextW`, `Thread32First/Next`.
* **Registry / service:** `ADVAPI32` — `RegCreateKeyW`, `RegSetKeyValueW`,
  `RegOpenKeyExW`, `RegQueryValueExW`, `RegEnumKeyExW`, `RegDeleteTreeW`,
  `OpenProcessToken`, `GetTokenInformation`.
* **Shell / elevation:** `ShellExecuteExW`, `SHCreateDirectoryExW`.
* **Files:** `CreateFileW`, `WriteFile`, `MoveFileExW`, `DeleteFileW`,
  `GetTempPathW`, `SetFileAttributesW`, `FindFirstFileW`.
* **UI/input:** `EnumWindows`, `EnumChildWindows`, `GetClassNameW`,
  `PostMessageW`, `SendMessageTimeoutW`, `SendInput`, `SetForegroundWindow`,
  `MessageBoxA`.
* **Command execution:** `system` (CRT) — used for the `taskkill` burst.

---

## 3. Embedded components

The loader carries three complete PE files inside its `.rdata`, none of which is
in a PE resource — they are raw blobs, found by scanning for `MZ`/`PE` at
aligned offsets:

| # | Offset in sample | Size | SHA-256 | Type | Build time |
|---|---|---|---|---|---|
| 1 | `0x114B0` | 553,472 B | `ee226cabc2216b1eba339bda1390a5916616591bfdb6ad72b149710e8e00ae0e` | carrier/loader DLL | 2026-11-05 21:06:48Z |
| 2 | `0x126B0` (inside #1) | 548,352 B | `0b28f1d6a23044d5d3df258926004f9a5c1fd12c4af0517c94b7b78de36b3253` | cheat DLL ("fortnite internal") | 2026-11-05 21:00:42Z |
| 3 | `0x986B0` | 40,080 B (30,208 B image + 9,872 B signature) | `01da64b789dcffbdd2f6aa44b2988ee92c707e1815124faeb6382389d1220927` | kernel driver (KMDF) | 2025-11-09 16:48:44Z |

### 3.1 Carrier DLL (`0x114B0`)

* PE32+ DLL, `SizeOfImage` 0x8A000, entry 0x18B0, only **0x8E4 bytes of code**.
* Imports: `TlsAlloc`, `TlsSetValue`, `VirtualAlloc`, `VirtualProtect`,
  `GetModuleHandleA`, `GetProcAddress`, `LoadLibraryA` — i.e. no file, network,
  registry or console API at all.
* Its `.data` section (0x85E00 bytes) is **byte-for-byte identical** to the
  cheat DLL below.
* **Interpretation:** a minimal in-memory loader stub. The user-mode injector
  pushes this small, unremarkable DLL into the game; it allocates memory,
  resolves imports and maps the real (large) cheat DLL. The exact stub logic was
  not fully traced (it is only ~570 instructions), but the structure is
  unambiguous.

### 3.2 Cheat DLL ("fortnite internal", `0x126B0`)

* PE32+ DLL, `SizeOfImage` 0x191000, `.fptable` section (common in
  anti-tamper/obfuscated builds), manifest `asInvoker`, entry 0x3C7E8.
* Imports: `KERNEL32` (`AllocConsole`, `FreeConsole`, `SetConsoleMode`,
  `GetConsoleMode`, `GetAsyncKeyState`, `ReadProcessMemory`, `VirtualProtect`,
  `VirtualAlloc`, `CreateThread`, `Sleep`, `FreeLibraryAndExitThread`) and
  `USER32`.
* PDB: `C:\Users\admin\Desktop\all src latest 04.11.26\all src latest\fortnite internal\x64\Release\dll.pdb`.
* Recovered functionality strings:
  * `[gobjects] wrote valid=%u empty=%u`, `[gobjects] progress %u/%u`,
    `[gobjects] dump crashed, stopped` → **UObject/SDK dumper** (enumerates the
    game's reflection data; the foundation of every internal cheat's ESP/aimbot).
  * 43 Fortnite movement/ability asset paths, e.g.
    `/Script/SlidingRuntime.FortMovementMode_Sliding`,
    `/Script/WallJumpCodeRuntime.FortMovementMode_ExtWallJump`,
    `/Script/FlyingCodeRuntime.FortMovementMode_ExtLogicFlying`,
    `/Script/ZiplineCodeRuntime.FortMovementMode_ExtLogicZipline`,
    `/Script/NitroGameplayRuntime.FortMovementMode_ExtLogicNitroState`,
    `/ClamberingContent/Gameplay/FMM_ExtClamber.FMM_ExtClamber_C`,
    `/Script/FallDamageOverrideCode.FortMovementMode_ExtFallDamageOverride` …
    → **movement-ability manipulation** (slide/wall-jump/fly/no-fall-damage
    style features).
  * `you just got kicked cutie!! dont forget that https://discord.gg/linouservices is the cutest discord server of all time` → shown when the user is removed ("kicked") from the product.
  * `CONOUT$` → cheat console window.

### 3.3 Kernel driver (`0x986B0`)

* PE32+ KMDF driver (`.text`, `.rdata`, `.data`, `.pdata`, `INIT`, `.reloc`),
  subsystem native (1), `SizeOfImage` 0x8000, entry 0x5DC0 (`INIT`), 2025-11-09.
* Imports — `ntoskrnl.exe`:
  `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `MmBuildMdlForNonPagedPool`,
  `MmProtectMdlSystemAddress`, `MmMapLockedPagesSpecifyCache`,
  `MmAllocatePagesForMdlEx`, `IoAllocateMdl`, `IoGetCurrentProcess`,
  `ObReferenceObjectByHandle`, `ObfDereferenceObject`, `ZwOpenSection`,
  `ZwMapViewOfSection`, `ZwUnmapViewOfSection`, `ZwCreateFile`, `ZwDeleteFile`,
  `ZwAllocateVirtualMemory`, `ZwProtectVirtualMemory`, `MmIsAddressValid`,
  `MmGetSystemRoutineAddress`, `KeStackAttachProcess`, `KeUnstackDetachProcess`,
  `KeDelayExecutionThread`, `KeGetCurrentIrql`, `PsLookupProcessByProcessId`,
  `PsGetProcessPeb`, `PsGetProcessWow64Process`, `RtlInitUnicodeString`,
  `RtlCompareMemory`, `RtlCompareUnicodeString`, `RtlCopyUnicodeString`,
  `IofCompleteRequest`, `IoCreateDevice`, `IoCreateSymbolicLink`,
  `IoDeleteDevice`, `IoDeleteSymbolicLink`, `IoFileObjectType`, `DbgPrintEx`;
  plus `WDFLDR.SYS` (`WdfVersionBind`, `WdfVersionBindClass`, …).
  Wide strings: `MmGetVirtualForPhysical`, `KmdfLibrary`, `Ntdll.dll`,
  `User32.dll`.
* **Signature (`WIN_CERTIFICATE`, revision 0x0200, type 0x0002, PKCS#7):**
  * Leaf subject: `C=US, ST=Washington, L=Redmond, O=Microsoft Corporation,
    CN=Microsoft Windows Hardware Compatibility Publisher`
    (validity 2025-02-20 → 2026-02-18).
  * Chain: `Microsoft Windows Third Party Component CA 2012` →
    `Microsoft Root Certificate Authority 2010`.
  * RFC-3161 countersignature: `Microsoft Time-Stamp Service`,
    `Microsoft Time-Stamp PCA 2010`, HSM `nShield TSS ESN:3605-05E0-D947`,
    timestamp `2025-11-10T08:00:50Z`.
  * Nested/vendor signature carries the original organization
    **`PAutel Intelligent Technology Corp., Ltd`** (BMPString inside the blob).
* **Interpretation:** a real, WHQL-accepted third-party driver — not something
  the cheat author compiled. It exposes physical/process memory primitives and
  is shipped as a **Bring Your Own Vulnerable Driver** kernel bypass. Because it
  is timestamped, its *expired* certificate does not prevent loading on current
  Windows builds; only the driver blocklist / HVCI would.

---

## 4. Execution chain (reconstructed statically)

The loader's strings are XOR-obfuscated (see §7), so the console messages and
registry/service names below were recovered by emulating the de-obfuscation
sequences with Unicorn and logging every imported-API argument
(`tools/emulate_strings.py`).

```
main()
 ├─ SetConsoleTitleW("linou free internal but cuter")
 ├─ SetConsoleCP/SetConsoleOutputCP(65001)  // UTF-8
 ├─ setlocale("en_US.UTF-8")
 ├─ OpenProcessToken + GetTokenInformation(TokenElevation)
 │    └─ not elevated → ShellExecuteExW(lpVerb="runas", own path)
 │         └─ failure → "[!] Failed: administrator rights required."
 │                      "\nPress enter to close..."
 ├─ resolve ntdll entry points (NtLoadDriver / NtUnloadDriver family)
 │    └─ failure → "[!] Failed: ntdll bindings."
 ├─ for each of 42 processes: system("taskkill /f /im <name> /t >nul 2>&1")
 ├─ driver install
 │    ├─ GetTempPathW + name  → CreateFileW / WriteFile (embedded .sys)
 │    │     └─ "[!] Failed: Driver creation error. (GetTempPath )"
 │    ├─ RegCreateKeyW / RegSetKeyValueW
 │    │     └─ SYSTEM\CurrentControlSet\Services\<svc>
 │    │        ImagePath = "\??\<temp>\<name>"   Type = 1 (kernel driver)
 │    ├─ enumerate SYSTEM\CurrentControlSet\Services (RegEnumKeyExW +
 │    │  RegQueryValueExW("ImagePath") + RegDeleteTreeW) — long full-service
 │    │  sweep (observed ~300k emulated API calls before completion)
 │    ├─ NtLoadDriver
 │    │     └─ "[!] Failed: Driver load error."
 │    └─ DeviceIoControl(handle, …)  → kernel memory primitives
 │          └─ "[!] Recovery channel unavailable." / "DeviceIoControl … error …"
 ├─ Easy Anti-Cheat splash replacement  (see §4.1)
 ├─ target discovery
 │    ├─ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) + Process32FirstW/NextW
 │    ├─ EnumWindows / EnumChildWindows / GetClassNameW  (game window)
 │    └─ OpenProcess → ReadProcessMemory / WriteProcessMemory  (injection)
 └─ MessageBoxA(NULL, …, "linou free internal", MB_ICONINFORMATION)
```

### 4.1 The splash-screen routine (`sub_140001270`, byte-level verified)

1. `path = "C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat" + "\SplashScreen.png"`
2. `GetTempPathW` → `%TEMP%\fortnite_splash_download.png.tmp`
3. `InternetOpenW(L"FortniteInjector/1.0", INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0)`
4. `InternetOpenUrlA(h, "https://files.catbox.moe/pvtjo9.png", 0, 0, 0x84800000, 0)`
5. `CreateFileW(tmp, GENERIC_WRITE, 0, 0, CREATE_ALWAYS(2), FILE_ATTRIBUTE_NORMAL(0x80), 0)`
6. loop `InternetReadFile(…0x1000…)` + `WriteFile` → close both handles
7. `GetFileAttributesW(target)` / `SHCreateDirectoryExW` (create the EAC folder
   if missing) / `SetFileAttributesW` (clear read-only)
8. `MoveFileExW(tmp, target, MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`
9. `"[*] Making the cat meow..."` → `"[+] Cat meowed successfully!"`
   (errors: `InternetOpen failed`, `InternetOpenUrl failed`, `CreateFile
   failed`, `Download returned no data`, `MoveFileEx failed`)

The PNG is *not* a picture in the sense of "screenshot bait": by replacing the
anti-cheat's own splash asset the cheat re-brands the moment Fortnite boots and
writes into the anti-cheat's installation directory (which is also a common
trick to interfere with the integrity checks of that folder).

### 4.2 Process kill list (42 `taskkill` invocations)

```
Overwolf.exe, OverwolfLauncher.exe, OverwolfBrowser.exe, OverwolfHelper.exe,
OverwolfHelper64.exe, ow-obs.exe, ow-overlay.exe, OverwolfUpdater.exe,
OverwolfCrashHandler.exe, OverwolfBenchmarking.exe, OWCleanup.exe,
OWUninstaller.exe, OWUninstallMenu.exe, OverwolfLauncherProxy.exe,
gameoverlayui.exe, GamePanel.exe, bcastdvr.exe, GameBarFTServer.exe,
RTSS.exe, MSIAfterburner.exe, Medal.exe, MedalEncoder.exe, MServer.exe,
squirrel.exe, elevate.exe, crashpad_handler.exe, inject-helper32.exe,
inject-helper64.exe, ffmpeg.exe, ffprobe.exe, mp4info.exe,
ThumbnailGenerator.exe, ICYMICreator.exe,
"NVIDIA App.exe", "NVIDIA Overlay.exe", nvsphelper64.exe, nvsphelper.exe,
nvcontainer.exe, RadeonSoftware.exe, AMDRSServ.exe, amdow.exe, AMDRSSrcExt.exe
```

Everything that could record, overlay, capture or profile the render pipeline is
terminated — this is anti-forensics aimed at clips/screenshots and at
performance overlays that would expose the cheat.

---

## 5. Capability matrix

| Capability | Present | Evidence |
|---|---|---|
| Auto-elevation to Administrator | **Yes** | manifest + `ShellExecuteExW("runas")` + token check |
| Command execution (`system`) | **Yes** | 42 × `taskkill /f /im …` |
| Kernel driver drop + service creation + load | **Yes** | embedded signed KMDF driver, `SYSTEM\…\Services`, `ImagePath`=`\??\…`, `Type`, `NtLoadDriver` |
| Kernel memory read/write primitives (BYOVD) | **Yes** | driver imports `MmGetVirtualForPhysical`, `KeStackAttachProcess`, `ZwProtectVirtualMemory`, MDL mapping |
| Remote file download | **Yes** | `files.catbox.moe/pvtjo9.png`, UA `FortniteInjector/1.0` |
| Write into anti-cheat directory | **Yes** | `…\EasyAntiCheat\SplashScreen.png` replacement |
| Process injection (manual map) | **Yes** | carrier DLL + `OpenProcess`/`WriteProcessMemory`; thread creation is resolved dynamically from `ntdll` (not in the IAT), so the exact API is only visible at run time |
| Game memory read/write | **Yes** | `Read/WriteProcessMemory`, `DeviceIoControl`, `[gobjects]` dumper |
| Input synthesis (hotkeys) | **Yes** | `GetAsyncKeyState` (payload), `SendInput` (loader) |
| Anti-analysis string obfuscation | **Yes** | all loader strings XOR-encrypted 16-byte blocks |
| Anti-debug / VM checks | **Not found** | `IsDebuggerPresent` is only the standard CRT stub import |
| Persistence (Run keys, scheduled task, service of itself) | **Not found** | only the temporary driver service, deleted after use |
| Credential / browser / wallet / token theft | **Not found** | no paths, no `leveldb`, `Login Data`, wallet or webhook strings |
| Ransomware / destructive behaviour | **Not found** | no crypto file APIs, no shadow-copy/WMI deletion |
| C2 beaconing / TLS to attacker infrastructure | **Not found** | only one WinINet request (the PNG) |
| Exfiltration | **Not found** | no archive/upload code |

---

## 6. Anti-analysis and evasion

* **No signature** on the loader; the *only* signed component is the borrowed
  WHQL driver — a deliberate split so that "it has a valid Microsoft
  signature" can be claimed by the distributor.
* **Payloads hidden in `.rdata`** as raw PE blobs, not resources, so that
  resource extractors return only a manifest.
* **String encryption:** every user-facing and API-related string in the loader
  is materialised on the stack as 16-byte XOR blocks (`xorps` with a 16-byte
  key stored in the same frame). `strings` on the sample shows only the
  plaintext strings that live inside the embedded modules.
* **Overlay/capture process killing** (§4.2).
* **Anti-cheat directory tampering** (§4.1).
* Console title and message box ("linou free internal") make the tool look
  like a game utility to a casual user.

---

## 7. How the obfuscated strings were recovered

`tools/emulate_strings.py` maps the loader's image into Unicorn, patches its
IAT so every import lands on a private stub, and then executes selected
functions with `RCX/RDX/R8/R9 = 0` and a sentinel return address. Each time a
stub is hit, the argument registers are read and both ASCII and UTF-16 strings
are decoded from emulated memory. Real implementations are provided for
`memcpy`, `memmove`, `memset`, `memcmp` and `malloc` so `std::string`
construction continues to work, and `GetTempPathW`/`GetModuleFileNameW` return
marked fake paths (`C:\Users\marker\…`) so any fabricated output is
recognisable in the results.

Recovered verbatim (selection):

```
linou free internal but cuter            (console title)
runas                                    (ShellExecuteEx verb)
[!] Failed: administrator rights required.
[!] Failed: ntdll bindings.
[!] Failed: Driver creation error. (GetTempPath )
[!] Failed: Driver load error.
SYSTEM\CurrentControlSet\Services        (RegOpenKeyExW)
ImagePath / Type                         (RegSetKeyValueW values for the service)
"\??\"                                   (driver ImagePath prefix)
[!] Recovery channel unavailable.        (driver/DeviceIoControl wrapper)
DeviceIoControl … error …
```

This also proves the *order* of the driver steps (create file → service key →
enumerate services → `NtLoadDriver`) and that the service names/keys are
constructed at runtime rather than stored in the file.

---

## 8. Indicators of compromise

Full list in [`IOCS.md`](IOCS.md). Highlights:

| Type | Value |
|---|---|
| SHA-256 | `7d2c55b9d95203e966f70e5de8a04aa48daccd7a1b5ff9d0b17f5a9a06bc085a` |
| SHA-256 (carrier DLL) | `ee226cabc2216b1eba339bda1390a5916616591bfdb6ad72b149710e8e00ae0e` |
| SHA-256 (cheat DLL) | `0b28f1d6a23044d5d3df258926004f9a5c1fd12c4af0517c94b7b78de36b3253` |
| SHA-256 (kernel driver) | `01da64b789dcffbdd2f6aa44b2988ee92c707e1815124faeb6382389d1220927` |
| URL | `https://files.catbox.moe/pvtjo9.png` |
| User-Agent | `FortniteInjector/1.0` |
| Discord | `https://discord.gg/linouservices` |
| File artefacts | `%TEMP%\fortnite_splash_download.png.tmp`, `%TEMP%\<random>.sys` (embedded driver), `…\EasyAntiCheat\SplashScreen.png` (replaced) |
| Registry | `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` with `ImagePath` = `\??\…`, `Type` = 1 |
| PDB paths | `…\no sideload injector\New injector\Newinjector.pdb`, `…\fortnite internal\x64\Release\dll.pdb` |
| Signer | Microsoft Windows Hardware Compatibility Publisher / vendor `PAutel Intelligent Technology Corp., Ltd`, timestamp 2025-11-10 |

Host-based hunting:

* a process holding a handle to `FortniteClient-Win64-Shipping.exe` that has
  **no** digital signature and a console window titled `linou free internal but
  cuter`;
* burst of `taskkill.exe` children spawned from a single parent within a second
  (40+ distinct image names);
* a `\Registry\Machine\System\CurrentControlSet\Services\…` key created where
  `ImagePath` points at `\??\C:\Users\<user>\AppData\Local\Temp\…` with
  `Type` = 1, shortly followed by `NtLoadDriver`;
* write/rename events on `…\EasyAntiCheat\SplashScreen.png` and a `WinINet`
  connection to `files.catbox.moe`;
* WHQL-signed driver whose file lives in `%TEMP%` (never legitimate).

Network controls: block `files.catbox.moe` outright (it is a general anonymous
file host abused by this and many other cheats/malware).

## 9. Detection rules

* [`yara/linou_free.yar`](yara/linou_free.yar) — three rules: loader, carrier +
  cheat DLL, and the embedded driver.
* Windows Defender / EDR: enable the Microsoft vulnerable-driver blocklist and
  HVCI; alert on any service created with an `ImagePath` under `%TEMP%`.
* Game side: Easy Anti-Cheat terminates the session on detection; note that
  running this sample is a **ban-worthy ToS violation** (and a legal risk).

## 10. Verdict and confidence

| Statement | Confidence |
|---|---|
| It is a Fortnite cheat loader/injector | **High** — strings, PDBs, asset paths, targeting logic |
| It loads a kernel driver as a service to obtain kernel memory access | **High** — imports, service-key writes, `\??\` path, `NtLoadDriver` |
| The driver is a third-party WHQL-signed binary (BYOVD pattern) | **High** — full PKCS#7 parsed, vendor string present |
| It disables overlay/capture software and rewrites an EAC asset | **High** — 42 `taskkill` strings, download + `MoveFileExW` into EAC dir |
| It steals credentials / persists / spreads | **Not observed** — but not provable by static analysis of one build |
| The remote PNG is harmless | **Unknown** — never fetched, by design; content can change |

## 11. Limitations / next steps

1. **Dynamic analysis** in an isolated VM (snapshot, host-only network, INetSim)
   would confirm: service name chosen at runtime, actual `DeviceIoControl` IOCTL
   codes, whether the driver stays loaded, and the injection technique
   (`QueueUserAPC`/`CreateRemoteThread`/manual map).
2. The cheat DLL (548 KB, `.fptable` section) was reviewed at string/section
   level only; a full disassembly is a separate project.
3. The driver was not disassembled instruction-by-instruction; its IOCTL surface
   should be compared against public LOLDrivers/blocklist entries.
4. If the PNG were fetched through a proxy (never directly), its content could be
   analysed to see whether the distributor uses the "splash" channel to deliver
   a second stage.

## 12. References

* ESET — *Bring Your Own Vulnerable Driver* research (BYOVD in game cheats and
  APTs): <https://www.eset.com/us/about/newsroom/research/esets-research-into-bring-your-own-vulnerable-driver-details-attacks-on-drivers-in-windows-core/>
* Microsoft — *Vulnerable driver blocklist* / HVCI guidance (Defender
  Application Control).
* MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation), T1553.006
  (Subvert Trust Controls: Code Signing Policy Modification), T1055 (Process
  Injection), T1562.001 (Impair Defenses: Disable or Modify Tools),
  T1014 (Rootkit), T1105 (Ingress Tool Transfer).
