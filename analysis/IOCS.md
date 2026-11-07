# Indicators of Compromise — "Linou Free" Fortnite cheat loader

> **Handling note:** every network indicator below is *evidence*, not a
> resource. **Do not request these URLs.** Blocking them is fine; fetching them
> is not (it alerts the distributor and may serve different content).
>
> Analysis date: 2026-11-07 · static analysis only, sample never executed.

## 1. Files / hashes

| SHA-256 | MD5 | Description | Size |
|---|---|---|---|
| `7d2c55b9d95203e966f70e5de8a04aa48daccd7a1b5ff9d0b17f5a9a06bc085a` | `d7e9be44fd922161220380a97e88a837` | `linou free.exe` — unsigned loader | 681,984 B |
| `ee226cabc2216b1eba339bda1390a5916616591bfdb6ad72b149710e8e00ae0e` | — | carrier/loader DLL (embedded @ `0x114B0`) | 553,472 B |
| `0b28f1d6a23044d5d3df258926004f9a5c1fd12c4af0517c94b7b78de36b3253` | — | cheat DLL "fortnite internal" (embedded @ `0x126B0`) | 548,352 B |
| `01da64b789dcffbdd2f6aa44b2988ee92c707e1815124faeb6382389d1220927` | — | WHQL-signed KMDF driver (embedded @ `0x986B0`) | 40,080 B |

SHA-1 of the loader: `6bf3169071b31f7d722cb22bd3cd443833b2c652`

## 2. Network

| Indicator | Context |
|---|---|
| `https://files.catbox.moe/pvtjo9.png` | downloaded by the loader and written over EAC's `SplashScreen.png` |
| `files.catbox.moe` | anonymous file host — block at proxy/DNS |
| `FortniteInjector/1.0` | HTTP User-Agent used with `InternetOpenW` |
| `https://discord.gg/linouservices` | distribution/support invite (appears in strings and in the "kicked" message) |

No IP addresses, no TLS callbacks to attacker hosts, no C2 protocol, no
beaconing: the loader makes exactly one HTTP(S) request.

## 3. Host artefacts

| Path / key | Note |
|---|---|
| `%TEMP%\fortnite_splash_download.png.tmp` | temporary download of the splash asset |
| `%TEMP%\<runtime-chosen name>` | embedded driver dropped before service creation (`\??\` prefix in `ImagePath`) |
| `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\SplashScreen.png` | overwritten asset (anti-cheat directory tampering) |
| `HKLM\SYSTEM\CurrentControlSet\Services\<runtime-chosen>` | `ImagePath` = `\??\%TEMP%\…`, `Type` = 1 (kernel driver) |
| Console title | `linou free internal but cuter` |
| Message box caption | `linou free internal` |

## 4. Process / behaviour indicators

* Unsigned, console-subsystem x64 process that immediately spawns a copy of
  itself via `ShellExecuteExW` with verb `runas` (UAC prompt).
* 42 back-to-back `taskkill.exe /f /im <name> /t` invocations from one parent
  process in under a second. Target names (complete list):

```
AMDRSServ.exe, AMDRSSrcExt.exe, GameBarFTServer.exe, GamePanel.exe,
ICYMICreator.exe, MSIAfterburner.exe, MServer.exe, Medal.exe, MedalEncoder.exe,
OWCleanup.exe, OWUninstallMenu.exe, OWUninstaller.exe, Overwolf.exe,
OverwolfBenchmarking.exe, OverwolfBrowser.exe, OverwolfCrashHandler.exe,
OverwolfHelper.exe, OverwolfHelper64.exe, OverwolfLauncher.exe,
OverwolfLauncherProxy.exe, OverwolfUpdater.exe, RTSS.exe, RadeonSoftware.exe,
ThumbnailGenerator.exe, amdow.exe, bcastdvr.exe, crashpad_handler.exe,
elevate.exe, ffmpeg.exe, ffprobe.exe, gameoverlayui.exe, inject-helper32.exe,
inject-helper64.exe, mp4info.exe, nvcontainer.exe, nvsphelper.exe,
nvsphelper64.exe, ow-obs.exe, ow-overlay.exe, squirrel.exe,
"NVIDIA App.exe", "NVIDIA Overlay.exe"
```

* Enumeration of every service under `SYSTEM\CurrentControlSet\Services` with
  repeated reads of the `ImagePath` value (service/persistence sweep) followed
  by `NtLoadDriver`.
* `DeviceIoControl` chatter with a freshly loaded driver from `%TEMP%`.
* Handle on `FortniteClient-Win64-Shipping.exe` opened by a non-game,
  unsigned process; `ReadProcessMemory`/`WriteProcessMemory` against it.
* Console window (`AllocConsole`) inside the game process; hotkeys read with
  `GetAsyncKeyState`.

## 5. Signature / certificate indicators

| Field | Value |
|---|---|
| Driver leaf subject | `CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, ST=Washington, C=US` |
| Driver issuer | `CN=Microsoft Windows Third Party Component CA 2012, O=Microsoft Corporation, …` |
| Leaf validity | 2025-02-20 → 2026-02-18 |
| Countersignature | Microsoft Time-Stamp PCA 2010, `2025-11-10T08:00:50Z`, HSM `nShield TSS ESN:3605-05E0-D947` |
| Vendor in nested signature | `PAutel Intelligent Technology Corp., Ltd` |
| Loader signature | **none** (`IMAGE_DIRECTORY_ENTRY_SECURITY` = 0) |

Hunt for *any* service whose `ImagePath` is under a user's `%TEMP%` and whose
binary carries a WHQL signature — that combination is never legitimate.

## 6. PDB / build-path artefacts

```
C:\Users\admin\Desktop\all src latest 04.11.26\all src latest\no sideload injector\New injector\Newinjector.pdb
C:\Users\admin\Desktop\all src latest 04.11.26\all src latest\fortnite internal\x64\Release\dll.pdb
```

Build machine: Windows account `admin`, project tree `all src latest 04.11.26`,
solution modules `no sideload injector` / `New injector` / `fortnite internal`.
Loader built 2026-11-05 21:06:53 UTC.

## 7. Detection quick-reference

* YARA: `yara/linou_free.yar`
* Sysmon: EID 1 (`taskkill` burst, unsigned parent), EID 11/15 (temp `.sys`,
  EAC `SplashScreen.png`), EID 12/13/14 (services key with temp path),
  EID 10 (handle to Fortnite with `0x1F0FFF`-style access from unsigned
  process), EID 22 (DNS to `files.catbox.moe`), EID 7 (driver image load from
  `%TEMP%`).
* Defender: vulnerable driver blocklist + HVCI enabled; custom indicator for the
  driver hash above.
