# Feature inventory — what "Linou Free" actually does

Derived from static analysis of every module in `linou free.exe`
(loader, carrier DLL, cheat DLL, kernel driver). Evidence is cited per row;
"not found" means an explicit search of ASCII **and** UTF-16 across all four
modules returned nothing (see [ANALYSIS.md](ANALYSIS.md) §5.1 and
[DRIVER_RE.md](DRIVER_RE.md)).

> **Short version:** despite "free Fortnite cheat" marketing, this build is a
> **movement-ability unlocker + UObject/SDK dumper** with a kernel-memory
> backend — **not** an aimbot/ESP package. There is no renderer of any kind in
> the binary (no D3D11/D3D12/DXGI/ImGui/GDI), so no ESP, chams or visual menu
> can be produced by this code as shipped.

---

## 1. In-game features (cheat DLL, offset `0x126B0`)

All of them are Fortnite **movement-mode extension** classes; the payload holds
45 asset paths that map them into the game's movement system. Each ability
appears twice (Blueprint `_C` class + `Script` runtime class), so 45 paths =
**29 distinct abilities**:

| # | Ability | Asset string (evidence) |
|---|---|---|
| 1 | **Fly** | `/Script/FlyingCodeRuntime.FortMovementMode_ExtLogicFlying` |
| 2 | **Winged / Sun Rose fly** | `/Script/SunRoseFlyingRuntime.FortMovementMode_ExtLogicFlyingWinged`, `/Script/WingSuitRuntime.FortMovementMode_ExtLogicWingSuit` |
| 3 | **Boosted jump** | `/Script/BoostJumpCode.FortMovementMode_ExtLogicBoostedJump`, `/BoostedJump/MovementMode/FMM_ExtBoostedJump.FMM_ExtBoostedJump_C` |
| 4 | **Wall jump** | `/Script/WallJumpCodeRuntime.FortMovementMode_ExtWallJump`, `/WallJump/MovementMode/FMM_ExtWallJump.FMM_ExtWallJump_C` |
| 5 | **Infinite wall stick** | `/Script/WallStickCodeRuntime.FortMovementMode_ExtLogicWallStick`, `/WallStick/MovementMode/MME_Logic_WallStick_Infinite.MME_Logic_WallStick_Infinite_C` |
| 6 | **Leap / super jump** | `/Script/FortniteGame.FortMovementMode_ExtLeap` |
| 7 | **Zero Point dash** | `/Script/DashRuntime.FortMovementMode_ExtDash`, `/Dash/MovementMode/ZeroPointDash_MME.ZeroPointDash_MME_C` |
| 8 | **Ground rush / glider release** | `/Script/GroundRushCode.FortMovementMode_ExtLogicGroundRush`, `/GliderRelease/Gameplay/MovementMode/MME_GroundRush.MME_GroundRush_C` |
| 9 | **Nitro state** | `/Script/NitroGameplayRuntime.FortMovementMode_ExtLogicNitroState` |
| 10 | **Tactical sprint** | `/Script/TacticalSprintRuntime.FortMovementMode_ELTacSprint`, `/TacticalSprintGame/Gameplay/MovementModeExtension/FMMEL_TacSprint.FMMEL_TacSprint_C` |
| 11 | **Slide** | `/Script/SlidingRuntime.FortMovementMode_Sliding`, `/Sliding/Blueprints/FMM_ExtSliding.FMM_ExtSliding_C` |
| 12 | **Slippery movement (ice-like)** | `/Script/SlipperyMovementCode.FortMovementMode_ExtLogicSlipperyMovement`, `/SlipperyMovement/Gameplay/FMM_SlipperyMovement.FMM_SlipperyMovement_C` |
| 13 | **Clamber** | `/Script/ClamberingCodeRuntime.FortMovementMode_ExtClambering`, `/ClamberingContent/Gameplay/FMM_ExtClamber.FMM_ExtClamber_C` |
| 14 | **Hurdle / vault** | `/Script/VaultingCodeRuntime.FortMovementMode_ExtLogicHurdle`, `/VaultingContent/Gameplay/MovementModeExtension/FMM_ExtHurlde.FMM_ExtHurlde_C` |
| 15 | **Zipline** | `/Script/ZiplineCodeRuntime.FortMovementMode_ExtLogicZipline`, `/Zipline/MovementMode/MME_Logic_Zipline.MME_Logic_Zipline_C` |
| 16 | **Grind rail** | `/Script/GrindRailRuntime.FortMovementMode_ExtLogicGrinding`, `/GrindRail/Blueprints/Movement/GrindingExtensionLogic.GrindingExtensionLogic_C` |
| 17 | **Cube surfing** | `/Script/CubeSurfingRuntime.FortMovementMode_ExtLogicCubeSurfing` |
| 18 | **Sky dive** | `/Script/SkyDivingCode.FortMovementMode_ExtLogicSkyDiving`, `/SkyDiving/MME/MME_SkyDiving.MME_SkyDiving_C` |
| 19 | **Hover** | `/Script/HoverGameplayRuntime.FortMovementMode_ExtHover` |
| 20 | **Ragdoll control** | `/Script/RagdollCode.FortMovementMode_ExtLogicRagdoll`, `/Script/TrendConcentrateRuntime.FortMovementMode_ExtLogicRagdollBase` |
| 21 | **DBNO roll** | `/Script/TrendConcentrateRuntime.FortMovementMode_ExtLogicDBNORoll`, `/TrendConcentrate/Gameplay/Movement/MME_Logic_DBNORoll.MME_Logic_DBNORoll_C` |
| 22 | **Roll landing** | `/Script/RollLandingCodeRuntime.FortMovementMode_ExtRollLanding` |
| 23 | **Damage landing (no landing damage)** | `/Script/DamageLandingCode.FortMovementMode_ExtDamageLanding` |
| 24 | **Fall-damage override** | `/Script/FallDamageOverrideCode.FortMovementMode_ExtFallDamageOverride` |
| 25 | **Shot hop (Pistol Cavalry)** | `/Script/PistolCavalryRuntime.FortMovementMode_ExtLogic_ShotHop` |
| 26 | **Tacky Goofiness stretch launch** | `/Script/TackyGoofinessGameplay.FortMovementMode_TackyGoofinessStretchLaunch` |
| 27 | **Slow-mo aim in air / hang time** | `/SloMoAimInAirParent/Gameplay/Movement/MME_SloMoAimInAir_HangTime.MME_SloMoAimInAir_HangTime_C` |
| 28 | **Car-wash speed buff** | `/CarWash/Gameplay/Player/FMM_CarWash_PlayerSpeedBuff.FMM_CarWash_PlayerSpeedBuff_C` |
| 29 | **SDK / UObject dumper** | `[gobjects] wrote valid=%u empty=%u`, `[gobjects] progress %u/%u`, `[gobjects] dump crashed, stopped` |

**What capability 29 buys the operator:** a dump of the game's reflection data
(`UObject` table). That is the reconnaissance step needed to locate *any* engine
function at run time — which is also why the payload needs no D3D/GDI code: it
can call whatever engine routine the dump reveals.

**Hotkeys.** `GetAsyncKeyState` is called from **43 sites**, 38 with literal
virtual-key codes: `0x02` RMB, `0x11` CTRL, `0x20` SPACE, `0xA0` LSHIFT,
`0x41` A, `0x44` D, `0x53` S, `0x56` V, `0x57` W, `0x47` G, `0x4A` J, `0x4B` K,
`0x74` F5, `0x77` F8. Features are toggled from the keyboard — there is no menu
renderer (next section).

**No rendering UI.** Searched for `d3d11/d3d12/dxgi/d3d9`, `IDXGISwapChain`,
`CreateDevice*`, `Present`, `DrawIndexed`, `D3DCompile`, `imgui/ImGui`,
`DXBC/DXIL`, `gdi32/gdiplus/dwmapi`, `CreateWindowEx/RegisterClass/GetDC`, and
found **zero** hits. The payload imports only `KERNEL32` + `USER32` and
`USER32` is `GetAsyncKeyState` alone. The console-subsystem imports
(`AllocConsole`, `ReadConsoleW`, `WriteConsoleW`, `SetConsoleMode`) have **no
call sites** — CRT leftovers, not a console menu.

**Taunt / branding.** `you just got kicked cutie!! dont forget that
https://discord.gg/linouservices is the cutest discord server of all time` —
shown when the user is removed from the product.

---

## 2. Loader / launcher features (main EXE)

| Feature | Evidence |
|---|---|
| Silent self-elevation to Administrator | `requireAdministrator` manifest + `ShellExecuteExW("runas")` + `GetTokenInformation(TokenElevation)` |
| Refuses to run without admin | `[!] Failed: administrator rights required.` |
| ntdll resolution (`NtLoadDriver` etc.) | `[!] Failed: ntdll bindings.` |
| **Kills 42 capture/overlay/GPU processes** | 42 × `system("taskkill /f /im … /t >nul 2>&1")` (Overwolf ×16, OBS helpers, Medal, RTSS, MSI Afterburner, NVIDIA App/container, AMD Radeon, Game Bar/DVR, ffmpeg, crashpad, inject-helpers) |
| Drops the embedded kernel driver to `%TEMP%` | `GetTempPathW` + `CreateFileW`/`WriteFile` + `[!] Failed: Driver creation error. (GetTempPath )` |
| Registers it as a **service** and loads it | `SYSTEM\CurrentControlSet\Services\<name>`, values `ImagePath` = `\??\%TEMP%\…`, `Type` = 1, then `NtLoadDriver` (`[!] Failed: Driver load error.`) |
| Sweeps the whole Services registry | `RegEnumKeyExW` + `RegQueryValueExW("ImagePath")` over every key (~300 k emulated calls), plus `RegDeleteTreeW` available |
| **Replaces Easy Anti-Cheat's splash image** | downloads `https://files.catbox.moe/pvtjo9.png` (UA `FortniteInjector/1.0`) → `%TEMP%\fortnite_splash_download.png.tmp` → `MoveFileExW` to `…\EasyAntiCheat\SplashScreen.png` (`[*] Making the cat meow...` / `[+] Cat meowed successfully!`) |
| Finds the game process | `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` |
| Injects the carrier DLL (manual map) | `OpenProcess` + `WriteProcessMemory` + thread creation resolved from ntdll; carrier's `.data` is a byte-copy of the cheat DLL |
| Kernel-assisted memory channel | `DeviceIoControl` + `[!] Recovery channel unavailable.`, `DeviceIoControl … error …` |
| Game-window handling | `EnumWindows`/`EnumChildWindows`/`GetClassNameW`/`SetForegroundWindow`/`ShowWindow`/`GetSystemMenu`/`EnableMenuItem`/`SendInput` |
| Console UI + error dialog | `SetConsoleTitleW("linou free internal but cuter")`, coloured `wcout` output, `MessageBoxA(NULL, …, "linou free internal", …)` |
| All user-facing strings encrypted | 16-byte XOR stack blocks (recovered in ANALYSIS.md §7) |

## 3. Kernel-driver features (offset `0x986B0`, full RE in DRIVER_RE.md)

| Feature | Evidence |
|---|---|
| IOCTL device `\\.\mLnUcWtv9IaZf8LBiMXD` (type `0x22`) | XOR-0xAA strings `\Device\…` / `\DosDevices\…` + `IoCreateDevice`/`IoCreateSymbolicLink` |
| Attach to any process and read/write/patch its memory | `IOCTL 0x222004` → `PsLookupProcessByProcessId` + `KeStackAttachProcess` + 11.9 KB engine |
| Authorisation handshake | requires magic `0x2AFBBBDC` else `STATUS_ACCESS_DENIED` |
| Physical memory access | `\device\physicalmemory` via `ZwOpenSection`+`ZwMapViewOfSection`; `IoAllocateMdl`+`MmBuildMdlForNonPagedPool`+`MmMapLockedPagesSpecifyCache`; `MmAllocatePagesForMdlEx` |
| CR3 / PML4 self-map VA translation | `0x140001F30`, PTE base `0xFFFFF68000000000` |
| Module base by name inside a process | PEB walk (`PsGetProcessPeb`, `PsGetProcessWow64Process`, `RtlCompareUnicodeString`) |
| Allocate / change protection in the target | `ZwAllocateVirtualMemory`, `ZwProtectVirtualMemory` wrappers |
| **Force-delete any file (bypasses in-use locks)** | `IOCTL 0x222024` → `ZwCreateFile` → clear section object → set `DeleteAccess` → `ZwDeleteFile` |
| Memory marker patcher | scans for `0x1122334455667788`, overwrites it |

## 4. Advertised elsewhere but **not present** in this build

Explicitly searched across all modules, including UTF-16 and obfuscated forms:

* **Aimbot / silent aim / triggerbot / FOV circle** — no such strings, no
  input-injection loop against the game, no rendering.
* **ESP / wallhack / chams / skeletons / snaplines** — no skeleton, bone,
  `PlayerController`, `Pawn` or draw-call strings, and no graphics API.
* **Weapon / combat cheats** — no ammo, recoil, spread, reload, damage or
  `AbilitySystem` strings.
* **Cosmetics / skin / emote / item unlockers, currency, stats, levels** — none.
* **HWID spoofer / ban bypass / account manager** — none.
* **Visual menu of any kind (DX11, DX12, GDI, ImGui, engine canvas)** — none of
  the APIs are imported; see §1.
* **Keylogger, webhook, stealer, persistence, C2** — none (see ANALYSIS §5.1).

**Caveat:** Fortnite is fully reflected and the payload resolves engine
functions at run time from its `[gobjects]` dump, so a visual feature added in a
*later build* could exist without leaving any new import behind. What is proven
here is what **this** binary can and cannot do: it ships a movement-ability
unlocker, an SDK dumper, hotkey handling and a kernel memory backend — and no
renderer.

---

## 5. Confidence

| Claim | Confidence |
|---|---|
| 29 movement abilities + SDK dump are the in-game features | High — literal asset paths / log formats |
| Hotkey-driven (no menu) | High — 38 literal VK codes, no UI/graphics imports |
| Loader: elevation, 42 process kills, driver install, EAC splash rewrite, injection | High — verified in disassembly + emulated strings |
| Driver: process R/W + physical memory + arbitrary file delete | High — imports, IOCTLs, magic, code paths |
| No aimbot/ESP/stealer in this build | High for "not implemented in this binary"; cannot speak for other builds or the remote PNG |
