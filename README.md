# analysy — Educational Malware Analysis Lab

> ## ⚠️ EDUCATIONAL USE ONLY — READ THIS FIRST
>
> This repository exists **only** for education, malware analysis and reverse
> engineering research. It is a *defensive* lab.
>
> * **Do not download anything.** No cheat, loader, injector, payload or "free"
>   build may be downloaded, mirrored, re-uploaded or shared from this repo or
>   because of it.
> * **Do not run the sample.** `linou free.exe` is a live, weaponised artefact
>   (game cheat + kernel driver loader). It is stored here as evidence for
>   static study only.
> * **Do not use anything in this repository to cheat**, to bypass anti-cheat,
>   to gain an advantage in an online game, or to attack anybody's system.
> * **No malware development.** The material documents *what a sample does*; it
>   is not a template, SDK, source drop or "how to build a cheat" guide.
>
> Cheating violates the Terms of Service of every game involved (Epic Games /
> Fortnite, Easy Anti-Cheat) and is illegal in several jurisdictions. Analysing
> a binary does not give you permission to use it. See [LICENSE](LICENSE).

---

## What this repository is

A single-sample static analysis lab for the file:

| Property | Value |
|---|---|
| File name | `linou free.exe` |
| Size | 681,984 bytes |
| Type | PE32+ (x86-64) console executable, unsigned, `requireAdministrator` |
| SHA-256 | `7d2c55b9d95203e966f70e5de8a04aa48daccd7a1b5ff9d0b17f5a9a06bc085a` |
| MD5 | `d7e9be44fd922161220380a97e88a837` |
| Build timestamp | 2026-11-05 21:06:53 UTC (PDB: `...\no sideload injector\New injector\Newinjector.pdb`) |
| Family / label | "Linou Free" — Fortnite cheat loader / injector (`linou free internal`) |

The binary advertises itself as a free Fortnite cheat ("internal") distributed
through the Discord server `discord.gg/linouservices`. It is a classic
**loader → in-memory DLL payload → WHQL-signed kernel driver** chain.

### Short verdict

* **It is not a "clean" game utility.** It is a potentially unwanted program
  (PUP) / game cheat that:
  * requires Administrator rights and re-launches itself elevated,
  * drops and loads an **embedded kernel-mode driver** whose signature was
    issued through Microsoft's WHQL programme to a third party
    (`PAutel Intelligent Technology Corp., Ltd`) — a textbook
    [BYOVD](https://www.eset.com/us/about/newsroom/research/esets-research-into-bring-your-own-vulnerable-driver-details-attacks-on-drivers-in-windows-core/)
    style anti-cheat-bypass component,
  * **injects an embedded cheat DLL** into the game process and reads/writes
    its memory (`OpenProcess` + `ReadProcessMemory`/`WriteProcessMemory` +
    `DeviceIoControl`),
  * **replaces Easy Anti-Cheat's `SplashScreen.png`** with a picture
    downloaded from `https://files.catbox.moe/pvtjo9.png`,
  * **force-kills ~45 overlay, capture and GPU companion processes**
    (OBS/Overwolf/Medal/RTSS/MSI Afterburner/NVIDIA App/AMD Radeon Software,
    game bar, …) via `system("taskkill /f /im …")`,
  * ships an SDK/UObject dumper (`[gobjects]`), an in-game console and
    movement-ability patches.
* **No credential-stealer, ransomware, persistence or lateral-movement
  indicators were found** in this static review: no browser/wallet/Telegram/
  Discord-token paths, no `Run`/`RunOnce` autostart, no webhook, no archive or
  exfiltration code. See [analysis/ANALYSIS.md](analysis/ANALYSIS.md) for the
  evidence and the list of things that static analysis cannot rule out.
* Treat it as **malicious-equivalent**: rootkit-capable by design, ToS-breaking,
  and shipped by an anonymous party that can push arbitrary content (the PNG
  URL is remote and can be changed at will by the distributor).

Read the full report: **[analysis/ANALYSIS.md](analysis/ANALYSIS.md)** ·
Indicators: **[analysis/IOCS.md](analysis/IOCS.md)** ·
Detections: **[yara/linou_free.yar](yara/linou_free.yar)**

---

## Repository layout

```
.
├── README.md                  ← you are here
├── LICENSE                    ← educational-use-only licence
├── "linou free.exe"           ← the sample (evidence, DO NOT EXECUTE)
├── analysis/
│   ├── ANALYSIS.md            ← full static analysis report
│   ├── DRIVER_RE.md           ← full reverse engineering of the kernel driver
│   └── IOCS.md                ← hashes, URLs, paths, strings, registry keys
├── yara/
│   └── linou_free.yar         ← detection rules for the loader, DLL and driver
└── tools/
    ├── triage.py              ← reproducible, offline static triage
    └── emulate_strings.py    ← recovers the XOR stack strings in Unicorn (see ANALYSIS §7)
```

Generated artefacts (extracted payloads, entropy dumps, emulation logs) are
**not** committed. `tools/triage.py --extract` writes them to
`analysis/extracted/`, which is git-ignored on purpose: extracted payloads are
live code and must never be committed or shared.

## Reproducing the analysis

Everything here was produced **statically**, on Linux, without a network
connection to the sample's infrastructure:

```bash
python3 -m pip install pefile            # only external dependency
python3 tools/triage.py "linou free.exe" # hashes, PE info, embedded modules, IOC hits
```

Optional (see the report for the exact recipes):

```bash
# disassembly of the loader
objdump -d --no-show-raw-insn "linou free.exe" > main.asm

# symbolic/emulated recovery of the XOR-obfuscated stack strings
python3 -m pip install unicorn
```

Rules of engagement for this repo:

1. **Never execute the sample on a host you care about** — Admin rights + kernel
   driver + anti-cheat tampering is a worst-case combination. Use a disposable,
   snapshotted VM with no shared folders, no credentials, no network (or a
   host-only network behind an INetSim/fakenet), and take a snapshot before and
   after.
2. **Never fetch the sample's URLs.** `files.catbox.moe/pvtjo9.png` and the
   Discord invite are *evidence*, not resources. Requesting them tips off the
   distributor and may serve different content over time.
3. **Never share the binaries.** Hash lists and YARA rules are shareable; the
   sample is not.

## Scope and disclaimer

* The analysis reflects **one snapshot of one file** (hash above). The
  distributor can rebuild and re-sign at any time; re-hash before trusting any
  conclusion.
* Static analysis cannot prove the *absence* of a payload: the two embedded
  modules are large, the kernel driver is a third-party signed binary that was
  not fully disassembled, and the remote PNG is unexamined.
* This material is provided **as-is, without warranty**, for defensive and
  educational purposes. The author is not responsible for any misuse, for any
  account ban, or for any damage caused by running the sample.

## Licence

Original text, scripts and rules in this repository are released under the
**Educational Use Only Licence** — see [LICENSE](LICENSE).
The third-party binary is included solely as forensic evidence for study and
review; all rights in it remain with its authors and it is **not** licensed for
use, redistribution or execution.
