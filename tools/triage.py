#!/usr/bin/env python3
"""
triage.py — fully static, offline triage for the "Linou Free" sample
(and for any Windows PE you point it at).

    python3 tools/triage.py "linou free.exe"
    python3 tools/triage.py "linou free.exe" --extract

WHAT THIS SCRIPT DOES
    * computes MD5 / SHA-1 / SHA-256
    * parses the PE header (machine, subsystem, timestamps, PDB, manifest)
    * lists sections with Shannon entropy
    * summarises imports per DLL
    * finds PE files embedded inside the file (recursively)
    * greps the file for known indicators (ASCII and UTF-16LE)

WHAT IT NEVER DOES
    * it never executes, loads, maps or "runs" the sample
    * it never touches the network (no URL is ever requested)
    * it never writes anything outside --out (default: analysis/extracted/)

Licence: Educational Use Only — see LICENSE in the repository root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from datetime import datetime, timezone

try:
    import pefile
except ImportError:  # pragma: no cover
    sys.exit("pefile is required:  python3 -m pip install pefile")

# --------------------------------------------------------------------------- #
# Indicators of compromise observed in the analysed sample.
# They are *evidence*; nothing here is fetched or contacted.
# --------------------------------------------------------------------------- #
IOC_STRINGS = [
    "linou free internal",
    "linou free internal but cuter",
    "FortniteInjector/1.0",
    "https://files.catbox.moe/pvtjo9.png",
    "discord.gg/linouservices",
    "you just got kicked cutie",
    "Making the cat meow",
    "Cat meowed successfully",
    "fortnite_splash_download.png.tmp",
    "FortniteGame\\Binaries\\Win64\\EasyAntiCheat",
    "\\SplashScreen.png",
    "taskkill /f /im",
    "[gobjects]",
    "MmGetVirtualForPhysical",
    "PAutel",
    "no sideload injector",
    "fortnite internal",
    "Newinjector.pdb",
    "runas",
    "SYSTEM\\CurrentControlSet\\Services",
    "\\??\\",
]

IOC_HASHES = {
    "7d2c55b9d95203e966f70e5de8a04aa48daccd7a1b5ff9d0b17f5a9a06bc085a":
        "loader (linou free.exe)",
    "ee226cabc2216b1eba339bda1390a5916616591bfdb6ad72b149710e8e00ae0e":
        "embedded carrier DLL",
    "0b28f1d6a23044d5d3df258926004f9a5c1fd12c4af0517c94b7b78de36b3253":
        "embedded cheat DLL (fortnite internal)",
    "01da64b789dcffbdd2f6aa44b2988ee92c707e1815124faeb6382389d1220927":
        "embedded WHQL kernel driver (PAutel)",
}

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetWindowsHookExA", "SetWindowsHookExW", "QueueUserAPC",
    "DeviceIoControl", "NtLoadDriver", "ZwLoadDriver", "CreateServiceW", "CreateServiceA",
    "InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileW", "WinExec",
    "ShellExecuteExW", "system", "GetAsyncKeyState", "EnumWindows", "SendInput",
    "OpenProcessToken", "GetTokenInformation", "RegSetKeyValueW", "RegDeleteTreeW",
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def utc(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return f"<invalid {ts:#x}>"


def pe_span(blob: bytes, off: int) -> int:
    """Size of the PE starting at `off`, based on its section table."""
    e_lfanew = struct.unpack_from("<I", blob, off + 0x3C)[0]
    fh = off + e_lfanew + 4
    nsec = struct.unpack_from("<H", blob, fh + 2)[0]
    optsz = struct.unpack_from("<H", blob, fh + 16)[0]
    opt = fh + 20
    magic = struct.unpack_from("<H", blob, opt)[0]
    dd = opt + (108 if magic == 0x20B else 92)
    end = 0
    sec = opt + optsz
    for i in range(nsec):
        s = sec + i * 40
        _, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", blob, off + (s - off))
        end = max(end, rptr + rsize)
    ndirs = struct.unpack_from("<I", blob, dd)[0] if magic in (0x10B, 0x20B) else 0
    if ndirs > 4:  # index 4 = certificate table (stored as a file offset)
        cva, csz = struct.unpack_from("<II", blob, dd + 4 + 8 * 4)
        # only trust it if a WIN_CERTIFICATE header really is where it claims
        if cva and csz >= 8 and off + cva + 8 <= len(blob):
            clen = struct.unpack_from("<I", blob, off + cva)[0]
            if 8 <= clen <= csz:
                end = max(end, cva + clen)
    return end


def find_embedded(blob: bytes, base: int = 0, label: str = "lvl0", depth: int = 0):
    """Yield (offset, size, label) for every PE embedded in `blob`."""
    out = []
    pos = 0
    while True:
        i = blob.find(b"MZ", pos)
        if i < 0:
            break
        pos = i + 2
        if i + 0x40 > len(blob):
            break
        if i == 0 and base == 0:
            continue  # the file itself, reported separately
        try:
            e = struct.unpack_from("<I", blob, i + 0x3C)[0]
            if e > 0x400 or i + e + 4 > len(blob):
                continue
            if blob[i + e:i + e + 4] != b"PE\0\0":
                continue
            size = pe_span(blob, i)
        except struct.error:
            continue
        if size <= 0 or i + size > len(blob):
            size = len(blob) - i
        name = f"{label}_{base + i:#010x}"
        out.append((base + i, size, name))
        if depth < 2:
            out.extend(find_embedded(blob[i:i + size], base + i, name, depth + 1))
    # de-duplicate (nested scans can report the same file twice)
    seen, uniq = set(), []
    for o, s, n in out:
        if o in seen:
            continue
        seen.add(o)
        uniq.append((o, s, n))
    return uniq


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def section(title):
    print("\n" + title)
    print("-" * len(title))


def main() -> int:
    ap = argparse.ArgumentParser(description="Static (offline) triage of a Windows PE.")
    ap.add_argument("sample", help='path to the file, e.g. "linou free.exe"')
    ap.add_argument("--extract", action="store_true",
                    help="write embedded PEs to --out (they are live code!)")
    ap.add_argument("--out", default="analysis/extracted",
                    help="output directory for --extract (default: analysis/extracted)")
    args = ap.parse_args()

    path = args.sample
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        return print(f"cannot read {path}: {exc}") or 2

    print("=" * 78)
    print(" STATIC TRIAGE — nothing is executed, no network access is performed")
    print("=" * 78)

    h = hashes(data)
    section("File")
    print(f"  path      : {path}")
    print(f"  size      : {h['size']:,} bytes ({h['size']:#x})")
    print(f"  md5       : {h['md5']}")
    print(f"  sha1      : {h['sha1']}")
    print(f"  sha256    : {h['sha256']}")
    if h["sha256"] in IOC_HASHES:
        print(f"  !! known sample: {IOC_HASHES[h['sha256']]}")

    if data[:2] != b"MZ":
        print("\nNot a PE file — stopping here.")
        return 0

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        print(f"\nPE parse error: {exc}")
        return 0

    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    section("PE header")
    machine = {0x8664: "x86-64", 0x14C: "x86", 0xAA64: "ARM64"}.get(fh.Machine, hex(fh.Machine))
    subsystem = {1: "native (driver)", 2: "GUI", 3: "console"}.get(oh.Subsystem, oh.Subsystem)
    print(f"  machine      : {machine}")
    print(f"  subsystem    : {subsystem}")
    print(f"  image base   : {oh.ImageBase:#x}   entry point: {oh.AddressOfEntryPoint:#x}")
    print(f"  linker       : {oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}")
    print(f"  build time   : {utc(fh.TimeDateStamp)}")
    print(f"  checksum     : {'ok' if pe.verify_checksum() else 'MISSING/INVALID'}")
    cert = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    print(f"  signature    : {'present (' + str(cert.Size) + ' bytes)' if cert.Size else 'NOT SIGNED'}")
    print(f"  TLS callbacks: {'yes' if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 'no'}")
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            if getattr(dbg.struct, "PdbFileName", None):
                print(f"  PDB          : {dbg.struct.PdbFileName.decode(errors='replace')}")

    # manifest (requested execution level)
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id != 24:  # RT_MANIFEST
                continue
            for e2 in entry.directory.entries:
                for e3 in e2.directory.entries:
                    blob = data[e3.data.struct.OffsetToData:
                                e3.data.struct.OffsetToData + e3.data.struct.Size].decode(
                        "utf-8", "ignore")
                    if "requestedExecutionLevel" in blob:
                        lvl = blob.split("requestedExecutionLevel")[1].split("level=")[1].split()[0]
                        print(f"  execution    : {lvl}")

    section("Sections")
    print(f"  {'name':10s} {'virt addr':>10s} {'virt size':>10s} {'raw size':>10s} {'entropy':>8s}")
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        print(f"  {name:10s} {s.VirtualAddress:#10x} {s.Misc_VirtualSize:#10x} "
              f"{s.SizeOfRawData:#10x} {s.get_entropy():8.2f}")
    if any(s.get_entropy() > 7.2 for s in pe.sections):
        print("  !! at least one high-entropy section (packed/encrypted data)")

    section("Imports")
    risky = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for imp in pe.DIRECTORY_ENTRY_IMPORT:
            names = [i.name.decode() if i.name else f"ord{i.ordinal}" for i in imp.imports]
            print(f"  {imp.dll.decode():28s} {len(names):3d}  {', '.join(names[:8])}"
                  f"{' …' if len(names) > 8 else ''}")
            risky.extend(n for n in names if n in SUSPICIOUS_IMPORTS)
    else:
        print("  (none)")
    if risky:
        print(f"\n  noteworthy imports: {', '.join(sorted(set(risky)))}")

    section("Embedded PE files")
    embedded = find_embedded(data)
    reported = []
    for off, size, name in embedded:
        blob = data[off:off + size]
        hh = hashlib.sha256(blob).hexdigest()
        reported.append({"offset": off, "size": size, "sha256": hh})
        tag = IOC_HASHES.get(hh, "")
        print(f"  {off:#010x}  {size:>10,} B  {hh[:32]}…  {tag}")
        if args.extract:
            os.makedirs(args.out, exist_ok=True)
            out = os.path.join(args.out, f"0x{off:08x}_{hh[:16]}.bin")
            with open(out, "wb") as fh_out:
                fh_out.write(blob)
            print(f"              -> written to {out}  (live code: handle with care)")
    if not embedded:
        print("  none found")

    section("Indicator strings (ASCII + UTF-16LE)")
    found = {}
    for s in IOC_STRINGS:
        for enc, label in (("ascii", "A"), ("utf-16-le", "W")):
            if s.encode(enc) in data:
                found.setdefault(s, set()).add(label)
    for s, encs in found.items():
        print(f"  [{'/'.join(sorted(encs))}] {s}")
    if not found:
        print("  none of the known indicators matched")

    section("Notes")
    print("  * Loader strings are XOR-obfuscated in this family; absence of a string")
    print("    above does not mean the capability is absent — see analysis/ANALYSIS.md §7")
    print("    (tools/emulate_strings.py recovers them by emulation).")
    print("  * Static triage cannot prove a binary is clean. Detonate only in an")
    print("    isolated, snapshotted VM with no credentials and a fake network.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
