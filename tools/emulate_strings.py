#!/usr/bin/env python3
"""
emulate_strings.py — recover XOR-obfuscated stack strings from a PE by
emulating *individual functions* in Unicorn. Nothing is executed natively.

    python3 -m pip install pefile unicorn
    python3 tools/emulate_strings.py "linou free.exe"
    python3 tools/emulate_strings.py "linou free.exe" 0x140007ef0 0x140005180

WHY
    The "Linou Free" loader never stores a readable string. Every message,
    registry path and service value is built on the stack as 16-byte XOR blocks
    (movabs/xorps), so `strings` only shows the payloads that are stored
    unpacked in .rdata. See analysis/ANALYSIS.md §7.

HOW
    1. the PE is mapped into a Unicorn x86-64 address space (image base as in
       the header, a private stack, a private heap, a zero page at 0 so that
       NULL dereferences do not abort the run);
    2. every IAT slot is rewritten to point at a private stub page, so an
       indirect `call [IAT]` lands on a hook instead of an unmapped address;
    3. the hook logs RCX/RDX/R8/R9 (decoding each both as ASCII and UTF-16LE)
       and continues execution at the caller's return address with RAX = 0.
       `memcpy`/`memmove`/`memset`/`memcmp`/`malloc` are really implemented so
       that std::string construction keeps working;
    4. functions are started with RSP/RBP set up and R9..RCX = 0. Most
       decrypt-then-use sequences do not depend on argument values, so their
       plaintext still ends up in the log.

    `GetTempPathW` / `GetModuleFileNameW` deliberately return paths containing
    the marker "marker" so that any string fabricated by this harness is easy to
    recognise and ignore.

WHAT THIS IS NOT
    This is not a sandbox and not an unpacker. It emulates a handful of
    instructions from a static image for analysis purposes and never lets the
    sample make a syscall, touch the disk, or reach the network. Keep it that
    way: this repository is educational-use only (see ../LICENSE).

    Defaults below are the function starts of the analysed sample (taken from
    its .pdata unwind table).
"""

from __future__ import annotations

import argparse
import struct
import sys

try:
    import pefile
    from unicorn import Uc, UcError, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_RSP,
    )
except ImportError:  # pragma: no cover
    sys.exit("dependencies:  python3 -m pip install pefile unicorn")

STUB_BASE = 0x50000000          # private page holding one stub per import
STACK_BASE = 0x7FF000000000     # private stack
STACK_SIZE = 0x200000
HEAP_BASE = 0x60000000          # private heap for memcpy/malloc emulation
HEAP_SIZE = 0x01000000
SENTINEL = 0xDEADBEEF           # fake return address that ends a run

HEAP_APIS = {"malloc", "_callnewh", "VirtualAlloc"}
LIBC_APIS = {"memcpy", "memmove", "memset", "memcmp"}

DEFAULT_TARGETS = [
    0x140007EF0,  # main(): elevation, taskkill burst, driver install, splash
    0x140005180,  # driver service creation (ImagePath / Type)
    0x140006840,  # driver I/O + injection orchestrator
    0x1400067B0,  # DeviceIoControl wrapper
]


class Heap:
    def __init__(self) -> None:
        self.next = HEAP_BASE

    def alloc(self, size: int) -> int:
        size = (size + 0xF) & ~0xF or 0x1000
        if self.next + size > HEAP_BASE + HEAP_SIZE:
            return 0
        addr = self.next
        self.next += size
        return addr


def decode_string(mu, addr: int, limit: int = 200) -> str | None:
    """Decode a pointer in emulated memory as ASCII or UTF-16LE."""
    if not addr:
        return None
    try:
        buf = bytes(mu.mem_read(addr, 2 * limit))
    except UcError:
        return None
    ascii_candidate = buf.split(b"\x00")[0].decode("latin-1", "replace")
    wide, ok = [], True
    for i in range(0, len(buf) - 1, 2):
        if buf[i] == 0 and buf[i + 1] == 0:
            break
        if buf[i + 1] != 0:
            ok = False
            break
        wide.append(chr(buf[i]))
    wide_candidate = "".join(wide) if ok else ""
    candidates = [
        c for c in (ascii_candidate, wide_candidate)
        if len(c) >= 2 and sum(ch.isprintable() for ch in c) >= 0.9 * len(c)
    ]
    return max(candidates, key=len)[:limit] if candidates else None


def run_function(pe, raw: bytes, start: int, max_instructions: int = 400_000):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF

    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            name = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
            imports[imp.address] = f"{entry.dll.decode()}:{name}"

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(image_base, image_size)
    mu.mem_map(0, 0x10000)                     # zero page: NULL reads succeed
    mu.mem_write(0, b"\x00" * 0x10000)
    mu.mem_write(image_base, raw[:0x400])      # PE headers
    for sec in pe.sections:
        chunk = raw[sec.PointerToRawData:sec.PointerToRawData + sec.SizeOfRawData]
        if chunk:
            mu.mem_write(image_base + sec.VirtualAddress, chunk)
    mu.mem_map(STUB_BASE, 0x10000)
    mu.mem_write(STUB_BASE, b"\xc3" * 0x10000)  # every stub is a bare `ret`
    stubs = {}
    for index, (slot, name) in enumerate(imports.items()):
        addr = STUB_BASE + index * 8
        stubs[addr] = name
        mu.mem_write(slot, struct.pack("<Q", addr))
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.mem_map(HEAP_BASE, HEAP_SIZE)

    heap = Heap()
    found: list[tuple[str, str]] = []

    def hook(uc, address, size, _user):
        if address not in stubs:
            return  # ordinary instruction inside the emulated image
        name = stubs[address]
        short = name.split(":")[-1]
        rsp = uc.reg_read(UC_X86_REG_RSP)
        try:
            ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        except UcError:
            ret = 0
        args = [uc.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX,
                                        UC_X86_REG_R8, UC_X86_REG_R9)]
        for arg in args:
            text = decode_string(uc, arg)
            if text and len(text) >= 3:
                found.append((short, text))

        value = 0
        if short in ("memcpy", "memmove"):
            try:
                if args[2]:
                    uc.mem_write(args[0], bytes(uc.mem_read(args[1], args[2])))
            except UcError:
                pass
            value = args[0]
        elif short == "memset":
            try:
                if args[2]:
                    uc.mem_write(args[0], bytes([args[1] & 0xFF]) * args[2])
            except UcError:
                pass
            value = args[0]
        elif short == "memcmp":
            try:
                left = bytes(uc.mem_read(args[0], args[2]))
                right = bytes(uc.mem_read(args[1], args[2]))
                value = 0 if left == right else (1 if left > right else -1)
            except UcError:
                value = 0
        elif short in HEAP_APIS:
            value = heap.alloc(args[0] or 0x100)
        elif short == "__acrt_iob_func":
            value = HEAP_BASE + 0x8000
        elif short == "GetTempPathW":
            try:
                uc.mem_write(args[0], "C:\\Users\\marker\\".encode("utf-16-le") + b"\x00\x00")
            except UcError:
                pass
            value = 16
        elif short == "GetModuleFileNameW":
            try:
                uc.mem_write(args[0], "Z:\\marker\\MZQRK.exe".encode("utf-16-le") + b"\x00\x00")
            except UcError:
                pass
            value = 20

        uc.reg_write(UC_X86_REG_RAX, value)
        if ret == SENTINEL:
            uc.emu_stop()
            return
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    mu.hook_add(UC_HOOK_CODE, hook)

    rsp = STACK_BASE + STACK_SIZE - 0x800
    mu.mem_write(rsp, struct.pack("<Q", SENTINEL))
    for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9):
        mu.reg_write(reg, 0)
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, rsp)

    status = "completed"
    try:
        mu.emu_start(start, SENTINEL, count=max_instructions)
    except UcError as exc:
        status = f"stopped: {exc}"
    return found, status


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sample")
    ap.add_argument("targets", nargs="*", help="function start addresses (hex), default: known set")
    ap.add_argument("--max-insn", type=int, default=400_000)
    args = ap.parse_args()

    data = open(args.sample, "rb").read()
    pe = pefile.PE(data=data, fast_load=False)
    targets = [int(t, 16) for t in args.targets] if args.targets else list(DEFAULT_TARGETS)

    print(f"# {args.sample} — image base {pe.OPTIONAL_HEADER.ImageBase:#x}")
    print("# emulating function entry points in Unicorn; nothing is executed natively\n")
    for start in targets:
        strings, status = run_function(pe, data, start, args.max_insn)
        print(f"===== function {start:#x} ({status}), {len(strings)} string arguments")
        seen = set()
        for api, text in strings:
            if text in seen:
                continue
            seen.add(text)
            print(f"  {api:32s} {text!r}")
        print()
    print('# strings containing "marker"/"MZQRK" are fabrications of this harness — ignore them.')
    return 0


if __name__ == "__main__":
    sys.exit(main())
