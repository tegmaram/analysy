# Kernel driver — full static reverse engineering

**File:** embedded at offset `0x986B0` of `linou free.exe`
**SHA-256:** `01da64b789dcffbdd2f6aa44b2988ee92c707e1815124faeb6382389d1220927`
**Size:** 40,080 bytes = `0x7600` image + `0x2690` Authenticode `WIN_CERTIFICATE`
**Type:** PE32+ KMDF driver (native subsystem), image base `0x140000000`,
entry `0x5DC0` in `INIT`, `SizeOfImage` `0x8000`, 6 sections, 47 functions
(`.pdata`), no exports, no debug directory
**Build stamp:** 2025-11-09 16:48:44Z
**Signature:** `CN=Microsoft Windows Hardware Compatibility Publisher`
(valid 2025-02-20 → 2026-02-18) ← `Microsoft Windows Third Party Component CA
2012` ← `Microsoft Root CA 2010`; RFC-3161 timestamp 2025-11-10T08:00:50Z;
nested vendor signature organisation **`PAutel Intelligent Technology Corp., Ltd`**

Everything below comes from static disassembly (`objdump -d`, 4,867 lines) plus
direct parsing of the section data. The driver was **not** loaded or executed.

---

## 1. Section map

| Section | VA | VirtSize | RawSize | Entropy | Content |
|---|---|---|---|---|---|
| `.text` | `0x1000` | `0x54B5` | `0x5600` | 5.26 | engine + WDM plumbing |
| `.rdata` | `0x7000` | `0x0C68` | `0x0E00` | 3.85 | import thunks, **XOR-0xAA strings**, KMDF binding blobs |
| `.data` | `0x8000` | `0x03E0` | `0x0200` | 3.00 | globals (device object, name buffers, wrap flag) |
| `.pdata` | `0x9000` | `0x0228` | `0x0400` | 2.42 | 47 `RUNTIME_FUNCTION` entries |
| `INIT` | `0xA000` | `0x05EA` | `0x0600` | 4.99 | `DriverEntry` + KMDF bootstrap (discardable) |
| `.reloc` | `0xB000` | `0x0034` | `0x0200` | 0.67 | 1 relocation block |

## 2. Imports (39 × ntoskrnl, 5 × WDFLDR)

```
ExAllocatePoolWithTag, ExFreePoolWithTag, MmBuildMdlForNonPagedPool,
MmProtectMdlSystemAddress, MmMapLockedPagesSpecifyCache, MmAllocatePagesForMdlEx,
IoAllocateMdl, IoGetCurrentProcess, ObReferenceObjectByHandle, ObfDereferenceObject,
ZwClose, ZwOpenSection, ZwMapViewOfSection, ZwUnmapViewOfSection, MmIsAddressValid,
KeStackAttachProcess, KeUnstackDetachProcess, KeDelayExecutionThread,
ZwAllocateVirtualMemory, ZwProtectVirtualMemory, PsLookupProcessByProcessId,
PsGetProcessPeb, PsGetProcessWow64Process, RtlInitUnicodeString, RtlCopyUnicodeString,
RtlCompareMemory, RtlCompareUnicodeString, MmGetSystemRoutineAddress,
IofCompleteRequest, IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice,
IoDeleteSymbolicLink, IoFileObjectType, ZwCreateFile, ZwDeleteFile, KeGetCurrentIrql,
strcmp, DbgPrintEx, __C_specific_handler
WDFLDR.SYS: WdfVersionBind, WdfVersionBindClass, WdfVersionUnbind, WdfVersionUnbindClass,
            WdfLdrQueryInterface
```

There is **no** `MmMapIoSpace`, no `MmGetPhysicalMemoryRanges`, no `PsSetCreateProcessNotifyRoutine`,
no file-system filter registration, no `ObRegisterCallbacks`, no network/WFP code — i.e. this
is not a generic rootkit; it is a **targeted, IOCTL-driven memory-access service**.

## 3. String encoding — XOR 0xAA on UTF-16

All three operational strings are stored as wide characters XOR'ed with `0xAA`
(the two KMDF strings `KmdfLibrary` / `Ntldll`/`User32` remain plaintext).
Decode with:

```python
bytes(b ^ 0xAA for b in raw).decode('utf-16-le')
```

| VA | Encoded bytes | Decoded |
|---|---|---|
| `0x7338` | `f6 ce cf dc c3 c9 cf f6 …` | `\device\physicalmemory` |
| `0x7360` | `f6 ee cf dc c3 c9 cf f6 …` | `\Device\mLnUcWtv9IaZf8LBiMXD` |
| `0x7388` | `f6 ee c5 d9 ee cf dc c3 …` | `\DosDevices\mLnUcWtv9IaZf8LBiMXD` |

→ user-mode path **`\\.\mLnUcWtv9IaZf8LBiMXD`** (device type `0x22`).
The `\device\physicalmemory` string is the section opened to read raw physical
memory — the classic "physical R/W" primitive.

## 4. Entry point and WDF binding

`DriverEntry` (`0x140005DC0`, `INIT`) is a three-instruction prologue that calls
`0x14000A000` (sanity/initialisation) and `0x140005DEC` (the real initialiser):

```
0x140005DEC  …  WdfVersionBind("KmdfLibrary", …)          ; WDFLDR
             …  WdfVersionBindClass / FxStubBindClasses   ; KMDF class binding
             …  WdfDriverCreate                            ; via WdfVersionBind result
             …  call 0x140005860                          ; ← create the control device
```

Failure paths print through `DbgPrintEx` (`"DriverEntry failed 0x%x for driver
%wZ"`, `"FxStubBindClasses: VersionBindClass …"`, `"FxGetNextClassBindInfo
failed"` …). The driver is therefore a **legitimately structured KMDF driver**
whose vendor framework wrapper has been left in place while the functional part
is hand-written WDM.

## 5. Device, dispatch table and unload

`0x140005860` (`CreateDevice`) — the IOCTL surface:

```
0x140005860:  allocate copies of the device + symlink names
              (ExAllocatePoolWithTag, tags "GDmN" = 0x4E6D4447, "GSmL" = 0x4C6D5347)
              DriverObject->MajorFunction[ 0] = 0x140005670   ; IRP_MJ_CREATE
              DriverObject->MajorFunction[ 2] = 0x140005670   ; IRP_MJ_CLOSE
              DriverObject->MajorFunction[14] = 0x1400056A0   ; IRP_MJ_DEVICE_CONTROL
              DriverObject->DriverUnload      = 0x140005A60
              IoCreateDevice(DriverObject, 0, &DeviceName, 0x22 /*FILE_DEVICE_UNKNOWN*/,
                             FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject)
              IoCreateSymbolicLink(&SymLink, &DeviceName)
```

| Function | Role |
|---|---|
| `0x140005670` (46 B) | create/close handler: `IofCompleteRequest(irp, 0)` + `STATUS_SUCCESS` |
| `0x1400056A0` (442 B) | **IOCTL dispatcher** |
| `0x140005A60` (199 B) | unload: `IoDeleteSymbolicLink`, `IoDeleteDevice`, frees both name buffers |
| `0x140005560` (271 B) | helper: build `UNICODE_STRING` from `{len, payload}` template via `ExAllocatePoolWithTag` + `RtlInitUnicodeString` |

## 6. IOCTL interface

Decoded from `0x1400056A0` (`IoControlCode` at `DeviceIoControl` params + 0x18):

| IOCTL | Device | Function | Method | Access | Handler |
|---|---|---|---|---|---|
| `0x222004` | `0x22` | `0x801` | `METHOD_BUFFERED` | `FILE_WRITE_ACCESS` | allocate a pool buffer (tag `x46d` = `0x64363478`) of `InputBuffer+8` bytes, copy the input, then call `0x140001D50` → **engine `0x140002400`** |
| `0x222024` | `0x22` | `0x809` | `METHOD_BUFFERED` | `FILE_WRITE_ACCESS` | `RtlInitUnicodeString(input buffer)` → **delete arbitrary file** (`0x140005B30`) |

Anything else returns `STATUS_INVALID_DEVICE_REQUEST` (`0xC0000010`); a NULL
input buffer returns `STATUS_INVALID_PARAMETER` (`0xC000000D`).

### 6.1 `0x222024` — forced deletion of a locked file (`0x140005B30`)

```
KeGetCurrentIrql()                       ; refuse at raised IRQL
ZwCreateFile(&h, 0x110100, &objattr{path from user}, …, FILE_SHARE_*, FILE_OPEN, …)
ObReferenceObjectByHandle(h, 0, IoFileObjectType, KernelMode, &fileObject, NULL)
   fileObject->SectionObjectPointer-><field at +0x28> = 0   ; drop the section/cache ref
   fileObject->DeleteAccess (offset 0x4C) = TRUE
ZwDeleteFile(&objattr)
ObfDereferenceObject(fileObject); ZwClose(h)
```

This is the well-known **"delete a file that is in use"** trick: clearing the
section-object pointer removes the mapped-image/cache reference so the
kernel-side delete succeeds even when user mode holds the file open with
`FILE_SHARE_READ` or the image is mapped. Practical impact: the loader can
delete *its own dropped driver at runtime*, and could equally delete EAC/game
files or evidence — a destructive/anti-forensic primitive that needs
**no** user-mode privileges beyond opening the device.

### 6.2 `0x222004` — the memory engine

Request layout used by the dispatcher (from the field accesses at
`0x1400056CA`…`0x1400057AA`):

```
struct kdrv_request {          // InputBuffer (METHOD_BUFFERED)
    uint32_t pid;              // +0x00
    uint32_t size;             // +0x08   (allocation size)
    void    *user_buffer;      // +0x10   (copied with rep movsb)
    uint32_t size2;            // +0x18
    uint32_t magic;            // +0x1C?  -> compared against 0x2AFBBBDC
};
```

`0x140001D50` forwards to `0x140002400` (11,895 bytes — the largest function in
the image). Head of the engine:

```
PsLookupProcessByProcessId(pid, &process)          ; 0x14000245C
if (*(uint32_t *)magic_ptr != 0x2AFBBBDC)          ; 0x140002488
        return STATUS_ACCESS_DENIED (0xC0000022)   ; 0x140002491
KeStackAttachProcess(process, &apc_state)          ; 0x1400024B2
PsGetProcessWow64Process(process)                  ; 0x1400024C0
… (PEB walk, memory copy, module lookup, patch helpers) …
KeUnstackDetachProcess(&apc_state)                 ; 0x140005255
ObfDereferenceObject(process)                      ; 0x140005263
```

The value **`0x2AFBBBDC`** is a hard-coded authorisation magic that the user-mode
loader must supply — a cheap "licence/authenticity" gate inside the driver.

## 7. Engine primitives (address map)

| Address | Size | Primitive |
|---|---|---|
| `0x140001060` | 173 B | `MmAllocatePagesForMdlEx` + `MmProtectMdlSystemAddress` — allocate non-paged physical pages and mark them executable/read-write |
| `0x140001110`, `0x1400015F0`, `0x140001660`, `0x1400020C0` | — | `MmIsAddressValid` probes — safe probing of arbitrary kernel VAs before touching them |
| `0x140001320` | 271 B | `ExAllocatePoolWithTag` + `RtlInitUnicodeString` — build a `UNICODE_STRING` (used for the `\device\physicalmemory` open) |
| `0x140001750`–`0x1400019D1` | 641 B | page-table / PTE helpers (see §8) |
| `0x140001B30` | 539 B | `PsGetProcessPeb` / `PsGetProcessWow64Process` + `RtlCompareUnicodeString` + `KeDelayExecutionThread` → **resolve a module base by name** (PEB → `Ldr` → `InLoadOrderModuleList`), with retry/sleep |
| `0x140001D80` | 113 B | scans memory for the 64-bit marker `0x1122334455667788` and **overwrites it** with a supplied value (patch/replace helper) |
| `0x140001E00` | 294 B | **builds a 10-byte code stub** in a stack buffer (`48 8B 04 D0` `mov rax,[rax+rdx*8]` / `48 C1 E0 19` `shl rax,0x19` / `48 BA imm64`) and locates it with `RtlCompareMemory` — computes a VA from a page-table index based at the kernel PTE base `0xFFFFF68000000000` |
| `0x140001F30` | 229 B | **CR3 → PML4 walk**: reads `%cr3`, maps that physical page, scans 512 entries for the self-reference entry, returns `(index + 0x1FFFE00) << 0x27` — the well-known "self-map any physical page into kernel VA" trick |
| `0x140002160` | 164 B | `IoAllocateMdl` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache(…, 1, 1, …)` → map an arbitrary **physical range** into system space |
| `0x140002210` | 493 B | `ZwOpenSection("\device\physicalmemory", 0xF001F)` + `ZwMapViewOfSection` → map physical memory directly; unmaps with `ZwUnmapViewOfSection` (`0x140001F30` companion) |
| `0x140005280` | 85 B | `MmMapLockedPagesSpecifyCache` wrapper (`MDL`, `AccessMode`, `CacheType`) |
| `0x1400054C0` | 158 B | `ZwAllocateVirtualMemory` wrapper (allocate inside the attached process) |
| `0x140005D22` | — | tail-jump to `ZwProtectVirtualMemory` (change page protections of the target) |
| `0x140005480` | 59 B | `KeDelayExecutionThread` (retry helper) |

Pool tags used: **`GDmN`** (`0x4E6D4447`), **`GSmL`** (`0x4C6D5347`),
**`PyPh`** (`0x68507950`), **`x46d`** (`0x64363478`).

## 8. What this driver is, in one paragraph

It is a **KMDF-signed "hardware support" driver repurposed as a kernel memory
service**. It exposes a single device (`\\.\mLnUcWtv9IaZf8LBiMXD`, type 0x22)
with two IOCTLs: one that attaches to any process (`PsLookupProcessByProcessId` +
`KeStackAttachProcess`) and, after a magic handshake (`0x2AFBBBDC`), gives the
caller kernel-side read/write/patch/protection primitives including physical
memory access through `\device\physicalmemory`, MDL mapping and a CR3/PML4
self-map; and one that force-deletes any file the caller names, defeating
in-use locks. Because the driver carries a valid WHQL signature it loads on
standard Windows with driver-signature-enforcement intact — the definition of a
**BYOVD** component. It is what lets the user-mode loader read and patch
`FortniteClient-Win64-Shipping.exe` without `OpenProcess` ever failing, and
delete its own artefacts afterwards.

## 9. Detection

* YARA: `yara/linou_free.yar` — rule `Embeded_WHQL_Kernel_Driver_PAutel_BYOVD`
  matches the XOR-encoded device names, the KMDF imports and the WHQL/vendor
  strings.
* Sysmon EID 6: `\Driver\mLnUcWtv9IaZf8LBiMXD` / symbolic link
  `\DosDevices\mLnUcWtv9IaZf8LBiMXD` (event 6 logs the driver image + its
  `\Device\…` name).
* Sysmon EID 11: driver image written to `%TEMP%`; EID 12/13/14: service key
  with `ImagePath` = `\??\%TEMP%\…`, `Type` = 1.
* Any user-mode process opening `\\.\mLnUcWtv9IaZf8LBiMXD`, sending
  `IOCTL 0x222004` / `IOCTL 0x222024`, or mapping `\device\physicalmemory`.
* Driver blocklist: add the SHA-256 above (or the PAutel vendor cert) to the
  Windows vulnerable-driver blocklist / WDAC policy; HVCI on.

## 10. Method / limitations

* Disassembly: `objdump -d --no-show-raw-insn` on the extracted blob
  (`tools/triage.py --extract` writes it to `analysis/extracted/`), plus
  `.pdata` parsing for function boundaries and the import-thunk table for
  xrefs (`call *0x…(%rip) # 0x1400070…`).
* Strings: `bytes(b ^ 0xAA for b in payload).decode('utf-16-le')`.
* The 11.9 KB engine (`0x140002400`) was characterised by its imports, its
  magic/handshake, its attach/detach sequence and its callers; it was **not**
  decompiled statement by statement. A decompiler (IDA/Ghidra/Binary Ninja)
  would yield the exact request struct and the individual read/write ops —
  that is the recommended next step if you need byte-level IOCs for specific
  operations.
* The driver's signature was parsed, not validated against a live trust store;
  a timestamped WHQL signature remains valid after the leaf certificate expires
  (2026-02-18), so the driver can still load unless it is blocklisted.
