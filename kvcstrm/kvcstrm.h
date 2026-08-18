#pragma once
#include <ntifs.h>
#include <wdf.h>

// =============================================================
// EXTERNAL PROTOTYPES
// =============================================================

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize
);

// =============================================================
// PROCESS ACCESS RIGHTS (not exposed in kernel-mode ntifs.h)
// =============================================================

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

// =============================================================
// DEVICE NAMES
// =============================================================

#define DEVICE_NAME   L"\\Device\\kvcstrm"
#define SYMBOLIC_NAME L"\\DosDevices\\kvcstrm"
#define POOL_TAG      'inmO'

// =============================================================
// IOCTL DEFINITIONS
// =============================================================

// --- Virtual memory R/W (existing, unchanged) ---
#define IOCTL_READWRITE_DRIVER_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READWRITE_DRIVER_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READWRITE_DRIVER_BULK  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// --- New operations ---
#define IOCTL_KILL_PROCESS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL_PROCESS_WESMAR   0x22201C
#define IOCTL_SET_PROTECTION         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PHYSMEM_READ           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PHYSMEM_WRITE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOC_KERNEL           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_KERNEL            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_PROTECTED        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ELEVATE_TOKEN          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

// --- Advanced "Bank-grade" operations ---
#define IOCTL_KILL_BY_NAME           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FORCE_CLOSE_HANDLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CALL_KERNEL            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

// =============================================================
// LIMITS
// =============================================================

#define MAX_TRANSFER_SIZE    (PAGE_SIZE * 256)  // 1 MB  - virtual R/W cap
#define MAX_BULK_OPERATIONS  64
#define MAX_PHYSMEM_SIZE     (PAGE_SIZE * 64)   // 256 KB - physical R/W cap
#define MAX_PROCESS_NAME     16                 // EPROCESS ImageFileName length

// =============================================================
// ALLOC FLAGS  (IOCTL_ALLOC_KERNEL)
// =============================================================

#define OMNI_ALLOC_NONPAGED          0x00   // Non-paged, not executable
#define OMNI_ALLOC_NONPAGED_EXECUTE  0x01   // Non-paged + executable (for shellcode/patches)

// =============================================================
// STRUCTURES
// =============================================================

// --- Kill by name (IOCTL_KILL_BY_NAME) ---
typedef struct _KERNEL_KILL_NAME_REQUEST {
    char     ProcessName[MAX_PROCESS_NAME]; // e.g. "notepad.exe"
    ULONG    KilledCount;                   // Output: number of processes killed
    NTSTATUS Status;
} KERNEL_KILL_NAME_REQUEST, *PKERNEL_KILL_NAME_REQUEST;

// --- Force Close Handle (IOCTL_FORCE_CLOSE_HANDLE) ---
typedef struct _KERNEL_CLOSE_HANDLE_REQUEST {
    ULONG    ProcessId;     // PID of process holding the handle
    HANDLE   HandleValue;   // The handle value to close
    NTSTATUS Status;
} KERNEL_CLOSE_HANDLE_REQUEST, *PKERNEL_CLOSE_HANDLE_REQUEST;

// --- Kernel call primitive (IOCTL_CALL_KERNEL) ---
//
// Calls Address as a four-argument x64 function: Args[0..3] → RCX/RDX/R8/R9.
// Executes at PASSIVE_LEVEL.  ReturnValue receives the 64-bit return value.
//
// *** RAW PRIMITIVE -- caller owns all preconditions ***
//
// The driver checks only that Address is in kernel canonical space and is
// currently mapped.  It does NOT validate prototype, IRQL contract, process
// context, lock state, or any other calling convention requirement.
// __try/__except catches hardware faults on the call site; it does NOT
// protect against bugchecks, IRQL violations, deadlocks, or state corruption
// triggered inside the callee.
//
// Caller responsibilities:
//   - Match the actual function prototype (argument count and types).
//   - Ensure correct IRQL before issuing the IOCTL.
//   - Establish required process attachment / APC state as needed.
//   - Hold any locks or object references the target routine expects.
//   - Use OMNI_ALLOC_NONPAGED_EXECUTE for shellcode targets so pages are
//     always resident and marked executable.
//
// Typical use cases:
//   - Calling exported kernel routines by address (PDB-resolved or via
//     MmGetSystemRoutineAddress).
//   - Executing shellcode in a POOL_FLAG_NON_PAGED_EXECUTE buffer obtained
//     via IOCTL_ALLOC_KERNEL (Flags = OMNI_ALLOC_NONPAGED_EXECUTE).

typedef struct _KERNEL_CALL_REQUEST {
    ULONG64  Address;       // Kernel virtual address to call
    ULONG64  Args[4];       // Arguments: RCX, RDX, R8, R9 (unused slots = 0)
    ULONG64  ReturnValue;   // Filled by driver: return value from the call
    NTSTATUS Status;
} KERNEL_CALL_REQUEST, *PKERNEL_CALL_REQUEST;

// --- Virtual memory R/W (existing, unchanged) ---

typedef struct _KERNEL_READWRITE_REQUEST {
    ULONG    ProcessId;     // Target PID
    ULONG64  Address;       // Target virtual address
    ULONG64  Buffer;        // Usermode buffer address
    SIZE_T   Size;          // Bytes to transfer
    BOOLEAN  Write;         // TRUE = write to target, FALSE = read from target
    NTSTATUS Status;        // Operation result (filled by driver)
} KERNEL_READWRITE_REQUEST, *PKERNEL_READWRITE_REQUEST;

typedef struct _KERNEL_BULK_OPERATION {
    ULONG                    Count;
    KERNEL_READWRITE_REQUEST Operations[MAX_BULK_OPERATIONS];
} KERNEL_BULK_OPERATION, *PKERNEL_BULK_OPERATION;

// --- Kill process (IOCTL_KILL_PROCESS) ---
//
// Driver calls ZwTerminateProcess via a kernel handle opened with
// ObOpenObjectByPointer.  Bypasses user-mode callbacks and PPL.

typedef struct _KERNEL_KILL_REQUEST {
    ULONG    ProcessId;
    NTSTATUS Status;
} KERNEL_KILL_REQUEST, *PKERNEL_KILL_REQUEST;

// --- PP/PPL manipulation (IOCTL_SET_PROTECTION) ---
//
// Writes one byte to EPROCESS at ProtectionOffset.
// EPROCESS is in non-paged pool so the byte is always writable.
//
// ProtectionOffset: PDB-resolved on the usermode side and passed in.
//   e.g. Win11 26200 = 0x87A
//
// Common ProtectionValue values:
//   0x00 - unprotected
//   0x62 - PPL Antimalware  (Type=2, Signer=6)
//   0x72 - PP  Antimalware  (Type=2, Signer=7)
//   0x61 - PPL Windows      (Type=1, Signer=6)

typedef struct _KERNEL_PROTECTION_REQUEST {
    ULONG    ProcessId;
    ULONG64  ProtectionOffset;  // Offset of PS_PROTECTION byte in EPROCESS
    UCHAR    ProtectionValue;   // Value to write
    UCHAR    Padding[3];
    NTSTATUS Status;
} KERNEL_PROTECTION_REQUEST, *PKERNEL_PROTECTION_REQUEST;

// --- Physical memory R/W (IOCTL_PHYSMEM_READ / IOCTL_PHYSMEM_WRITE) ---
//
// Buffer: usermode virtual address in the calling process.
//   READ:  driver maps physical range, copies to usermode buffer.
//   WRITE: driver maps physical range, copies from usermode buffer.

typedef struct _KERNEL_PHYSMEM_REQUEST {
    ULONG64  PhysicalAddress;
    ULONG64  Buffer;        // Usermode buffer address
    SIZE_T   Size;          // Must be <= MAX_PHYSMEM_SIZE
    NTSTATUS Status;
} KERNEL_PHYSMEM_REQUEST, *PKERNEL_PHYSMEM_REQUEST;

// --- Kernel memory allocation (IOCTL_ALLOC_KERNEL) ---
//
// Allocates non-paged kernel memory and returns its virtual address.
// The caller is responsible for freeing it via IOCTL_FREE_KERNEL.

typedef struct _KERNEL_ALLOC_REQUEST {
    SIZE_T   Size;          // Bytes to allocate
    ULONG    Flags;         // OMNI_ALLOC_* flags
    ULONG64  Address;       // Returned: allocated kernel virtual address
    NTSTATUS Status;
} KERNEL_ALLOC_REQUEST, *PKERNEL_ALLOC_REQUEST;

// --- Kernel memory free (IOCTL_FREE_KERNEL) ---

typedef struct _KERNEL_FREE_REQUEST {
    ULONG64  Address;       // Address returned by a previous IOCTL_ALLOC_KERNEL
    NTSTATUS Status;
} KERNEL_FREE_REQUEST, *PKERNEL_FREE_REQUEST;

// --- Write to read-only kernel memory (IOCTL_WRITE_PROTECTED) ---
//
// Temporarily clears CR0.WP, writes, restores CR0.WP.
// HVCI must be OFF (which is guaranteed if this driver loaded at all).
//
// Input buffer layout:
//   [KERNEL_PROTECTED_WRITE_REQUEST header][data bytes ...]
//   Total input length = sizeof(header) + Size

typedef struct _KERNEL_PROTECTED_WRITE_REQUEST {
    ULONG64  DstAddress;    // Target kernel virtual address (read-only page)
    SIZE_T   Size;          // Bytes to write
    NTSTATUS Status;
    // Data bytes follow immediately after this struct in the input buffer.
} KERNEL_PROTECTED_WRITE_REQUEST, *PKERNEL_PROTECTED_WRITE_REQUEST;

// --- SYSTEM token steal (IOCTL_ELEVATE_TOKEN) ---
//
// Replaces the primary token of ProcessId with the SYSTEM token from
// PsInitialSystemProcess.  After this call the target process runs with
// full NT AUTHORITY\SYSTEM privileges.
//
// TokenOffset: PDB-resolved on the usermode side and passed in.
//   e.g. Win11 26200 = 0x4B8
//
// Token field is EX_FAST_REF (lower 4 bits = reference count).
// We clear those bits when reading from SYSTEM, write the clean pointer.

typedef struct _KERNEL_TOKEN_REQUEST {
    ULONG    ProcessId;
    ULONG64  TokenOffset;   // Offset of Token (EX_FAST_REF) in EPROCESS
    NTSTATUS Status;
} KERNEL_TOKEN_REQUEST, *PKERNEL_TOKEN_REQUEST;
