OmniDriver
==========

Overview
- OmniDriver is an internal NT/KMDF control driver.
- It exposes a buffered IOCTL device for process, memory, token, handle, and protection operations used by the trusted test client.
- The default queue is sequential and the I/O model is METHOD_BUFFERED.
- The driver is intended for controlled lab use, not for public deployment.

Current project layout
- Root-level files intentionally kept in the project root:
  build.ps1
  sign.ps1
  trust.ps1
  ReadMe.txt
- Source tree:
  src\
- Final build artifacts:
  bin\
- Signing material:
  cert\

Device names
- NT device: \\Device\\OmniDriver
- Win32/DOS path: \\\\.\\OmniDriver

Access control
- Device access is restricted by SDDL to SYSTEM and local Administrators.
- SDDL in code: D:P(A;;GA;;;SY)(A;;GA;;;BA)
- The IOCTL definitions use FILE_ANY_ACCESS, but the device ACL is the real access boundary.
- In practice the client should run as Administrator or LocalSystem.

Important interface limits
- MAX_TRANSFER_SIZE: 1 MB
- MAX_BULK_OPERATIONS: 64
- MAX_PHYSMEM_SIZE: 256 KB
- MAX_PROCESS_NAME: 16 bytes including the trailing NUL
- The driver uses METHOD_BUFFERED, so the same buffer is used for input and output.
- For most IOCTLs the real operation result is returned in the Status field inside the request structure.
- Legacy exception: IOCTL_KILL_PROCESS_WESMAR returns the operation status directly as the request status.

IOCTL summary
- IOCTL_READWRITE_DRIVER_READ, function 0x800, struct KERNEL_READWRITE_REQUEST
  Reads virtual memory from the target process.
- IOCTL_READWRITE_DRIVER_WRITE, function 0x801, struct KERNEL_READWRITE_REQUEST
  Writes virtual memory to the target process.
- IOCTL_READWRITE_DRIVER_BULK, function 0x802, struct KERNEL_BULK_OPERATION
  Executes a batch of read/write requests.
- IOCTL_KILL_PROCESS, function 0x803, struct KERNEL_KILL_REQUEST
  Terminates the target PID.
- IOCTL_KILL_PROCESS_WESMAR, code 0x22201C, input ULONG PID
  Legacy compatibility path for the previous client.
- IOCTL_SET_PROTECTION, function 0x804, struct KERNEL_PROTECTION_REQUEST
  Writes the protection byte in EPROCESS.
- IOCTL_PHYSMEM_READ, function 0x805, struct KERNEL_PHYSMEM_REQUEST
  Reads a physical memory range.
- IOCTL_PHYSMEM_WRITE, function 0x806, struct KERNEL_PHYSMEM_REQUEST
  Writes a physical memory range.
- IOCTL_FREE_KERNEL, function 0x808, struct KERNEL_FREE_REQUEST
  Frees an address previously returned by driver allocation.
- IOCTL_WRITE_PROTECTED, function 0x809, struct KERNEL_PROTECTED_WRITE_REQUEST plus trailing payload
  Writes to read-only kernel memory using the payload appended after the header.
- IOCTL_ELEVATE_TOKEN, function 0x80A, struct KERNEL_TOKEN_REQUEST
  Replaces the target primary token with the SYSTEM token.
- IOCTL_ALLOC_KERNEL, function 0x80B, struct KERNEL_ALLOC_REQUEST
  Allocates kernel memory.
- IOCTL_KILL_BY_NAME, function 0x810, struct KERNEL_KILL_NAME_REQUEST
  Terminates matching processes by image name prefix.
- IOCTL_FORCE_CLOSE_HANDLE, function 0x811, struct KERNEL_CLOSE_HANDLE_REQUEST
  Closes a handle in the target process handle table.

Call contract and debugging notes
- If an IOCTL is recognized and the input size is valid, DeviceIoControl usually completes successfully at the request level and the real operation result is written to the Status field inside the request structure.
- For IOCTL_KILL_PROCESS_WESMAR the real operation result is returned directly as the request status, without an output structure.
- For READ, WRITE, KILL, SET_PROTECTION, PHYSMEM, ALLOC, FREE, WRITE_PROTECTED, ELEVATE_TOKEN, KILL_BY_NAME, and FORCE_CLOSE_HANDLE, bytesReturned equals the request structure size.
- For READWRITE_DRIVER_BULK, bytesReturned equals InputBufferLength.
- For IOCTL_KILL_PROCESS_WESMAR, bytesReturned is 0.
- READWRITE_DRIVER_WRITE overwrites Write to TRUE before execution, and READWRITE_DRIVER_READ overwrites Write to FALSE before execution.
- READWRITE_DRIVER_BULK stores Status per sub-operation. The bulk request status is the first failure seen, otherwise STATUS_SUCCESS.
- WRITE_PROTECTED requires one contiguous input buffer: [KERNEL_PROTECTED_WRITE_REQUEST][payload bytes].
- KILL_BY_NAME overwrites the last byte of ProcessName with NUL and treats the name as at most 15 characters plus NUL.
- SET_PROTECTION and ELEVATE_TOKEN reject offsets outside the range 1..0x2000.
- Typical request-level or Status-field errors are STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_INVALID_DEVICE_REQUEST, and on selected paths STATUS_INVALID_ADDRESS.

Request structures
- KERNEL_READWRITE_REQUEST
  Fields: ProcessId, Address, Buffer, Size, Write, Status
- KERNEL_BULK_OPERATION
  Fields: Count, Operations[MAX_BULK_OPERATIONS]
- KERNEL_KILL_REQUEST
  Fields: ProcessId, Status
- KERNEL_PROTECTION_REQUEST
  Fields: ProcessId, ProtectionOffset, ProtectionValue, Status
- KERNEL_PHYSMEM_REQUEST
  Fields: PhysicalAddress, Buffer, Size, Status
- KERNEL_ALLOC_REQUEST
  Fields: Size, Flags, Address, Status
- KERNEL_FREE_REQUEST
  Fields: Address, Status
- KERNEL_PROTECTED_WRITE_REQUEST
  Fields: DstAddress, Size, Status
  Input layout: [header][payload]
- KERNEL_TOKEN_REQUEST
  Fields: ProcessId, TokenOffset, Status
- KERNEL_KILL_NAME_REQUEST
  Fields: ProcessName[16], KilledCount, Status
- KERNEL_CLOSE_HANDLE_REQUEST
  Fields: ProcessId, HandleValue, Status

Notes for testers
- Use only the approved client application.
- Check both the DeviceIoControl result and the Status field inside the request structure.
- For IOCTL_WRITE_PROTECTED the input buffer must contain the structure plus a payload of Size bytes.
- For IOCTL_SET_PROTECTION and IOCTL_ELEVATE_TOKEN the offset must be in the range 1..0x2000, otherwise the request is rejected.
- For IOCTL_KILL_BY_NAME the image name is limited to 15 characters plus NUL.
- For bulk operations each sub-operation has its own Status field.
- For IOCTL_ALLOC_KERNEL the Flags field is bit-based. If bit 0x01 is set, the allocation is non-paged executable. If bit 0x01 is clear, the allocation is non-paged and non-executable. The maximum allocation size is 16 MB.
- The address returned by IOCTL_ALLOC_KERNEL must be freed through IOCTL_FREE_KERNEL. Freeing an address outside the driver's allocation list, or double-free, returns STATUS_INVALID_PARAMETER without modifying memory.
- IOCTL_KILL_BY_NAME matches from the start of the image name with strnicmp. It does not search for substrings in the middle. It terminates every process that matches. KilledCount reports how many processes were actually terminated. STATUS_SUCCESS is still returned when KilledCount is 0.
- IOCTL_FORCE_CLOSE_HANDLE closes a handle in the target process handle table. HandleValue must be a handle opened in that target process, not in the calling process.
- IOCTL_PHYSMEM_READ and IOCTL_PHYSMEM_WRITE validate the requested range against MmGetPhysicalMemoryRanges. If the range is outside normal RAM, STATUS_INVALID_ADDRESS is returned and no mapping is attempted. If MmGetPhysicalMemoryRanges returns NULL, validation is skipped and mapping continues.
- Buffer in KERNEL_READWRITE_REQUEST and KERNEL_PHYSMEM_REQUEST is a user-mode virtual address in the caller process, not a kernel address.

Build
- The project builds from src\OmniDriver.vcxproj.
- Run:
  powershell -ExecutionPolicy Bypass -File .\build.ps1
- build.ps1 locates the newest installed Visual Studio 2026 (18.x) instance automatically.
- The script prepares a clean bin\ directory, builds the Release|x64 KMDF driver, copies only the final package files, and removes intermediate build directories by default.
- Final output files in bin\:
  OmniDriver.sys
  OmniDriver.inf
  omnidriver.cat
- build.ps1 sets SOURCE_DATE_EPOCH and applies a fixed file timestamp of 2030-01-01 00:00:00 to the staged files.
- The project enables /BREPRO on the linker, but the stamped INF version still depends on the actual build moment unless StampInf is later pinned to a fixed DriverVer value.

Signing
- sign.ps1 is for local lab signing only.
- The current workflow creates a self-signed root CA and a self-signed embedded code-signing certificate.
- This does not emulate Microsoft trust. It only creates a local SHA-256 embedded signature for testing.
- The default certificate display name is:
  Microsoft Windows OS
- Run once to create the certificate material:
  powershell -ExecutionPolicy Bypass -File .\sign.ps1 -Create
- Optional custom name:
  powershell -ExecutionPolicy Bypass -File .\sign.ps1 -Create -Name "Microsoft Windows OS"
- Recreate an existing set:
  powershell -ExecutionPolicy Bypass -File .\sign.ps1 -Create -Force
- Sign the current unsigned driver from bin\:
  powershell -ExecutionPolicy Bypass -File .\sign.ps1
- Optional custom timestamp:
  powershell -ExecutionPolicy Bypass -File .\sign.ps1 -Timestamp "2030-01-01 00:00:00"
- Signing output:
  bin\OmniDriver_Signed.sys
- sign.ps1 writes an embedded SHA-256 signature only.
- No catalog signing step is required for the current sc create installation workflow.
- Certificate material stored in cert\:
  <name>-root.cer
  <name>-signing.cer
  <name>-signing.pfx
  <name>-signing.pwd
  signing.config.json
- sign.ps1 also applies the fixed timestamp 2030-01-01 00:00:00 to the signed driver and generated certificate files by default.

Trust note
- A self-signed embedded signature is expected to appear as untrusted until the generated root certificate is imported into a trusted root store on the test machine.
- This is normal for the current lab workflow.
- trust.ps1 imports the generated certificates into the appropriate certificate stores.
- Default command:
  powershell -ExecutionPolicy Bypass -File .\trust.ps1
- Default behavior imports:
  <name>-root.cer -> LocalMachine\Root
  <name>-signing.cer -> LocalMachine\TrustedPublisher
- Current-user only import:
  powershell -ExecutionPolicy Bypass -File .\trust.ps1 -CurrentUser
- Remove previously imported trust entries:
  powershell -ExecutionPolicy Bypass -File .\trust.ps1 -Remove

Installation note
- The current expected install path is service-based loading, for example through sc create.
- For that workflow the embedded signature on OmniDriver_Signed.sys is the relevant artifact.
- The INF and CAT are still built and kept in bin\ because the KMDF packaging step already produces them and they may still be useful later.
