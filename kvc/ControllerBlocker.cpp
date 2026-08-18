// ControllerBlocker.cpp
// kvcblocker.sys (minifilter, service: clrcd, altitude 389991) lifecycle
// management and IOCTL wrappers.
//
// All extern "C" functions are called directly from vg\handlers.asm and
// vg\listview.asm - names and calling convention must match exactly.

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

// Globals defined in vg\main.asm
extern "C" DWORD g_driverInstalled;
extern "C" DWORD g_driverRunning;

// Status buffer - declared EXTERN in vg\handlers.asm
extern "C" BYTE g_statusResult[16] = {};

// 64 KB IOCTL enum buffer - defined in vg\main.asm .data?
extern "C" BYTE  g_ioBuf[];

// Internal device handle
static HANDLE s_hDevice = INVALID_HANDLE_VALUE;

static constexpr wchar_t BLOCKER_DEVICE[] =
    L"\\\\.\\BE79F7D853E643089D51EDCDA79805C4";

static constexpr wchar_t BLOCKER_SVC[]      = L"clrcd";
static constexpr wchar_t BLOCKER_ALTITUDE[] = L"389991";
static constexpr wchar_t BLOCKER_GROUP[]    = L"FSFilter Content Screener";

static constexpr wchar_t BLOCKER_INST_KEY[] =
    L"SYSTEM\\CurrentControlSet\\Services\\clrcd\\Instances";
static constexpr wchar_t BLOCKER_INST_SUB[] =
    L"SYSTEM\\CurrentControlSet\\Services\\clrcd\\Instances\\clrcd";

// DOS -> NT path conversion
static bool DosToNtPath(const WCHAR* dos, WCHAR* nt, DWORD ntChars) noexcept {
    if (!dos || wcslen(dos) < 3 || dos[1] != L':')
        return false;
    WCHAR drv[3] = { dos[0], L':', 0 };
    WCHAR dev[MAX_PATH] = {};
    if (!QueryDosDeviceW(drv, dev, MAX_PATH))
        return false;
    const WCHAR* suf = dos + 2;
    if (wcslen(dev) + wcslen(suf) + 1 > ntChars)
        return false;
    wcscpy_s(nt, ntChars, dev);
    wcscat_s(nt, ntChars, suf);
    DWORD len = static_cast<DWORD>(wcslen(nt));
    if (len > 0 && nt[len - 1] == L'\\')
        nt[len - 1] = L'\0';
    return true;
}

// Device lifecycle

extern "C" INT_PTR OpenDevice() noexcept {
    if (s_hDevice != INVALID_HANDLE_VALUE)
        return 1;
    s_hDevice = CreateFileW(BLOCKER_DEVICE,
                            GENERIC_READ | GENERIC_WRITE,
                            0, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (s_hDevice != INVALID_HANDLE_VALUE) {
        g_driverInstalled = 1;
        g_driverRunning   = 1;
        return 1;
    }
    return 0;
}

extern "C" void CloseDevice() noexcept {
    if (s_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(s_hDevice);
        s_hDevice = INVALID_HANDLE_VALUE;
    }
}

extern "C" INT_PTR EnsureDriverReady() noexcept {
    return OpenDevice();
}

// IOCTL wrappers

extern "C" INT_PTR IoctlSetActive(DWORD active) noexcept {
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    DWORD flag = active;
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C40241C,
                           &flag, sizeof(flag),
                           nullptr, 0, &ret, nullptr) ? 1 : 0;
}

extern "C" INT_PTR IoctlGetStatus() noexcept {
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C402420,
                           nullptr, 0,
                           g_statusResult, 16, &ret, nullptr) ? 1 : 0;
}

extern "C" INT_PTR IoctlAddPath(DWORD flags, const WCHAR* dosPath) noexcept {
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    static BYTE buf[0x6414];
    ZeroMemory(buf, sizeof(buf));
    *reinterpret_cast<DWORD*>(buf) = flags;
    WCHAR* ntDst = reinterpret_cast<WCHAR*>(buf + 4);
    if (!DosToNtPath(dosPath, ntDst, (sizeof(buf) - 4) / sizeof(WCHAR)))
        return 0;
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C402400,
                           buf, sizeof(buf),
                           nullptr, 0, &ret, nullptr) ? 1 : 0;
}

extern "C" INT_PTR IoctlRemovePath(const WCHAR* dosPath) noexcept {
    return IoctlAddPath(0, dosPath);
}

extern "C" INT_PTR IoctlAddTrusted(const WCHAR* name) noexcept {
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    static BYTE rec[0xD94];
    ZeroMemory(rec, sizeof(rec));
    WCHAR* dst = reinterpret_cast<WCHAR*>(rec + 4);
    wcsncpy_s(dst, (sizeof(rec) - 4) / sizeof(WCHAR), name, _TRUNCATE);
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C402408,
                           rec, sizeof(rec),
                           nullptr, 0, &ret, nullptr) ? 1 : 0;
}

extern "C" INT_PTR IoctlRemoveTrusted(const WCHAR* /*name*/) noexcept {
    // Zero-size input = driver clears all trusted entries.
    // Caller reloads remaining from registry via ConfigLoad().
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C402408,
                           nullptr, 0,
                           nullptr, 0, &ret, nullptr) ? 1 : 0;
}

extern "C" INT_PTR IoctlEnumPaths() noexcept {
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C402404,
                           nullptr, 0,
                           g_ioBuf, 65536, &ret, nullptr) ? 1 : 0;
}

extern "C" INT_PTR IoctlEnumTrusted() noexcept {
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C40240C,
                           nullptr, 0,
                           g_ioBuf, 65536, &ret, nullptr) ? 1 : 0;
}

extern "C" INT_PTR IoctlClearAll() noexcept {
    if (s_hDevice == INVALID_HANDLE_VALUE && !OpenDevice())
        return 0;
    DWORD ret = 0;
    return DeviceIoControl(s_hDevice, 0x9C402424,
                           nullptr, 0,
                           nullptr, 0, &ret, nullptr) ? 1 : 0;
}

// Minifilter altitude registry setup
static void SetupBlockerAltitude(const std::wstring& svcName) noexcept {
    HKEY hKey = nullptr;
    DWORD disp = 0;
    // HKLM\...\Services\clrcd\Instances -> DefaultInstance = "clrcd"
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, BLOCKER_INST_KEY,
                        0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, nullptr, &hKey, &disp) == ERROR_SUCCESS) {
        const wchar_t* def = svcName.c_str();
        RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(def),
                       static_cast<DWORD>((wcslen(def) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    // HKLM\...\Services\clrcd\Instances\clrcd -> Altitude + Flags
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, BLOCKER_INST_SUB,
                        0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, nullptr, &hKey, &disp) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"Altitude", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(BLOCKER_ALTITUDE),
                       static_cast<DWORD>((wcslen(BLOCKER_ALTITUDE) + 1) * sizeof(wchar_t)));
        DWORD flags = 0;
        RegSetValueExW(hKey, L"Flags", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&flags), sizeof(flags));
        RegCloseKey(hKey);
    }
}

// Controller methods

bool Controller::EnsureBlockerDriver() noexcept {
    // Try to open device first (driver already running)
    if (OpenDevice())
        return true;

    const std::wstring driverPath = GetDriverStorePath() + L"\\kvcblocker.sys";
    if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"kvcblocker.sys not found in DriverStore - run 'kvc list' first");
        return false;
    }

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        ERROR(L"Failed to open SCM: %lu", GetLastError());
        return false;
    }

    // Create service if not present
    SC_HANDLE hSvc = OpenServiceW(hSCM, BLOCKER_SVC, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        hSvc = CreateServiceW(
            hSCM, BLOCKER_SVC, L"kvcblocker",
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_AUTO_START,          // load on boot
            SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
            BLOCKER_GROUP,               // load order group
            nullptr, L"FltMgr\0\0",      // dependency: Filter Manager
            nullptr, nullptr);
        if (!hSvc) {
            DWORD err = GetLastError();
            CloseServiceHandle(hSCM);
            ERROR(L"Failed to create clrcd service: %lu", err);
            return false;
        }
        SetupBlockerAltitude(BLOCKER_SVC);
    }

    // Start service
    BOOL started = StartServiceW(hSvc, 0, nullptr);
    if (!started) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            ERROR(L"Failed to start clrcd service: %lu", err);
            return false;
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    // Wait briefly for minifilter to attach
    Sleep(500);

    if (!OpenDevice()) {
        ERROR(L"clrcd service started but device unavailable");
        return false;
    }
    SUCCESS(L"kvcblocker.sys loaded (clrcd service running)");
    return true;
}

bool Controller::IsBlockerRunning() noexcept {
    if (s_hDevice != INVALID_HANDLE_VALUE)
        return true;
    HANDLE h = CreateFileW(BLOCKER_DEVICE,
                           GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return true;
    }
    return false;
}

std::wstring Controller::GetBlockerStatus() noexcept {
    if (!OpenDevice())
        return L"STOPPED";
    if (!IoctlGetStatus())
        return L"RUNNING (no status)";
    BYTE active = g_statusResult[0];
    DWORD paths   = *reinterpret_cast<DWORD*>(g_statusResult + 4);
    DWORD trusted = *reinterpret_cast<DWORD*>(g_statusResult + 8);
    DWORD ver     = *reinterpret_cast<DWORD*>(g_statusResult + 12);
    wchar_t buf[128];
    swprintf_s(buf, L"%s  paths=%lu  trusted=%lu  ver=%lu",
               active ? L"ACTIVE" : L"INACTIVE", paths, trusted, ver);
    return buf;
}
