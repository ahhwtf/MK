// ControllerDriverLoader.cpp
// External driver loading with DSE bypass (Safe method) - automatic restore

#include "Controller.h"
#include "common.h"
#include <algorithm>
#include <bcrypt.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    constexpr wchar_t kMiomiHidServiceName[] = L"miomi_hid";
    constexpr wchar_t kMiomiHidHardwareId[] = L"Root\\MiomiHid";

    bool is_miomi_hid(const std::wstring& serviceName) noexcept
    {
        return _wcsicmp(serviceName.c_str(), kMiomiHidServiceName) == 0;
    }

    std::wstring replace_extension(const std::wstring& path, const wchar_t* newExt) noexcept
    {
        std::wstring result = path;
        const size_t slash = result.find_last_of(L"\\/");
        const size_t dot = result.find_last_of(L'.');
        if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash))
            result.erase(dot);
        result += newExt;
        return result;
    }

    std::wstring miomi_hid_inf_for_sys(const std::wstring& sysPath) noexcept
    {
        return replace_extension(sysPath, L".inf");
    }

    // Best-effort SHA-256 of a file's contents; returns empty string on any failure.
    std::wstring file_sha256(const std::wstring& path) noexcept
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
            return L"";

        std::vector<unsigned char> data(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return L"";

        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::wstring result;
        unsigned char emptyByte = 0;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0)
        {
            if (BCryptHashData(hHash, data.empty() ? &emptyByte : data.data(),
                                static_cast<ULONG>(data.size()), 0) == 0)
            {
                unsigned char digest[32]{};
                if (BCryptFinishHash(hHash, digest, sizeof(digest), 0) == 0)
                {
                    wchar_t hex[65]{};
                    for (int i = 0; i < 32; ++i)
                        swprintf_s(hex + i * 2, 3, L"%02x", digest[i]);
                    result.assign(hex, 64);
                }
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    std::wstring file_modified_string(const std::wstring& path) noexcept
    {
        WIN32_FILE_ATTRIBUTE_DATA info{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info))
            return L"unknown";

        FILETIME localFt{};
        SYSTEMTIME st{};
        if (!FileTimeToLocalFileTime(&info.ftLastWriteTime, &localFt) ||
            !FileTimeToSystemTime(&localFt, &st))
            return L"unknown";

        wchar_t buf[64]{};
        swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
                   st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }

    // Reads the "DriverVer=" line out of an INF without pulling in SetupAPI parsing.
    std::wstring read_driver_ver(const std::wstring& infPath) noexcept
    {
        std::wifstream file(infPath);
        if (!file)
            return L"unknown";

        std::wstring line;
        while (std::getline(file, line))
        {
            std::wstring trimmed = line;
            size_t start = trimmed.find_first_not_of(L" \t");
            if (start == std::wstring::npos)
                continue;
            trimmed = trimmed.substr(start);
            if (_wcsnicmp(trimmed.c_str(), L"DriverVer", 9) == 0)
            {
                size_t eq = trimmed.find(L'=');
                if (eq != std::wstring::npos)
                {
                    std::wstring value = trimmed.substr(eq + 1);
                    size_t end = value.find_last_not_of(L" \t\r\n");
                    if (end != std::wstring::npos)
                        value.erase(end + 1);
                    return value;
                }
            }
        }
        return L"unknown";
    }

    // Logs the exact package about to be installed and refuses to proceed if any
    // of the three files that make up the package (.inf/.sys/.cat) are missing.
    // This is the only place miomi_hid installation is allowed to happen from, so
    // a stale/incomplete package is caught here instead of failing silently deep
    // inside SetupAPI or, worse, "succeeding" against the wrong driver image.
    bool log_and_validate_miomi_hid_package(const std::wstring& infPath, const std::wstring& sysPath) noexcept
    {
        const std::wstring catPath = replace_extension(infPath, L".cat");

        INFO(L"[MIOMI_HID] INF path=%s", infPath.c_str());
        if (GetFileAttributesW(infPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            ERROR(L"[MIOMI_HID] INF missing; refusing install: %s", infPath.c_str());
            return false;
        }
        INFO(L"[MIOMI_HID] INF sha256=%s", file_sha256(infPath).c_str());
        INFO(L"[MIOMI_HID] INF modified=%s", file_modified_string(infPath).c_str());
        INFO(L"[MIOMI_HID] INF DriverVer=%s", read_driver_ver(infPath).c_str());

        INFO(L"[MIOMI_HID] SYS path=%s", sysPath.c_str());
        if (GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            ERROR(L"[MIOMI_HID] SYS missing; refusing install: %s", sysPath.c_str());
            return false;
        }
        INFO(L"[MIOMI_HID] SYS modified=%s", file_modified_string(sysPath).c_str());

        if (GetFileAttributesW(catPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            ERROR(L"[MIOMI_HID] CAT missing; refusing install: %s", catPath.c_str());
            ERROR(L"[MIOMI_HID] A driver package is INF+SYS+CAT together; a missing catalog");
            ERROR(L"[MIOMI_HID] means the package was never (re)generated after the last build.");
            return false;
        }
        INFO(L"[MIOMI_HID] CAT modified=%s", file_modified_string(catPath).c_str());

        return true;
    }
}

// Check if HVCI is enabled and handle it (returns true if safe to proceed)
bool Controller::CheckAndHandleHVCI(const std::wstring& operation, const std::wstring& targetPath) noexcept {
    PerformAtomicCleanup();
    if (!BeginDriverSession()) {
        ERROR(L"Failed to start driver session for HVCI check");
        return false;
    }
    if (!m_rtc->Initialize()) {
        ERROR(L"Failed to initialize driver handle");
        EndDriverSession(true);
        return false;
    }
    
    if (!m_dseBypass) {
        m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
    }
    
    // Get DSE status to check HVCI
    DSEBypass::Status status;
    if (!m_dseBypass->GetStatus(status)) {
        ERROR(L"Failed to get DSE status");
        EndDriverSession(true);
        return false;
    }
    
    EndDriverSession(true);
    
    if (!status.HVCIEnabled) {
        SUCCESS(L"Memory Integrity is disabled - safe to proceed");
        return true;
    }
    
    // HVCI is enabled - same handling as DisableDSESafe()
    INFO(L"Memory Integrity is enabled (g_CiOptions = 0x%08X)", status.CiOptionsValue);
    INFO(L"A reboot is required to disable Memory Integrity before driver %s", operation.c_str());
    std::wcout << L"\n";
    std::wcout << L"Disable Memory Integrity and reboot now? [Y/N]: ";
    wchar_t choice;
    std::wcin >> choice;
    if (choice != L'Y' && choice != L'y') {
        INFO(L"Operation cancelled by user");
        return false;
    }
    // Set HVCI registry to 0
    HKEY hKeyRaw = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                      0, KEY_SET_VALUE, &hKeyRaw) == ERROR_SUCCESS) {
        RegKeyGuard hKey(hKeyRaw);
        DWORD disabled = 0;
        RegSetValueExW(hKey.get(), L"Enabled", 0, REG_DWORD,
                      reinterpret_cast<const BYTE*>(&disabled), sizeof(DWORD));
        SUCCESS(L"Memory Integrity disabled in registry");
    } else {
        ERROR(L"Failed to modify HVCI registry key");
        return false;
    }
    INFO(L"Initiating system reboot...");
    INFO(L"After reboot, run 'kvc driver %s %s' again to complete the operation", 
         operation.c_str(), targetPath.c_str());
    // Enable shutdown privilege and reboot
    {
        TokenGuard token;
        HANDLE hTokenRaw = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenRaw)) {
            token.reset(hTokenRaw);
            TOKEN_PRIVILEGES tkp;
            LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token.get(), FALSE, &tkp, 0, NULL, 0);
        }
    }
    if (InitiateShutdownW(NULL, NULL, 0, SHUTDOWN_RESTART | SHUTDOWN_FORCE_OTHERS, 
                          SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIGURE) != ERROR_SUCCESS) {
        ERROR(L"Failed to initiate reboot: %d", GetLastError());
    }
    return false; // Don't proceed - reboot required
}

std::wstring Controller::NormalizeDriverPath(const std::wstring& input) noexcept {
    if (input.find(L'\\') != std::wstring::npos || input.find(L':') != std::wstring::npos) {
        std::wstring path = input;
        if (path.length() < 4 || StringUtils::ToLowerCaseCopy(path.substr(path.length() - 4)) != L".sys") {
            path += L".sys";
        }
        return path;
    }
    std::wstring filename = input;
    if (filename.length() < 4 || StringUtils::ToLowerCaseCopy(filename.substr(filename.length() - 4)) != L".sys") {
        filename += L".sys";
    }
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    return std::wstring(sysDir) + L"\\drivers\\" + filename;
}

std::wstring Controller::ExtractServiceName(const std::wstring& driverPath) noexcept {
    size_t lastSlash = driverPath.find_last_of(L"\\/");
    std::wstring filename = (lastSlash != std::wstring::npos) 
        ? driverPath.substr(lastSlash + 1) 
        : driverPath;
    if (filename.length() >= 4) {
        std::wstring ext = StringUtils::ToLowerCaseCopy(filename.substr(filename.length() - 4));
        if (ext == L".sys") {
            filename = filename.substr(0, filename.length() - 4);
        }
    }
    return filename;
}

bool Controller::LoadExternalDriver(const std::wstring& driverPath, DWORD startType) noexcept {
    std::wstring normalizedPath = NormalizeDriverPath(driverPath);
    std::wstring serviceName = ExtractServiceName(normalizedPath);
    INFO(L"Loading external driver: %s", serviceName.c_str());
    INFO(L"Path: %s", normalizedPath.c_str());

    // miomi_hid is a root-enumerated KMDF/VHF PnP driver. Never start it as
    // a generic SERVICE_KERNEL_DRIVER service: doing so loads the image without
    // creating Root\MiomiHid, so there is no PnP device lifetime to remove later.
    if (is_miomi_hid(serviceName))
    {
        const std::wstring infPath = miomi_hid_inf_for_sys(normalizedPath);
        if (!log_and_validate_miomi_hid_package(infPath, normalizedPath))
        {
            ERROR(L"Refusing legacy/direct load so miomi_hid cannot become orphaned in the kernel");
            return false;
        }

        INFO(L"[MIOMI_HID] Routing load through PnP: %s", infPath.c_str());
        return InstallPnpDriver(infPath, kMiomiHidHardwareId);
    }

    // Verify file exists
    if (GetFileAttributesW(normalizedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"Driver file not found: %s", normalizedPath.c_str());
        return false;
    }
    
    // CHECK AND HANDLE HVCI
    if (!CheckAndHandleHVCI(L"load", normalizedPath)) {
        return false;
    }
    
    bool dseDisabled = false;
    bool driverLoaded = false;
    
    // STEP 1: ACTIVATE DSE BYPASS (Safe Mode)
    {
        INFO(L"Activating DSE bypass (Safe Mode)...");
        PerformAtomicCleanup();
        
        if (!BeginDriverSession()) {
            ERROR(L"Failed to start driver session for DSE bypass");
            return false;
        }
        
        if (!m_rtc->Initialize()) {
            ERROR(L"Failed to initialize handle kvc (kvc.sys)");
            EndDriverSession(true);
            return false;
        }
        
        if (!m_dseBypass) {
            m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
        }
        
        if (!m_dseBypass->Disable(DSEBypass::Method::Safe)) {
            ERROR(L"Failed to disable DSE");
            EndDriverSession(true);
            return false;
        }
        
        dseDisabled = true;
        SUCCESS(L"DSE bypass activated successfully");
        EndDriverSession(true); // Close session to avoid conflicts with SCM
    }
    
    // STEP 2: LOAD THE DRIVER (with guaranteed DSE restore on exit)
    {
        bool serviceSuccess = false;
        bool apiInitialized = false;
        
        // RAII-style DSE restore guarantee
        auto dseRestoreGuard = [&]() {
            if (dseDisabled) {
                INFO(L"Auto-restoring DSE protection...");
                
                if (!BeginDriverSession()) {
                    ERROR(L"Failed to start driver session for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    return;
                }
                
                if (!m_rtc->Initialize()) {
                    ERROR(L"Failed to initialize driver handle for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    EndDriverSession(true);
                    return;
                }
                
                if (!m_dseBypass) {
                    m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
                }
                
                if (m_dseBypass->Restore(DSEBypass::Method::Safe)) {
                    SUCCESS(L"DSE protection restored successfully");
                } else {
                    ERROR(L"Failed to restore DSE protection");
                    ERROR(L"Run 'kvc dse on --safe' to manually restore kernel protection");
                }
                
                EndDriverSession(true);
            }
        };
        
        if (!InitDynamicAPIs()) {
            ERROR(L"Failed to initialize service APIs");
            dseRestoreGuard();
            return false;
        }
        apiInitialized = true;
        
        // Try to create and start the service
        SCManagerGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
        if (!scm) {
            ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
            dseRestoreGuard();
            return false;
        }

        // Check if service already exists
        ServiceHandleGuard service(g_pOpenServiceW(scm.get(), serviceName.c_str(), SERVICE_ALL_ACCESS));
        if (service) {
            INFO(L"Service already exists - updating driver path before start...");

            if (!ChangeServiceConfigW(
                    service.get(),
                    SERVICE_NO_CHANGE,
                    startType,
                    SERVICE_NO_CHANGE,
                    normalizedPath.c_str(),
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr)) {
                ERROR(L"Failed to update existing service path: %d", GetLastError());
                dseRestoreGuard();
                return false;
            }

            SUCCESS(L"Existing service path updated: %s", normalizedPath.c_str());

            // Query current status
            SERVICE_STATUS status;
            if (QueryServiceStatus(service.get(), &status)) {
                if (status.dwCurrentState == SERVICE_RUNNING) {
                    SUCCESS(L"Driver service is already running");
                    driverLoaded = true;
                    dseRestoreGuard();
                    return true;
                }
            }

            // Try to start
            if (g_pStartServiceW(service.get(), 0, nullptr)) {
                SUCCESS(L"Driver service started successfully");
                driverLoaded = true;
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                    SUCCESS(L"Driver service is already running");
                    driverLoaded = true;
                } else {
                    ERROR(L"Failed to start existing service: %d", err);
                }
            }
        } else {
            // Create new service
            INFO(L"Creating new driver service...");
            service.reset(g_pCreateServiceW(
                scm.get(),
                serviceName.c_str(),
                serviceName.c_str(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                startType,
                SERVICE_ERROR_NORMAL,
                normalizedPath.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr
            ));

            if (!service) {
                ERROR(L"Failed to create service: %d", GetLastError());
                dseRestoreGuard();
                return false;
            }

            SUCCESS(L"Driver service created successfully");

            // Start the service
            if (g_pStartServiceW(service.get(), 0, nullptr)) {
                SUCCESS(L"Driver service started successfully");
                driverLoaded = true;
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                    SUCCESS(L"Driver service is already running");
                    driverLoaded = true;
                } else {
                    ERROR(L"Failed to start service: %d", err);
                }
            }
        }

        // Guards automatically close handles on scope exit
        
        // STEP 3: AUTO-RESTORE DSE AFTER LOAD (always called)
        dseRestoreGuard();
    }

    // Connect kvcstrm client immediately after successful load
    if (driverLoaded && serviceName == L"kvcstrm") {
        if (m_strm.Open())
            SUCCESS(L"kvcstrm client connected");
        else
            ERROR(L"kvcstrm loaded but Open() failed - check driver status");
    }

    return driverLoaded;
}

bool Controller::ReloadExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring normalizedPath = NormalizeDriverPath(driverNameOrPath);
    std::wstring serviceName = ExtractServiceName(normalizedPath);
    INFO(L"Reloading driver: %s", serviceName.c_str());

    if (is_miomi_hid(serviceName))
    {
        const std::wstring infPath = miomi_hid_inf_for_sys(normalizedPath);
        if (!log_and_validate_miomi_hid_package(infPath, normalizedPath))
        {
            ERROR(L"Refusing miomi_hid PnP reload with an incomplete package");
            return false;
        }

        INFO(L"[MIOMI_HID] Removing Root\\MiomiHid before PnP reload");
        if (!RemovePnpDriver(kMiomiHidHardwareId))
            return false;

        return InstallPnpDriver(infPath, kMiomiHidHardwareId);
    }
    
    // CHECK AND HANDLE HVCI
    if (!CheckAndHandleHVCI(L"reload", normalizedPath)) {
        return false;
    }
    
    bool dseDisabled = false;
    bool driverReloaded = false;
    
    // STEP 1: ACTIVATE DSE BYPASS (Safe Mode)
    {
        INFO(L"Activating DSE bypass (Safe Mode)...");
        PerformAtomicCleanup();
        
        if (!BeginDriverSession()) {
            ERROR(L"Failed to start driver session");
            return false;
        }
        
        if (!m_rtc->Initialize()) {
            ERROR(L"Failed to initialize handle kvc (kvc.sys)");
            EndDriverSession(true);
            return false;
        }
        
        if (!m_dseBypass) {
            m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
        }
        
        if (!m_dseBypass->Disable(DSEBypass::Method::Safe)) {
            ERROR(L"Failed to disable DSE");
            EndDriverSession(true);
            return false;
        }
        
        dseDisabled = true;
        SUCCESS(L"DSE bypass activated successfully");
        EndDriverSession(true);
    }
    
    // STEP 2: RELOAD THE DRIVER (with guaranteed DSE restore)
    {
        // RAII-style DSE restore guarantee
        auto dseRestoreGuard = [&]() {
            if (dseDisabled) {
                INFO(L"Auto-restoring DSE protection...");
                
                if (!BeginDriverSession()) {
                    ERROR(L"Failed to start driver session for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    return;
                }
                
                if (!m_rtc->Initialize()) {
                    ERROR(L"Failed to initialize driver handle for DSE restore");
                    ERROR(L"DSE remains disabled - run 'kvc dse on --safe' manually");
                    EndDriverSession(true);
                    return;
                }
                
                if (!m_dseBypass) {
                    m_dseBypass = std::make_unique<DSEBypass>(m_rtc, &m_trustedInstaller);
                }
                
                if (m_dseBypass->Restore(DSEBypass::Method::Safe)) {
                    SUCCESS(L"DSE protection restored successfully");
                } else {
                    ERROR(L"Failed to restore DSE protection");
                    ERROR(L"Run 'kvc dse on --safe' to manually restore kernel protection");
                }
                
                EndDriverSession(true);
            }
        };
        
        if (!InitDynamicAPIs()) {
            ERROR(L"Failed to initialize service APIs");
            dseRestoreGuard();
            return false;
        }
        
        // Stop existing service if running
        {
            SCManagerGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
            if (scm) {
                ServiceHandleGuard service(g_pOpenServiceW(scm.get(), serviceName.c_str(), SERVICE_ALL_ACCESS));
                if (service) {
                    SERVICE_STATUS status;
                    if (g_pControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
                        INFO(L"Service stopped successfully");
                    }
                }
            }
        }

        // Start service
        bool startSuccess = false;
        {
            SCManagerGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
            if (scm) {
                ServiceHandleGuard service(g_pOpenServiceW(scm.get(), serviceName.c_str(), SERVICE_START));
                if (!service) {
                    // Create if doesn't exist
                    service.reset(g_pCreateServiceW(
                        scm.get(),
                        serviceName.c_str(),
                        serviceName.c_str(),
                        SERVICE_ALL_ACCESS,
                        SERVICE_KERNEL_DRIVER,
                        SERVICE_DEMAND_START,
                        SERVICE_ERROR_NORMAL,
                        normalizedPath.c_str(),
                        nullptr, nullptr, nullptr, nullptr, nullptr
                    ));
                }

                if (service) {
                    if (g_pStartServiceW(service.get(), 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                        SUCCESS(L"Driver service restarted successfully");
                        startSuccess = true;
                        driverReloaded = true;
                    } else {
                        ERROR(L"Failed to start service: %d", GetLastError());
                    }
                }
            }
        }
        
        // STEP 3: AUTO-RESTORE DSE AFTER RELOAD (always called)
        dseRestoreGuard();
    }

    // Re-connect kvcstrm client after successful reload
    if (driverReloaded && serviceName == L"kvcstrm") {
        if (m_strm.Open())
            SUCCESS(L"kvcstrm client reconnected");
        else
            ERROR(L"kvcstrm reloaded but Open() failed - check driver status");
    }

    return driverReloaded;
}

// Opens the kvcstrm device handle.
// If the service is not running, loads kvcstrm.sys from DriverStore FileRepository
// via LoadExternalDriver (includes DSE bypass via kvc.sys — same path as kvc driver load).
// Works even when the service is not yet registered in SCM.
// Sets autoStarted=true only when this call loaded the driver (caller must CleanupStrm).
bool Controller::EnsureStrmOpen(bool& autoStarted) noexcept {
    autoStarted = false;

    if (m_strm.IsOpen()) return true;
    if (m_strm.Open())   return true;   // service was running, handle just wasn't open

    // Locate kvcstrm.sys in DriverStore FileRepository (avc.inf_amd64_* glob)
    std::wstring sysPath = GetDriverStorePath() + L"\\kvcstrm.sys";
    if (GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        DEBUG(L"[EnsureStrmOpen] kvcstrm.sys not found at %s", sysPath.c_str());
        return false;
    }

    // LoadExternalDriver: DSE bypass + service create/start + m_strm.Open()
    if (!LoadExternalDriver(sysPath)) return false;

    autoStarted = true;
    return m_strm.IsOpen();
}

// Cleans up kvcstrm only when EnsureStrmOpen auto-loaded it.
// Removes service entry from registry (DeleteService) so SCM is clean after use.
// If user loaded kvcstrm manually (autoStarted=false) — leaves everything untouched.
void Controller::CleanupStrm(bool autoStarted) noexcept {
    if (autoStarted)
        RemoveExternalDriver(L"kvcstrm");
}

bool Controller::StopExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    std::wstring serviceName = ExtractServiceName(driverNameOrPath);
    INFO(L"Stopping driver service: %s", serviceName.c_str());

    if (is_miomi_hid(serviceName))
    {
        INFO(L"[MIOMI_HID] Stop requested: removing Root\\MiomiHid through PnP");
        return RemovePnpDriver(kMiomiHidHardwareId);
    }

    // Close kvcstrm client handle before stopping the driver to avoid
    // keeping an open device reference during unload (potential BSOD)
    if (serviceName == L"kvcstrm")
        m_strm.Close();

    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }

    SCManagerGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
        return false;
    }

    ServiceHandleGuard service(g_pOpenServiceW(scm.get(), serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            ERROR(L"Service not found: %s", serviceName.c_str());
        } else {
            ERROR(L"Failed to open service: %d", err);
        }
        return false;
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(service.get(), &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            INFO(L"Service is already stopped");
            return true;
        }
    }

    if (!g_pControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
        ERROR(L"Failed to stop service: %d", GetLastError());
        return false;
    }

    SUCCESS(L"Driver service stopped: %s", serviceName.c_str());
    return true;
}

bool Controller::RemoveExternalDriver(const std::wstring& driverNameOrPath) noexcept {
    INFO(L"[DEBUG] RemoveExternalDriver input: %s", driverNameOrPath.c_str());

    // Check if input is a hardware ID (e.g., "Root\MiomiHid")
    if (driverNameOrPath.find(L"\\") != std::wstring::npos &&
        driverNameOrPath.find(L".") == std::wstring::npos)
    {
        INFO(L"[DEBUG] Detected as hardware ID (has \\ no .)");
        // This is a hardware ID, not a path
        if (_wcsicmp(driverNameOrPath.c_str(), kMiomiHidHardwareId) == 0)
        {
            INFO(L"[MIOMI_HID] Remove requested via hardware ID: removing Root\\MiomiHid through PnP");
            return RemovePnpDriver(kMiomiHidHardwareId);
        }
        INFO(L"[DEBUG] Hardware ID check failed, comparing '%s' vs '%s'", driverNameOrPath.c_str(), kMiomiHidHardwareId);
    }
    else
    {
        INFO(L"[DEBUG] Not a hardware ID pattern");
    }

    std::wstring serviceName = ExtractServiceName(driverNameOrPath);
    INFO(L"Removing driver service: %s", serviceName.c_str());

    if (is_miomi_hid(serviceName))
    {
        INFO(L"[MIOMI_HID] Remove requested: removing Root\\MiomiHid through PnP");
        return RemovePnpDriver(kMiomiHidHardwareId);
    }

    if (!StopExternalDriver(serviceName)) {
        ERROR(
            L"Driver is still running; refusing to delete its service registration: %s",
            serviceName.c_str());
        return false;
    }
    if (!InitDynamicAPIs()) {
        ERROR(L"Failed to initialize service APIs");
        return false;
    }

    SCManagerGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        ERROR(L"Failed to open Service Control Manager: %d", GetLastError());
        return false;
    }

    ServiceHandleGuard service(g_pOpenServiceW(scm.get(), serviceName.c_str(), DELETE));
    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            INFO(L"Service does not exist: %s", serviceName.c_str());
            return true;
        }
        ERROR(L"Failed to open service for deletion: %d", err);
        return false;
    }

    if (!g_pDeleteService(service.get())) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            INFO(L"Service already marked for deletion");
            return true;
        }
        ERROR(L"Failed to delete service: %d", err);
        return false;
    }

    SUCCESS(L"Driver service removed: %s", serviceName.c_str());
    return true;
}
