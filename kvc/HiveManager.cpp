// HiveManager.cpp
#include "HiveManager.h"
#include "common.h"
#include "TrustedInstallerIntegrator.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <shlobj.h>
#include <sddl.h>
#include <lmcons.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

namespace
{
constexpr wchar_t kProfileListBase[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\";

bool QueryRegStringValue(
    HKEY root,
    const wchar_t* subKey,
    const wchar_t* valueName,
    std::wstring& value,
    DWORD* valueType = nullptr)
{
    value.clear();

    HKEY hKey = nullptr;
    LONG st = RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE, &hKey);
    if (st != ERROR_SUCCESS) {
        return false;
    }

    DWORD type = 0;
    DWORD cbData = 0;
    st = RegQueryValueExW(hKey, valueName, nullptr, &type, nullptr, &cbData);
    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || cbData < sizeof(wchar_t)) {
        RegCloseKey(hKey);
        return false;
    }

    std::vector<wchar_t> buffer((cbData / sizeof(wchar_t)) + 1, L'\0');
    st = RegQueryValueExW(hKey, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &cbData);
    RegCloseKey(hKey);
    if (st != ERROR_SUCCESS) {
        return false;
    }

    value.assign(buffer.data());
    if (valueType != nullptr) {
        *valueType = type;
    }
    return true;
}

bool ExpandIfNeeded(const std::wstring& raw, DWORD type, std::wstring& expanded)
{
    if (type == REG_SZ) {
        expanded = raw;
        return true;
    }
    if (type != REG_EXPAND_SZ) {
        return false;
    }

    DWORD needed = ExpandEnvironmentStringsW(raw.c_str(), nullptr, 0);
    if (needed == 0) {
        return false;
    }
    std::vector<wchar_t> buffer(needed + 1, L'\0');
    DWORD written = ExpandEnvironmentStringsW(raw.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
    if (written == 0 || written > buffer.size()) {
        return false;
    }
    expanded.assign(buffer.data());
    return true;
}

bool ResolveUserProfilePathBySid(const std::wstring& sid, std::wstring& profilePath)
{
    profilePath.clear();
    if (sid.empty()) {
        return false;
    }

    std::wstring sidKey = std::wstring(kProfileListBase) + sid;
    std::wstring rawPath;
    DWORD type = 0;
    if (!QueryRegStringValue(HKEY_LOCAL_MACHINE, sidKey.c_str(), L"ProfileImagePath", rawPath, &type)) {
        return false;
    }
    return ExpandIfNeeded(rawPath, type, profilePath);
}

bool StartsWith(const std::wstring& value, const std::wstring& prefix)
{
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool ResolveBcdPhysicalPath(std::wstring& pathOut)
{
    pathOut.clear();

    HKEY hHiveList = nullptr;
    LONG st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\hivelist",
                            0,
                            KEY_QUERY_VALUE,
                            &hHiveList);
    if (st != ERROR_SUCCESS) {
        return false;
    }

    wchar_t ntPath[1024] = {};
    DWORD type = 0;
    DWORD cbData = sizeof(ntPath);
    st = RegQueryValueExW(hHiveList, L"\\REGISTRY\\MACHINE\\BCD00000000", nullptr, &type,
                          reinterpret_cast<LPBYTE>(ntPath), &cbData);

    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        for (DWORD index = 0;; ++index) {
            wchar_t valueName[256] = {};
            DWORD cchValueName = ARRAYSIZE(valueName);
            cbData = sizeof(ntPath);
            type = 0;

            if (RegEnumValueW(hHiveList, index, valueName, &cchValueName, nullptr, &type,
                              reinterpret_cast<LPBYTE>(ntPath), &cbData) != ERROR_SUCCESS) {
                break;
            }

            if ((type == REG_SZ || type == REG_EXPAND_SZ) &&
                _wcsnicmp(valueName, L"\\REGISTRY\\MACHINE\\BCD", 22) == 0) {
                st = ERROR_SUCCESS;
                break;
            }
        }
    }

    RegCloseKey(hHiveList);
    if (st != ERROR_SUCCESS) {
        return false;
    }

    std::wstring nt = ntPath;
    if (StartsWith(nt, L"\\Device\\")) {
        pathOut = L"\\\\?\\GLOBALROOT" + nt;
        return true;
    }
    if (StartsWith(nt, L"\\??\\")) {
        pathOut = nt.substr(4);
        return true;
    }
    if (nt.size() >= 3 && nt[1] == L':' && (nt[2] == L'\\' || nt[2] == L'/')) {
        pathOut = nt;
        return true;
    }
    return false;
}

void ResetDwordValueIfNonZero(HKEY key, const wchar_t* valueName)
{
    DWORD type = 0;
    DWORD value = 0;
    DWORD cbData = sizeof(value);
    if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &cbData) == ERROR_SUCCESS &&
        type == REG_DWORD && value != 0) {
        value = 0;
        RegSetValueExW(key, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
    }
}

void SanitizeProfileListInSoftwareHive(HKEY softwareRoot)
{
    HKEY hProfileList = nullptr;
    if (RegOpenKeyExW(softwareRoot,
                      L"Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                      0,
                      KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                      &hProfileList) != ERROR_SUCCESS) {
        return;
    }

    for (DWORD index = 0;; ++index) {
        wchar_t sidKeyName[256] = {};
        DWORD cchSid = ARRAYSIZE(sidKeyName);
        FILETIME ft = {};
        LONG st = RegEnumKeyExW(hProfileList, index, sidKeyName, &cchSid, nullptr, nullptr, nullptr, &ft);
        if (st == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (st != ERROR_SUCCESS) {
            continue;
        }

        if (_wcsnicmp(sidKeyName, L"S-1-5-21-", 9) != 0) {
            continue;
        }

        HKEY hSid = nullptr;
        if (RegOpenKeyExW(hProfileList, sidKeyName, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hSid) == ERROR_SUCCESS) {
            ResetDwordValueIfNonZero(hSid, L"State");
            ResetDwordValueIfNonZero(hSid, L"RefCount");
            RegCloseKey(hSid);
        }
    }

    RegCloseKey(hProfileList);
}
} // namespace

HiveManager::HiveManager()
    : m_tiToken(nullptr)
    , m_tiIntegrator(nullptr)
{
    m_currentUserSid = GetCurrentUserSid();
    m_currentUsername = GetCurrentUsername();
    InitializeHiveLists();
    ResetStats();
}

HiveManager::~HiveManager()
{
    if (m_tiToken) {
        RevertToSelf();
        m_tiToken = nullptr;
    }
    
    if (m_tiIntegrator) {
        delete m_tiIntegrator;
        m_tiIntegrator = nullptr;
    }
}

std::wstring HiveManager::GetCurrentUserSid()
{
    TokenGuard token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.addressof())) {
        return L"";
    }

    DWORD dwSize = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &dwSize);

    std::vector<BYTE> buffer(dwSize);
    TOKEN_USER* pTokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());

    std::wstring sidString;
    if (GetTokenInformation(token.get(), TokenUser, pTokenUser, dwSize, &dwSize)) {
        LPWSTR stringSid;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &stringSid)) {
            sidString = stringSid;
            LocalFree(stringSid);
        }
    }

    return sidString;
}

std::wstring HiveManager::GetCurrentUsername()
{
    wchar_t username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    
    if (GetUserNameW(username, &size)) {
        return std::wstring(username);
    }
    
    return L"";
}

fs::path HiveManager::GetHivePhysicalPath(const std::wstring& hiveName)
{
    wchar_t sysDir[MAX_PATH];

    GetSystemDirectoryW(sysDir, MAX_PATH);
    fs::path systemPath(sysDir);

    if (hiveName == L"DEFAULT") {
        return systemPath / L"config" / L"DEFAULT";
    }
    else if (hiveName == L"SAM") {
        return systemPath / L"config" / L"SAM";
    }
    else if (hiveName == L"SECURITY") {
        return systemPath / L"config" / L"SECURITY";
    }
    else if (hiveName == L"SOFTWARE") {
        return systemPath / L"config" / L"SOFTWARE";
    }
    else if (hiveName == L"SYSTEM") {
        return systemPath / L"config" / L"SYSTEM";
    }
    else if (hiveName == L"BCD") {
        std::wstring bcdPath;
        if (ResolveBcdPhysicalPath(bcdPath)) {
            return fs::path(bcdPath);
        }
    }
    else if (hiveName == L"NTUSER" && !m_currentUserSid.empty()) {
        std::wstring profilePath;
        if (ResolveUserProfilePathBySid(m_currentUserSid, profilePath)) {
            return fs::path(profilePath) / L"NTUSER.DAT";
        }
    }
    else if (hiveName == L"UsrClass" && !m_currentUserSid.empty()) {
        std::wstring profilePath;
        if (ResolveUserProfilePathBySid(m_currentUserSid, profilePath)) {
            return fs::path(profilePath) / L"AppData" / L"Local" / L"Microsoft" / L"Windows" / L"UsrClass.dat";
        }
    }
    
    return L"";
}

void HiveManager::InitializeHiveLists()
{
    // Build user-specific paths
    std::wstring userHivePath = L"HKU\\" + m_currentUserSid;
    std::wstring userClassPath = userHivePath + L"_Classes";
    
    // Critical registry hives (all operations require TrustedInstaller elevation)
    m_registryHives = {
        { L"BCD", L"HKLM\\BCD00000000", true },            // Bootloader
        { L"DEFAULT", L"HKU\\.DEFAULT", true },
        { L"NTUSER", userHivePath, true },                 // User hive with real SID
        { L"SAM", L"HKLM\\SAM", true },
        { L"SECURITY", L"HKLM\\SECURITY", true },
        { L"SOFTWARE", L"HKLM\\SOFTWARE", true },
        { L"SYSTEM", L"HKLM\\SYSTEM", true },
        { L"UsrClass", userClassPath, true }               // User classes with real SID
    };
}

void HiveManager::ResetStats()
{
    m_lastStats = BackupStats{};
}

fs::path HiveManager::GenerateDefaultBackupPath()
{
    wchar_t downloadsPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, downloadsPath))) {
        fs::path basePath = fs::path(downloadsPath) / L"Downloads";
        std::wstring folderName = L"Registry_Backup_" + TimeUtils::GetFormattedTimestamp("datetime_file");
        return basePath / folderName;
    }
    
    return fs::temp_directory_path() / (L"Registry_Backup_" + TimeUtils::GetFormattedTimestamp("datetime_file"));
}

bool HiveManager::ValidateBackupDirectory(const fs::path& path)
{
    std::error_code ec;
    
    fs::path normalizedPath = fs::absolute(path, ec);
    if (ec) {
        ERROR(L"Failed to normalize path: %s", path.c_str());
        return false;
    }
    
    if (!fs::exists(normalizedPath, ec)) {
        if (!fs::create_directories(normalizedPath, ec)) {
            ERROR(L"Failed to create backup directory: %s", normalizedPath.c_str());
            return false;
        }
        INFO(L"Created backup directory: %s", normalizedPath.c_str());
    }
    
    if (!fs::is_directory(normalizedPath, ec)) {
        ERROR(L"Path is not a directory: %s", normalizedPath.c_str());
        return false;
    }
    
    return true;
}

bool HiveManager::ValidateRestoreDirectory(const fs::path& path)
{
    std::error_code ec;
    
    fs::path normalizedPath = fs::absolute(path, ec);
    if (ec) {
        ERROR(L"Failed to normalize path: %s", path.c_str());
        return false;
    }
    
    if (!fs::exists(normalizedPath, ec) || !fs::is_directory(normalizedPath, ec)) {
        ERROR(L"Restore directory does not exist: %s", normalizedPath.c_str());
        return false;
    }
    
    return true;
}

bool HiveManager::ElevateToTrustedInstaller()
{
    if (m_tiToken) {
        return true;
    }
    
    if (!m_tiIntegrator) {
        m_tiIntegrator = new TrustedInstallerIntegrator();
    }
    
    INFO(L"Acquiring TrustedInstaller token...");
    m_tiToken = m_tiIntegrator->GetCachedTrustedInstallerToken();
    
    if (!m_tiToken) {
        ERROR(L"Failed to acquire TrustedInstaller token - ensure running as Administrator");
        return false;
    }
    
    if (!ImpersonateLoggedOnUser(m_tiToken)) {
        ERROR(L"Failed to impersonate TrustedInstaller: %d", GetLastError());
        m_tiToken = nullptr;
        return false;
    }
    
    SUCCESS(L"Elevated to TrustedInstaller");
    return true;
}

bool HiveManager::PromptYesNo(const wchar_t* question)
{
    std::wcout << L"\n" << question << L" ";
    std::wstring response;
    std::getline(std::wcin, response);
    
    if (response.empty()) {
        return false;
    }
    
    wchar_t first = towlower(response[0]);
    return (first == L'y' || first == L't'); // Y/y or T/t (Polish "tak")
}

bool HiveManager::SaveRegistryHive(const std::wstring& registryPath, const fs::path& destFile)
{
    HKEY hRootKey = nullptr;
    std::wstring subKey;

    if (registryPath.starts_with(L"HKLM\\") || registryPath.starts_with(L"HKEY_LOCAL_MACHINE\\")) {
        hRootKey = HKEY_LOCAL_MACHINE;
        size_t pos = registryPath.find(L'\\');
        subKey = registryPath.substr(pos + 1);
    }
    else if (registryPath.starts_with(L"HKU\\") || registryPath.starts_with(L"HKEY_USERS\\")) {
        hRootKey = HKEY_USERS;
        size_t pos = registryPath.find(L'\\');
        subKey = registryPath.substr(pos + 1);
    }
    else if (registryPath.starts_with(L"HKCU") || registryPath.starts_with(L"HKEY_CURRENT_USER")) {
        hRootKey = HKEY_CURRENT_USER;
        size_t pos = registryPath.find(L'\\');
        if (pos != std::wstring::npos) {
            subKey = registryPath.substr(pos + 1);
        }
    }
    else {
        ERROR(L"Invalid registry path format: %s", registryPath.c_str());
        return false;
    }

    RegKeyGuard key;
    LONG result = RegOpenKeyExW(hRootKey, subKey.empty() ? nullptr : subKey.c_str(),
                                0, KEY_READ, key.addressof());

    if (result != ERROR_SUCCESS) {
        ERROR(L"Failed to open registry key %s: %d", registryPath.c_str(), result);
        return false;
    }

    // Save the hive using latest format (compresses and defragments)
    result = RegSaveKeyExW(key.get(), destFile.c_str(), nullptr, REG_LATEST_FORMAT);

    if (result != ERROR_SUCCESS) {
        ERROR(L"RegSaveKeyEx failed for %s: %d", registryPath.c_str(), result);
        return false;
    }

    return true;
}


bool HiveManager::BackupRegistryHives(const fs::path& targetDir)
{
    INFO(L"Backing up registry hives...");
    
    for (const auto& hive : m_registryHives) {
        m_lastStats.totalHives++;
        
        fs::path destFile = targetDir / hive.name;
        
        INFO(L"  Saving %s -> %s", hive.name.c_str(), destFile.filename().c_str());
        
        // All hives are saved via their live registry path using RegSaveKeyExW.
        // Physical-file loading is not attempted here: hives already mounted by the kernel
        // (including BCD and UsrClass) will always return ERROR_SHARING_VIOLATION (32)
        // from RegLoadKeyW, making that path useless on a running system.
        bool saved = SaveRegistryHive(hive.registryPath, destFile);

        if (saved) {
            m_lastStats.successfulHives++;
            
            std::error_code ec;
            auto size = fs::file_size(destFile, ec);
            if (!ec) {
                m_lastStats.totalBytes += size;
            }
            
            SUCCESS(L"  Saved %s (%llu bytes)", hive.name.c_str(), size);
        }
        else {
            m_lastStats.failedHives++;
            ERROR(L"  Failed to save %s", hive.name.c_str());
        }
    }
    
    return m_lastStats.successfulHives > 0;
}

void HiveManager::PrintStats(const std::wstring& operation)
{
    std::wcout << L"\n";
    INFO(L"=== %s Statistics ===", operation.c_str());
    INFO(L"Registry Hives: %zu/%zu successful", m_lastStats.successfulHives, m_lastStats.totalHives);
    INFO(L"Total Size: %.2f MB", static_cast<double>(m_lastStats.totalBytes) / (1024.0 * 1024.0));
    
    if (m_lastStats.failedHives > 0) {
        ERROR(L"Failed: %zu hives", m_lastStats.failedHives);
    }
}

bool HiveManager::Backup(const std::wstring& targetPath)
{
    ResetStats();
    
    fs::path backupDir;
    if (targetPath.empty()) {
        backupDir = GenerateDefaultBackupPath();
        INFO(L"Using default backup path: %s", backupDir.c_str());
    }
    else {
        backupDir = targetPath;
    }
    
    if (!ValidateBackupDirectory(backupDir)) {
        return false;
    }
    
    if (!ElevateToTrustedInstaller()) {
        return false;
    }
    
    INFO(L"Starting registry backup to: %s", backupDir.c_str());
    
    bool success = BackupRegistryHives(backupDir);
    
    PrintStats(L"Backup");
    
    if (success) {
        SUCCESS(L"Backup completed: %s", backupDir.c_str());
        return true;
    }
    
    ERROR(L"Backup failed");
    return false;
}

bool HiveManager::RestoreRegistryHives(const fs::path& sourceDir)
{
    INFO(L"Validating backup files...");
    
    for (const auto& hive : m_registryHives) {
        fs::path sourceFile = sourceDir / hive.name;
        
        std::error_code ec;
        if (fs::exists(sourceFile, ec)) {
            INFO(L"  Found: %s", hive.name.c_str());
            m_lastStats.successfulHives++;
            
            auto size = fs::file_size(sourceFile, ec);
            if (!ec) {
                m_lastStats.totalBytes += size;
            }
        }
        else {
            ERROR(L"  Missing: %s", hive.name.c_str());
            m_lastStats.failedHives++;
        }
    }
    
    return m_lastStats.failedHives == 0;
}

// Schedule replacement of a single hive at next boot via RegReplaceKeyW.
//
// SYSTEM hive requires a special flow because direct RegReplaceKeyW on a raw
// backup file returns ERROR_SHARING_VIOLATION (32) for SYSTEM on a live system:
//   1. RegLoadKeyW   -> load backup as HKLM\TMP_SYSTEM (validates + maps file)
//   2. RegSaveKeyExW -> produce a clean hive file via API (no dirty pages)
//   3. RegUnLoadKeyW -> unload TMP_SYSTEM
//   4. RegReplaceKeyW(HKLM, "SYSTEM", cleanFile, bakFile)
//
// All other hives (SOFTWARE, SAM, SECURITY, DEFAULT, user hives):
//   1. CopyFileW(sourceFile -> stagingFile)  - preserve original backup
//   2. RegReplaceKeyW(root, subKey, stagingFile, bakFile)
//
// RegReplaceKeyW registers the swap inside the kernel hive manager.
// At next boot, before SMSS maps hives, the kernel atomically replaces the
// live hive file. No BootExecute entry, no PendingFileRenameOperations.
bool HiveManager::ScheduleHiveReplacement(const RegistryHive& hive, const fs::path& sourceFile)
{
    // Resolve physical path for staging and BAK files
    fs::path physicalPath = GetHivePhysicalPath(hive.name);
    if (physicalPath.empty()) {
        ERROR(L"  Cannot determine physical path for %s", hive.name.c_str());
        return false;
    }

    fs::path stagingFile = fs::path(physicalPath.wstring() + L".TMP");
    fs::path bakFile     = fs::path(physicalPath.wstring() + L".BAK");

    // Parse root key and subkey from registryPath
    HKEY    hRootKey = nullptr;
    std::wstring subKey;

    if (hive.registryPath.starts_with(L"HKLM\\")) {
        hRootKey = HKEY_LOCAL_MACHINE;
        subKey   = hive.registryPath.substr(5); // skip "HKLM\"
    }
    else if (hive.registryPath.starts_with(L"HKU\\")) {
        hRootKey = HKEY_USERS;
        subKey   = hive.registryPath.substr(4); // skip "HKU\"
    }
    else {
        ERROR(L"  Invalid path format for %s", hive.name.c_str());
        return false;
    }

    LONG ret = ERROR_SUCCESS;
    // SYSTEM and SOFTWARE need load+normalize+save to avoid sharing violations with RegReplaceKeyW.
    // BCD has a restrictive DACL that blocks direct staging writes to the EFI partition.
    // UsrClass is a live user hive that benefits from the same clean normalize cycle.
    bool normalized = (hive.name == L"SYSTEM" || hive.name == L"SOFTWARE" ||
                       hive.name == L"BCD"    || hive.name == L"UsrClass");

    if (normalized) {
        // Normalize SYSTEM/SOFTWARE through RegLoadKeyW + RegSaveKeyExW.
        // This avoids dirty/format quirks and lets us sanitize SOFTWARE ProfileList.
        fs::path cleanFile = fs::path(physicalPath.wstring() + L".TMP2");
        std::wstring mountName;

        for (DWORD attempt = 0; attempt < 32; ++attempt) {
            wchar_t buffer[64] = {};
            if (FAILED(StringCchPrintfW(buffer, ARRAYSIZE(buffer), L"TMP_KVC_%s_%lu_%lu",
                                        (hive.name == L"SYSTEM") ? L"SYSTEM" : L"SOFTWARE",
                                        GetCurrentProcessId(), attempt))) {
                return false;
            }
            mountName = buffer;
            ret = RegLoadKeyW(HKEY_LOCAL_MACHINE, mountName.c_str(), sourceFile.c_str());
            if (ret == ERROR_SUCCESS) {
                break;
            }
            if (ret != ERROR_ALREADY_EXISTS) {
                ERROR(L"  %s RegLoadKeyW returned %ld", hive.name.c_str(), ret);
                return false;
            }
        }

        if (ret != ERROR_SUCCESS) {
            ERROR(L"  %s failed to obtain unique temp mount name", hive.name.c_str());
            return false;
        }

        HKEY hTmp = nullptr;
        ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, mountName.c_str(), 0, KEY_READ | KEY_WRITE, &hTmp);
        if (ret != ERROR_SUCCESS) {
            ERROR(L"  %s RegOpenKeyExW(%s) returned %ld", hive.name.c_str(), mountName.c_str(), ret);
            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, mountName.c_str());
            return false;
        }

        if (hive.name == L"SOFTWARE") {
            SanitizeProfileListInSoftwareHive(hTmp);
        }

        DeleteFileW(cleanFile.c_str()); // RegSaveKeyExW does not overwrite
        ret = RegSaveKeyExW(hTmp, cleanFile.c_str(), nullptr, REG_LATEST_FORMAT);
        RegCloseKey(hTmp);
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, mountName.c_str());

        if (ret != ERROR_SUCCESS) {
            ERROR(L"  %s RegSaveKeyExW returned %ld", hive.name.c_str(), ret);
            DeleteFileW(cleanFile.c_str());
            return false;
        }

        DeleteFileW(bakFile.c_str());
        ret = RegReplaceKeyW(hRootKey, subKey.c_str(), cleanFile.c_str(), bakFile.c_str());
        if (ret != ERROR_SUCCESS) {
            ERROR(L"  %s RegReplaceKeyW returned %ld", hive.name.c_str(), ret);
            DeleteFileW(cleanFile.c_str());
            return false;
        }
    } else {
        // Other hives: copy backup to staging so original backup is preserved.
        DeleteFileW(stagingFile.c_str());
        if (!CopyFileW(sourceFile.c_str(), stagingFile.c_str(), FALSE)) {
            ERROR(L"  CopyFileW failed for %s: %lu", hive.name.c_str(), GetLastError());
            return false;
        }

        DeleteFileW(bakFile.c_str()); // RegReplaceKeyW returns ERROR_ALREADY_EXISTS if BAK exists
        ret = RegReplaceKeyW(hRootKey, subKey.c_str(), stagingFile.c_str(), bakFile.c_str());
        if (ret != ERROR_SUCCESS) {
            ERROR(L"  %s RegReplaceKeyW returned %ld", hive.name.c_str(), ret);
            DeleteFileW(stagingFile.c_str());
            return false;
        }
    }

    SUCCESS(L"  Scheduled %s for replacement at next boot", hive.name.c_str());
    return true;
}

bool HiveManager::ApplyRestoreAndReboot(const fs::path& sourceDir)
{
    // Enable backup and restore privileges required by RegReplaceKeyW and RegLoadKeyW
    {
        TokenGuard token;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token.addressof())) {
            TOKEN_PRIVILEGES tp;
            LUID luid;

            if (LookupPrivilegeValueW(nullptr, SE_RESTORE_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token.get(), FALSE, &tp, 0, nullptr, nullptr);
            }

            if (LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token.get(), FALSE, &tp, 0, nullptr, nullptr);
            }
        }
    }

    INFO(L"Scheduling registry hive replacements via RegReplaceKeyW...");

    size_t scheduled = 0;

    for (const auto& hive : m_registryHives) {
        if (!hive.canRestore) {
            INFO(L"  Skipping %s (cannot restore)", hive.name.c_str());
            continue;
        }

        fs::path sourceFile = sourceDir / hive.name;

        std::error_code ec;
        if (!fs::exists(sourceFile, ec)) {
            ERROR(L"  Missing backup file: %s", hive.name.c_str());
            continue;
        }

        INFO(L"  Processing %s...", hive.name.c_str());

        if (ScheduleHiveReplacement(hive, sourceFile)) {
            scheduled++;
        }
    }

    if (scheduled == 0) {
        ERROR(L"No hives were scheduled successfully");
        return false;
    }

    SUCCESS(L"Scheduled %zu hive(s) for replacement at next boot", scheduled);
    INFO(L"Kernel will replace hive files before SMSS maps them - no BootExecute required");
    INFO(L"Initiating system reboot in 10 seconds...");

    // Enable shutdown privilege
    {
        TokenGuard token;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token.addressof())) {
            TOKEN_PRIVILEGES tp;
            LUID luid;

            if (LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token.get(), FALSE, &tp, 0, nullptr, nullptr);
            }
        }
    }

    if (!InitiateSystemShutdownExW(
        nullptr,
        const_cast<LPWSTR>(L"Registry restore complete - system restart required"),
        10,
        TRUE,
        TRUE,
        SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_RECONFIG | SHTDN_REASON_FLAG_PLANNED
    )) {
        ERROR(L"Failed to initiate shutdown: %d", GetLastError());
        INFO(L"Please restart the system manually");
        return false;
    }

    SUCCESS(L"System reboot initiated");
    return true;
}

bool HiveManager::Restore(const std::wstring& sourcePath)
{
    ResetStats();
    
    fs::path restoreDir = sourcePath;
    
    if (!ValidateRestoreDirectory(restoreDir)) {
        return false;
    }
    
    if (!ElevateToTrustedInstaller()) {
        return false;
    }
    
    INFO(L"Starting registry restore from: %s", restoreDir.c_str());
    
    bool validated = RestoreRegistryHives(restoreDir);
    
    PrintStats(L"Restore Validation");
    
    if (!validated) {
        ERROR(L"Restore validation failed - missing backup files");
        return false;
    }
    
    INFO(L"All backup files validated successfully");
    INFO(L"WARNING: Registry restore will modify system hives and requires restart");
    
    if (PromptYesNo(L"Apply restore and reboot now? (Y/N):")) {
        return ApplyRestoreAndReboot(restoreDir);
    }
    
    INFO(L"Restore cancelled by user");
    return false;
}

bool HiveManager::Defrag(const std::wstring& tempPath)
{
    INFO(L"Starting registry defragmentation (backup with compression)");
    
    fs::path defragPath;
    if (tempPath.empty()) {
        defragPath = fs::temp_directory_path() / (L"Registry_Defrag_" + TimeUtils::GetFormattedTimestamp("datetime_file"));
    }
    else {
        defragPath = tempPath;
    }
    
    INFO(L"Using temporary path: %s", defragPath.c_str());
    
    if (!Backup(defragPath.wstring())) {
        ERROR(L"Defrag failed at backup stage");
        return false;
    }
    
    INFO(L"Defragmented backup created successfully");
    INFO(L"Backup location: %s", defragPath.c_str());
    
    // Validate that every scheduled hive was actually written before committing to a replace cycle.
    // This mirrors the validation step in Restore and ensures no hive is silently skipped.
    ResetStats();
    bool validated = RestoreRegistryHives(defragPath);
    PrintStats(L"Defrag Validation");

    if (!validated) {
        ERROR(L"Defrag aborted - one or more hive files are missing from the export");
        return false;
    }

    INFO(L"All defragmented hive files validated");
    INFO(L"WARNING: Registry defrag will modify system hives and requires restart");
    
    if (PromptYesNo(L"Apply defragmented hives and reboot now? (Y/N):")) {
        return ApplyRestoreAndReboot(defragPath);
    }
    
    SUCCESS(L"Defragmentation backup completed");
    INFO(L"You can manually restore from: %s", defragPath.c_str());
    return true;
}
