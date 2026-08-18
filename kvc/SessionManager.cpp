// SessionManager.cpp
// Session state management and DSE-NG symbol cache with LCUVer validation

#include "SessionManager.h"
#include "Controller.h"
#include "Utils.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// Static cache cleared on reboot detection
static std::wstring g_cachedBootSession;

namespace {

constexpr ULONG kSystemBootEnvironmentInformation = 90;
constexpr wchar_t kDseStateKey[] = L"Software\\kvc\\DSE";
constexpr wchar_t kOriginalCiCallbackValue[] = L"OriginalCiCallback";
constexpr wchar_t kOriginalCiCallbackBootIdValue[] = L"OriginalCiCallbackBootId";
constexpr wchar_t kOriginalCiOptionsValue[] = L"OriginalCiOptions";
constexpr wchar_t kOriginalCiOptionsBootIdValue[] = L"OriginalCiOptionsBootId";

struct BootEnvironmentInformation {
    GUID      BootIdentifier;
    ULONG     FirmwareType;
    ULONGLONG BootFlags;
};

using NtQuerySystemInformationFn = NTSTATUS (NTAPI *)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

bool GetCurrentBootIdentifier(GUID& bootIdentifier) noexcept
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

    auto querySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!querySystemInformation)
        return false;

    BootEnvironmentInformation information{};
    NTSTATUS status = querySystemInformation(
        static_cast<SYSTEM_INFORMATION_CLASS>(kSystemBootEnvironmentInformation),
        &information, sizeof(information), nullptr);
    if (status < 0)
        return false;

    bootIdentifier = information.BootIdentifier;
    return true;
}

} // namespace

// ============================================================================
// SESSION MANAGEMENT (existing functionality)
// ============================================================================

std::wstring SessionManager::CalculateBootTime() noexcept
{
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULONGLONG currentTime = (static_cast<ULONGLONG>(ftNow.dwHighDateTime) << 32) | ftNow.dwLowDateTime;
    ULONGLONG tickCount = GetTickCount64();
    ULONGLONG bootTime = currentTime - (tickCount * 10000ULL);
    
    std::wostringstream oss;
    oss << bootTime;
    return oss.str();
}

ULONGLONG SessionManager::GetLastBootIdFromRegistry() noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;
    
    ULONGLONG lastBootId = 0;
    DWORD dataSize = sizeof(ULONGLONG);
    RegQueryValueExW(hKey, L"LastBootId", nullptr, nullptr, reinterpret_cast<BYTE*>(&lastBootId), &dataSize);
    
    RegCloseKey(hKey);
    return lastBootId;
}

void SessionManager::SaveLastBootId(ULONGLONG bootId) noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey = OpenOrCreateKey(basePath);
    
    if (hKey)
    {
        RegSetValueExW(hKey, L"LastBootId", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&bootId), sizeof(ULONGLONG));
        RegCloseKey(hKey);
    }
}

ULONGLONG SessionManager::GetLastTickCountFromRegistry() noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;
    
    ULONGLONG lastTickCount = 0;
    DWORD dataSize = sizeof(ULONGLONG);
    RegQueryValueExW(hKey, L"LastTickCount", nullptr, nullptr, reinterpret_cast<BYTE*>(&lastTickCount), &dataSize);
    
    RegCloseKey(hKey);
    return lastTickCount;
}

void SessionManager::SaveLastTickCount(ULONGLONG tickCount) noexcept
{
    std::wstring basePath = GetRegistryBasePath();
    HKEY hKey = OpenOrCreateKey(basePath);
    
    if (hKey)
    {
        RegSetValueExW(hKey, L"LastTickCount", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&tickCount), sizeof(ULONGLONG));
        RegCloseKey(hKey);
    }
}

std::wstring SessionManager::GetCurrentBootSession() noexcept
{
    if (!g_cachedBootSession.empty())
        return g_cachedBootSession;
    
    ULONGLONG lastBootId = GetLastBootIdFromRegistry();
    
    if (lastBootId == 0)
    {
        // First run ever - calculate and save
        std::wstring calculatedSession = CalculateBootTime();
        ULONGLONG calculatedBootId = std::stoull(calculatedSession);
        SaveLastBootId(calculatedBootId);
        g_cachedBootSession = calculatedSession;
        return g_cachedBootSession;
    }
    
    // Use LastBootId from registry as session ID
    std::wostringstream oss;
    oss << lastBootId;
    g_cachedBootSession = oss.str();
    
    return g_cachedBootSession;
}

void SessionManager::DetectAndHandleReboot() noexcept
{
    ULONGLONG currentTick = GetTickCount64();
    ULONGLONG lastTick = GetLastTickCountFromRegistry();
    ULONGLONG lastBootId = GetLastBootIdFromRegistry();
    
    if (lastBootId == 0)
    {
        // First run ever
        std::wstring calculatedSession = CalculateBootTime();
        ULONGLONG calculatedBootId = std::stoull(calculatedSession);
        SaveLastBootId(calculatedBootId);
        SaveLastTickCount(currentTick);
        g_cachedBootSession = calculatedSession;
        return;
    }
    
    // Detect reboot: tickCount decreased
    if (currentTick < lastTick)
    {
        // New boot detected
        std::wstring calculatedSession = CalculateBootTime();
        ULONGLONG calculatedBootId = std::stoull(calculatedSession);
        SaveLastBootId(calculatedBootId);
        SaveLastTickCount(currentTick);
        g_cachedBootSession = calculatedSession;
        
        // Enforce session limit
        EnforceSessionLimit(16); // Default 16 sessions
    }
    else
    {
        // Same boot - use LastBootId as session ID
        SaveLastTickCount(currentTick);
        std::wostringstream oss;
        oss << lastBootId;
        g_cachedBootSession = oss.str();
    }
}

std::vector<std::wstring> SessionManager::GetAllSessionIds() noexcept
{
    std::vector<std::wstring> sessionIds;
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hSessions) != ERROR_SUCCESS)
        return sessionIds;
    
    DWORD index = 0;
    wchar_t sessionName[256];
    DWORD sessionNameSize;
    
    while (true)
    {
        sessionNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, sessionName, &sessionNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        sessionIds.push_back(sessionName);
        index++;
    }
    
    RegCloseKey(hSessions);
    return sessionIds;
}

void SessionManager::EnforceSessionLimit(int maxSessions) noexcept
{
    auto sessions = GetAllSessionIds();
    
    if (static_cast<int>(sessions.size()) <= maxSessions)
        return;
    
    // Sort sessions by ID (oldest first)
    std::sort(sessions.begin(), sessions.end(), [](const std::wstring& a, const std::wstring& b) {
        try {
            return std::stoull(a) < std::stoull(b);
        } catch (...) {
            return a < b;
        }
    });
    
    std::wstring currentSession = GetCurrentBootSession();
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_WRITE, &hSessions) != ERROR_SUCCESS)
        return;
    
    int toDelete = static_cast<int>(sessions.size()) - maxSessions;
    int deleted = 0;
    
    for (const auto& sessionId : sessions)
    {
        if (deleted >= toDelete)
            break;
        
        if (sessionId != currentSession)
        {
            DeleteKeyRecursive(hSessions, sessionId);
            DEBUG(L"Deleted old session: %s", sessionId.c_str());
            deleted++;
        }
    }
    
    RegCloseKey(hSessions);
    
    if (deleted > 0)
    {
        INFO(L"Enforced session limit: deleted %d old sessions", deleted);
    }
}

void SessionManager::CleanupAllSessionsExceptCurrent() noexcept
{
    std::wstring currentSession = GetCurrentBootSession();
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ | KEY_WRITE, &hSessions) != ERROR_SUCCESS)
    {
        INFO(L"No sessions to cleanup");
        return;
    }
    
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::vector<std::wstring> keysToDelete;
    
    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        std::wstring keyName = subKeyName;
        if (keyName != currentSession)
            keysToDelete.push_back(keyName);
        
        index++;
    }
    
    for (const auto& key : keysToDelete)
    {
        DeleteKeyRecursive(hSessions, key);
    }
    
    RegCloseKey(hSessions);
    
    if (!keysToDelete.empty())
    {
        SUCCESS(L"Cleaned up %zu old sessions (kept current session)", keysToDelete.size());
    }
    else
    {
        INFO(L"No old sessions to cleanup");
    }
}

std::wstring SessionManager::GetRegistryBasePath() noexcept
{
    return L"Software\\kvc";
}

std::wstring SessionManager::GetSessionPath(const std::wstring& sessionId) noexcept
{
    return GetRegistryBasePath() + L"\\Sessions\\" + sessionId;
}

bool SessionManager::SaveUnprotectOperation(const std::wstring& signerName, 
                                           const std::vector<ProcessEntry>& affectedProcesses) noexcept
{
    if (affectedProcesses.empty())
        return true;
    
    // Use original signer name (no normalization)
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    std::wstring signerPath = sessionPath + L"\\" + signerName;
    
    HKEY hKey = OpenOrCreateKey(signerPath);
    if (!hKey)
    {
        ERROR(L"Failed to create registry key for session state");
        return false;
    }
    
    DWORD index = 0;
    for (const auto& proc : affectedProcesses)
    {
        SessionEntry entry;
        entry.Pid = proc.Pid;
        entry.ProcessName = proc.ProcessName;
        entry.OriginalProtection = Utils::GetProtection(proc.ProtectionLevel, proc.SignerType);
        entry.SignatureLevel = proc.SignatureLevel;
        entry.SectionSignatureLevel = proc.SectionSignatureLevel;
        entry.Status = L"UNPROTECTED";
        
        // Format: "PID|ProcessName|Protection|SigLevel|SecSigLevel|Status"
        std::wostringstream oss;
        oss << entry.Pid << L"|"
            << entry.ProcessName << L"|"
            << static_cast<int>(entry.OriginalProtection) << L"|"
            << static_cast<int>(entry.SignatureLevel) << L"|"
            << static_cast<int>(entry.SectionSignatureLevel) << L"|"
            << entry.Status;
        
        std::wstring valueName = L"Proc_" + std::to_wstring(index);
        std::wstring valueData = oss.str();
        
        LONG result = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ, 
                                      reinterpret_cast<const BYTE*>(valueData.c_str()),
                                      static_cast<DWORD>((valueData.length() + 1) * sizeof(wchar_t)));
        
        if (result != ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return false;
        }
        
        index++;
    }
    
    // Write count
    DWORD count = static_cast<DWORD>(affectedProcesses.size());
    RegSetValueExW(hKey, L"Count", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&count), sizeof(DWORD));
    
    RegCloseKey(hKey);
    
    SUCCESS(L"Session state saved to registry (%d processes tracked)", count);
    return true;
}

std::vector<SessionEntry> SessionManager::LoadSessionEntries(const std::wstring& signerName) noexcept
{
    // Normalize signer name for case-insensitive comparison
    std::wstring normalizedSigner = signerName;
    StringUtils::ToLower(normalizedSigner);
    
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    
    HKEY hSession;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) != ERROR_SUCCESS)
        return {};
    
    // Search all subkeys for matching signer (case-insensitive)
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::wstring foundSignerKey;
    
    while (true)
    {
        subKeyNameSize = 256;
        LONG result = RegEnumKeyExW(hSession, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr);
        if (result != ERROR_SUCCESS)
            break;
        
        std::wstring candidate = subKeyName;
        std::wstring normalizedCandidate = candidate;
        StringUtils::ToLower(normalizedCandidate);
        
        if (normalizedCandidate == normalizedSigner) {
            foundSignerKey = candidate;
            break;
        }
        
        index++;
    }
    
    if (foundSignerKey.empty()) {
        RegCloseKey(hSession);
        DEBUG(L"No signer key found for: %s (normalized: %s)", signerName.c_str(), normalizedSigner.c_str());
        return {};
    }
    
    // Load entries using actual key name
    auto entries = LoadSessionEntriesFromPath(sessionPath, foundSignerKey);
    RegCloseKey(hSession);
    
    DEBUG(L"Loaded %zu entries for signer: %s (key: %s)", entries.size(), signerName.c_str(), foundSignerKey.c_str());
    return entries;
}

std::vector<SessionEntry> SessionManager::LoadSessionEntriesFromPath(const std::wstring& sessionPath, 
                                                                     const std::wstring& signerName) noexcept
{
    std::vector<SessionEntry> entries;
    std::wstring signerPath = sessionPath + L"\\" + signerName;
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, signerPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return entries;
    
    DWORD count = 0;
    DWORD dataSize = sizeof(DWORD);
    if (RegQueryValueExW(hKey, L"Count", nullptr, nullptr, reinterpret_cast<BYTE*>(&count), &dataSize) != ERROR_SUCCESS) {
        count = 0;
    }
    
    for (DWORD i = 0; i < count; i++)
    {
        std::wstring valueName = L"Proc_" + std::to_wstring(i);
        wchar_t valueData[512];
        DWORD valueSize = sizeof(valueData);
        
        if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr, 
                            reinterpret_cast<BYTE*>(valueData), &valueSize) == ERROR_SUCCESS)
        {
            // Parse: "PID|ProcessName|Protection|SigLevel|SecSigLevel|Status"
            std::wstring data = valueData;
            std::vector<std::wstring> parts;
            std::wstring current;
            
            for (wchar_t ch : data)
            {
                if (ch == L'|')
                {
                    parts.push_back(current);
                    current.clear();
                }
                else
                {
                    current += ch;
                }
            }
            if (!current.empty())
                parts.push_back(current);
            
            if (parts.size() >= 5)
            {
                SessionEntry entry;
                entry.Pid = static_cast<DWORD>(std::stoul(parts[0]));
                entry.ProcessName = parts[1];
                entry.OriginalProtection = static_cast<UCHAR>(std::stoi(parts[2]));
                entry.SignatureLevel = static_cast<UCHAR>(std::stoi(parts[3]));
                entry.SectionSignatureLevel = static_cast<UCHAR>(std::stoi(parts[4]));
                entry.Status = (parts.size() >= 6) ? parts[5] : L"UNPROTECTED";
                
                entries.push_back(entry);
            }
        }
    }
    
    RegCloseKey(hKey);
    return entries;
}

bool SessionManager::RestoreBySigner(const std::wstring& signerName, Controller* controller) noexcept
{
    if (!controller)
    {
        ERROR(L"Controller not available for restoration");
        return false;
    }
    
    // Find actual signer key name in registry (case-insensitive search)
    std::wstring normalizedSigner = signerName;
    StringUtils::ToLower(normalizedSigner);
    
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    
    HKEY hSession;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) != ERROR_SUCCESS)
    {
        INFO(L"No saved state found for signer: %s", signerName.c_str());
        return false;
    }
    
    // Find actual key name in registry
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::wstring foundSignerKey;
    
    while (true)
    {
        subKeyNameSize = 256;
        LONG result = RegEnumKeyExW(hSession, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr);
        if (result != ERROR_SUCCESS)
            break;
        
        std::wstring candidate = subKeyName;
        std::wstring normalizedCandidate = candidate;
        StringUtils::ToLower(normalizedCandidate);
        
        if (normalizedCandidate == normalizedSigner) {
            foundSignerKey = candidate;
            break;
        }
        
        index++;
    }
    
    RegCloseKey(hSession);
    
    if (foundSignerKey.empty())
    {
        INFO(L"No saved state found for signer: %s", signerName.c_str());
        return false;
    }
    
    // Load entries using actual key name
    auto entries = LoadSessionEntriesFromPath(sessionPath, foundSignerKey);
    
    if (entries.empty())
    {
        INFO(L"No saved state found for signer: %s", signerName.c_str());
        return false;
    }
    
    INFO(L"Restoring protection for %s (%zu processes)", signerName.c_str(), entries.size());
    
    DWORD successCount = 0;
    DWORD skipCount = 0;
    DWORD entryIndex = 0;
    
    for (const auto& entry : entries)
    {
        // Skip if already restored
        if (entry.Status == L"RESTORED")
        {
            skipCount++;
            entryIndex++;
            continue;
        }
        
        // Check if process still exists
        auto kernelAddr = controller->GetProcessKernelAddress(entry.Pid);
        if (!kernelAddr)
        {
            INFO(L"Skipping PID %d (%s) - process no longer exists", entry.Pid, entry.ProcessName.c_str());
            skipCount++;
            entryIndex++;
            continue;
        }
        
        // Restore original protection
        if (controller->SetProcessProtection(kernelAddr.value(), entry.OriginalProtection))
        {
            // Update status in registry
            std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
            std::wstring signerPath = sessionPath + L"\\" + foundSignerKey;
            
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, signerPath.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS)
            {
                // Rebuild entry with new status
                std::wostringstream oss;
                oss << entry.Pid << L"|"
                    << entry.ProcessName << L"|"
                    << static_cast<int>(entry.OriginalProtection) << L"|"
                    << static_cast<int>(entry.SignatureLevel) << L"|"
                    << static_cast<int>(entry.SectionSignatureLevel) << L"|"
                    << L"RESTORED";
                
                std::wstring valueName = L"Proc_" + std::to_wstring(entryIndex);
                std::wstring valueData = oss.str();
                
                RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ, 
                               reinterpret_cast<const BYTE*>(valueData.c_str()),
                               static_cast<DWORD>((valueData.length() + 1) * sizeof(wchar_t)));
                RegCloseKey(hKey);
            }
            
            SUCCESS(L"Restored protection for PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
            successCount++;
        }
        else
        {
            ERROR(L"Failed to restore protection for PID %d (%s)", entry.Pid, entry.ProcessName.c_str());
        }
        
        entryIndex++;
    }
    
    INFO(L"Restoration completed: %d restored, %d skipped", successCount, skipCount);
    return successCount > 0;
}

bool SessionManager::RestoreAll(Controller* controller) noexcept
{
    if (!controller)
    {
        ERROR(L"Controller not available for restoration");
        return false;
    }
    
    std::wstring sessionPath = GetSessionPath(GetCurrentBootSession());
    
    HKEY hSession;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) != ERROR_SUCCESS)
    {
        INFO(L"No saved session state found");
        return false;
    }
    
    // Enumerate all signer subkeys
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    std::vector<std::wstring> signers;
    
    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSession, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        signers.push_back(subKeyName);
        index++;
    }
    
    RegCloseKey(hSession);
    
    if (signers.empty())
    {
        INFO(L"No saved state found in current session");
        return false;
    }
    
    INFO(L"Restoring all protection states (%zu groups)", signers.size());
    
    bool anySuccess = false;
    for (const auto& signer : signers)
    {
        if (RestoreBySigner(signer, controller))
            anySuccess = true;
    }
    
    return anySuccess;
}

void SessionManager::ShowHistory() noexcept
{
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ, &hSessions) != ERROR_SUCCESS)
    {
        INFO(L"No saved session state found (cannot open sessions key)");
        return;
    }

    // Show current calculated boot session ID
    std::wstring currentSession = GetCurrentBootSession();
    INFO(L"Current boot session ID: %s", currentSession.c_str());
    INFO(L"All sessions found in registry:");
    
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    bool foundSessions = false;

    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        std::wstring sessionId = subKeyName;
        std::wcout << L"\nSession: " << sessionId;
        if (sessionId == currentSession) {
            std::wcout << L" [CURRENT]";
        }
        std::wcout << L"\n";
        
        std::wstring sessionPath = basePath + L"\\" + sessionId;
        HKEY hSession;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, sessionPath.c_str(), 0, KEY_READ, &hSession) == ERROR_SUCCESS)
        {
            DWORD signerIndex = 0;
            wchar_t signerName[256];
            DWORD signerNameSize;

            while (true)
            {
                signerNameSize = 256;
                if (RegEnumKeyExW(hSession, signerIndex, signerName, &signerNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    break;

                std::wstring signer = signerName;
                auto entries = LoadSessionEntriesFromPath(sessionPath, signer);
                std::wcout << L"  [" << signer << L"] - " << entries.size() << L" processes\n";

                for (const auto& entry : entries)
                {
                    std::wcout << L"    PID " << entry.Pid << L": " << entry.ProcessName 
                               << L" (protection: 0x" << std::hex << static_cast<int>(entry.OriginalProtection) 
                               << std::dec << L", status: " << entry.Status << L")\n";
                }

                signerIndex++;
                foundSessions = true;
            }
            RegCloseKey(hSession);
        }
        index++;
    }

    RegCloseKey(hSessions);
    
    if (!foundSessions) {
        INFO(L"No session data found in registry");
    }
}

void SessionManager::CleanupStaleSessions() noexcept
{
    std::wstring currentSession = GetCurrentBootSession();
    std::wstring basePath = GetRegistryBasePath() + L"\\Sessions";
    
    HKEY hSessions;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, KEY_READ | KEY_WRITE, &hSessions) != ERROR_SUCCESS)
        return;
    
    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyNameSize;
    
    std::vector<std::wstring> keysToDelete;
    
    while (true)
    {
        subKeyNameSize = 256;
        if (RegEnumKeyExW(hSessions, index, subKeyName, &subKeyNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        std::wstring keyName = subKeyName;
        if (keyName != currentSession)
            keysToDelete.push_back(keyName);
        
        index++;
    }
    
    // Delete stale sessions
    for (const auto& key : keysToDelete)
    {
        DeleteKeyRecursive(hSessions, key);
    }
    
    RegCloseKey(hSessions);
}

HKEY SessionManager::OpenOrCreateKey(const std::wstring& path) noexcept
{
    HKEY hKey;
    DWORD disposition;
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 
                       REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, 
                       &hKey, &disposition) != ERROR_SUCCESS)
    {
        return nullptr;
    }
    
    return hKey;
}

bool SessionManager::DeleteKeyRecursive(HKEY hKeyParent, const std::wstring& subKey) noexcept
{
    HKEY hKey;
    if (RegOpenKeyExW(hKeyParent, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;
    
    // Delete all subkeys first
    wchar_t childName[256];
    DWORD childNameSize;
    
    while (true)
    {
        childNameSize = 256;
        if (RegEnumKeyExW(hKey, 0, childName, &childNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        
        DeleteKeyRecursive(hKey, childName);
    }
    
    RegCloseKey(hKey);
    RegDeleteKeyW(hKeyParent, subKey.c_str());
    
    return true;
}

// ============================================================================
// DSE-NG ORIGINAL CALLBACK MANAGEMENT (simplified)
// ============================================================================
// Note: Offset caching removed - KernelBase changes on every reboot due to KASLR
// Offsets are now always calculated fresh from local or downloaded PDB

bool SessionManager::SaveOriginalCiCallback(DWORD64 address) noexcept
{
    GUID bootIdentifier{};
    if (!GetCurrentBootIdentifier(bootIdentifier)) {
        ERROR(L"Failed to obtain the current boot identifier; original CI callback was not saved");
        return false;
    }

    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kDseStateKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        ERROR(L"Failed to open DSE state registry key");
        return false;
    }

    const LSTATUS bootResult = RegSetValueExW(hKey, kOriginalCiCallbackBootIdValue,
        0, REG_BINARY, reinterpret_cast<const BYTE*>(&bootIdentifier), sizeof(bootIdentifier));
    const LSTATUS valueResult = RegSetValueExW(hKey, kOriginalCiCallbackValue, 0,
        REG_QWORD, reinterpret_cast<const BYTE*>(&address), sizeof(address));

    if (bootResult != ERROR_SUCCESS || valueResult != ERROR_SUCCESS) {
        RegDeleteValueW(hKey, kOriginalCiCallbackBootIdValue);
        RegDeleteValueW(hKey, kOriginalCiCallbackValue);
        RegCloseKey(hKey);
        ERROR(L"Failed to persist original CI callback state");
        return false;
    }

    RegCloseKey(hKey);
    DEBUG(L"Saved OriginalCiCallback: 0x%llX to registry", address);
    return true;
}

DWORD64 SessionManager::GetOriginalCiCallback() noexcept
{
    GUID currentBootIdentifier{};
    if (!GetCurrentBootIdentifier(currentBootIdentifier))
        return 0;

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kDseStateKey, 0,
        KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;

    GUID savedBootIdentifier{};
    DWORD64 value = 0;
    DWORD bootType = 0;
    DWORD valueType = 0;
    DWORD bootSize = sizeof(savedBootIdentifier);
    DWORD valueSize = sizeof(value);
    const LSTATUS bootResult = RegQueryValueExW(hKey, kOriginalCiCallbackBootIdValue,
        nullptr, &bootType, reinterpret_cast<BYTE*>(&savedBootIdentifier), &bootSize);
    const LSTATUS valueResult = RegQueryValueExW(hKey, kOriginalCiCallbackValue,
        nullptr, &valueType, reinterpret_cast<BYTE*>(&value), &valueSize);
    RegCloseKey(hKey);

    if (bootResult != ERROR_SUCCESS || bootType != REG_BINARY ||
        bootSize != sizeof(savedBootIdentifier) || valueResult != ERROR_SUCCESS ||
        valueType != REG_QWORD || valueSize != sizeof(value))
        return 0;

    if (memcmp(&savedBootIdentifier, &currentBootIdentifier,
        sizeof(currentBootIdentifier)) != 0) {
        INFO(L"Ignoring saved CI callback from a different boot session");
        return 0;
    }

    DEBUG(L"Loaded OriginalCiCallback: 0x%llX from registry", value);
    return value;
}

void SessionManager::ClearOriginalCiCallback() noexcept
{
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kDseStateKey, 0, 
        KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, kOriginalCiCallbackValue);
        RegDeleteValueW(hKey, kOriginalCiCallbackBootIdValue);
        RegCloseKey(hKey);
        DEBUG(L"Cleared OriginalCiCallback from registry");
    }
}

bool SessionManager::SaveOriginalCiOptions(DWORD value) noexcept
{
    GUID bootIdentifier{};
    if (!GetCurrentBootIdentifier(bootIdentifier)) {
        ERROR(L"Failed to obtain the current boot identifier; original g_CiOptions was not saved");
        return false;
    }

    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kDseStateKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        ERROR(L"Failed to open DSE state registry key");
        return false;
    }

    const LSTATUS bootResult = RegSetValueExW(hKey, kOriginalCiOptionsBootIdValue,
        0, REG_BINARY, reinterpret_cast<const BYTE*>(&bootIdentifier), sizeof(bootIdentifier));
    const LSTATUS valueResult = RegSetValueExW(hKey, kOriginalCiOptionsValue,
        0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));

    if (bootResult != ERROR_SUCCESS || valueResult != ERROR_SUCCESS) {
        RegDeleteValueW(hKey, kOriginalCiOptionsBootIdValue);
        RegDeleteValueW(hKey, kOriginalCiOptionsValue);
        RegCloseKey(hKey);
        ERROR(L"Failed to persist original g_CiOptions state");
        return false;
    }

    RegCloseKey(hKey);
    DEBUG(L"Saved original g_CiOptions: 0x%08X", value);
    return true;
}

std::optional<DWORD> SessionManager::GetOriginalCiOptions() noexcept
{
    GUID currentBootIdentifier{};
    if (!GetCurrentBootIdentifier(currentBootIdentifier))
        return std::nullopt;

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kDseStateKey, 0, KEY_READ,
        &hKey) != ERROR_SUCCESS)
        return std::nullopt;

    GUID savedBootIdentifier{};
    DWORD savedValue = 0;
    DWORD bootType = 0;
    DWORD valueType = 0;
    DWORD bootSize = sizeof(savedBootIdentifier);
    DWORD valueSize = sizeof(savedValue);
    const LSTATUS bootResult = RegQueryValueExW(hKey, kOriginalCiOptionsBootIdValue,
        nullptr, &bootType, reinterpret_cast<BYTE*>(&savedBootIdentifier), &bootSize);
    const LSTATUS valueResult = RegQueryValueExW(hKey, kOriginalCiOptionsValue,
        nullptr, &valueType, reinterpret_cast<BYTE*>(&savedValue), &valueSize);
    RegCloseKey(hKey);

    if (bootResult != ERROR_SUCCESS || bootType != REG_BINARY ||
        bootSize != sizeof(savedBootIdentifier) || valueResult != ERROR_SUCCESS ||
        valueType != REG_DWORD || valueSize != sizeof(savedValue))
        return std::nullopt;

    if (memcmp(&savedBootIdentifier, &currentBootIdentifier,
        sizeof(currentBootIdentifier)) != 0) {
        INFO(L"Ignoring saved g_CiOptions from a different boot session");
        return std::nullopt;
    }

    return savedValue;
}

void SessionManager::ClearOriginalCiOptions() noexcept
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kDseStateKey, 0, KEY_WRITE,
        &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, kOriginalCiOptionsValue);
        RegDeleteValueW(hKey, kOriginalCiOptionsBootIdValue);
        RegCloseKey(hKey);
    }
}
