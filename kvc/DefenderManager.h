// DefenderManager.h
// Windows Defender engine control via IFEO registry manipulation.
//
// disable: offline hive edit adds Debugger=systray.exe to MsMpEng.exe IFEO key.
//          Windows loader intercepts every subsequent launch — restart required
//          because the engine is already running.
// enable:  offline hive edit removes the Debugger block, then starts WinDefend
//          via SCM so the engine re-launches immediately — no restart needed.
//
// Both operations use RegSaveKeyEx → RegLoadKey(TempIFEO) → edit →
// RegUnLoadKey → RegRestoreKey(REG_FORCE_RESTORE) to bypass the DACL on the
// IFEO subtree.  Only SE_BACKUP_NAME + SE_RESTORE_NAME are required.

#pragma once

#include <windows.h>
#include <string>
#include <vector>

class DefenderManager {
public:
    // Coarse summary for the status display.
    enum class SecurityState {
        ACTIVE,         // Engine running, no IFEO block
        IFEO_BLOCKED,   // Debugger intercept set — engine dead or will die after restart
        INACTIVE,       // WinDefend stopped, no IFEO block (another AV or manual stop)
        NOT_INSTALLED,  // WinDefend service absent
        UNKNOWN
    };

    // Rich point-in-time snapshot returned by QueryStatus().
    struct DefenderStatus {
        SecurityState   state;
        bool            ifeoBlocked;        // Debugger value present on MsMpEng.exe IFEO key
        bool            winDefendRunning;   // WinDefend service in SERVICE_RUNNING state
        bool            msmpengRunning;     // MsMpEng.exe process visible in snapshot
        std::wstring    ifeoDebugger;       // Current Debugger value, empty if not set
    };

    // Offline IFEO edit — adds Debugger block.  Restart required to take full effect.
    static bool DisableSecurityEngine() noexcept;

    // Offline IFEO edit — removes Debugger block, then starts WinDefend via SCM.
    static bool EnableSecurityEngine() noexcept;

    // Full three-part status query (IFEO + service + process).
    static DefenderStatus QueryStatus() noexcept;

    // Derived single-value state for callers that only need a summary.
    static SecurityState GetSecurityEngineStatus() noexcept;

private:
    // RAII holder for the temporary hive file and associated transaction artefacts.
    struct HiveContext {
        std::wstring tempPath;
        std::wstring hiveFile;

        HiveContext()  = default;
        ~HiveContext() { Cleanup(); }
        HiveContext(const HiveContext&)            = delete;
        HiveContext& operator=(const HiveContext&) = delete;
        HiveContext(HiveContext&&)                 = default;
        HiveContext& operator=(HiveContext&&)      = default;

        void Cleanup() noexcept;
    };

    // Enable SE_BACKUP_NAME + SE_RESTORE_NAME on the current token.
    static bool EnableRequiredPrivileges() noexcept;

    // Save HKLM\IFEO_KEY → hiveFile, load as HKLM\TempIFEO.
    static bool CreateIFEOSnapshot(HiveContext& ctx) noexcept;

    // Create or remove HKLM\TempIFEO\MsMpEng.exe Debugger value.
    static bool ModifyMsMpEngIFEO(const HiveContext& ctx, bool addBlock) noexcept;

    // Unload TempIFEO, restore hiveFile → HKLM\IFEO_KEY (REG_FORCE_RESTORE).
    static bool RestoreIFEOSnapshot(const HiveContext& ctx) noexcept;

    // Open SCM and call StartService on WinDefend.
    static bool StartWinDefend() noexcept;

    // Snapshot process list and look for MsMpEng.exe.
    static bool IsMsMpEngRunning() noexcept;

    // Query WinDefend service status.
    static bool IsWinDefendRunning() noexcept;

    // Registry path constants.
    static constexpr const wchar_t* IFEO_KEY =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    static constexpr const wchar_t* MSMPENG_SUBKEY =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MsMpEng.exe";
    static constexpr const wchar_t* TEMP_HIVE_NAME  = L"TempIFEO";
    static constexpr const wchar_t* DEBUGGER_VALUE  = L"Debugger";
    static constexpr const wchar_t* DEBUGGER_PAYLOAD = L"systray.exe";
    static constexpr const wchar_t* WINDEFEND_SVC   = L"WinDefend";
};
