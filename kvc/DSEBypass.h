// DSEBypass.h
// Unified DSE Bypass Manager - combines Standard and Safe (PDB-based) methods.
// g_CiOptions location is delegated to CiOptionsFinder.

#pragma once

#include "kvcDrv.h"
#include "SymbolEngine.h"
#include "SessionManager.h"
#include "CiOptionsFinder.h"
#include <memory>
#include <optional>
#include <utility>
#include <string>

// Forward declaration
class TrustedInstallerIntegrator;

class DSEBypass {
public:
    // Bypass method selection
    enum class Method {
        Standard,   // g_CiOptions modification + HVCI bypass via skci.dll rename
        Safe        // PDB-based SeCiCallbacks patching (preserves VBS)
    };

    // DSE state for Safe method
    enum class DSEState {
        UNKNOWN,
        NORMAL,      // DSE enabled, original callback active
        PATCHED,     // DSE disabled, ZwFlush callback active
        CORRUPTED    // Unknown callback value
    };

    // Status information structure
    struct Status {
        ULONG_PTR CiOptionsAddress;
        DWORD     CiOptionsValue;
        bool      DSEEnabled;
        bool      HVCIEnabled;
        DWORD64   SavedCallback;   // For Safe method state tracking
    };

    DSEBypass(std::unique_ptr<kvc>& driver, TrustedInstallerIntegrator* ti);
    ~DSEBypass() = default;

    // ========================================================================
    // MAIN OPERATIONS
    // ========================================================================

    bool Disable(Method method) noexcept;
    bool Restore(Method method) noexcept;

    // ========================================================================
    // STATUS AND DIAGNOSTICS
    // ========================================================================

    bool GetStatus(Status& outStatus) noexcept;
    DSEState CheckSafeMethodState() noexcept;
    static std::wstring GetDSEStateString(DSEState state);

    ULONG_PTR GetCiOptionsAddress() const noexcept { return m_ciOptionsAddr; }
    DWORD     GetOriginalValue()    const noexcept { return m_originalCiOptions; }

    // ========================================================================
    // KERNEL MODULE HELPERS (public for Controller status checks)
    // ========================================================================

    std::optional<ULONG_PTR> GetKernelModuleBase(const char* moduleName) noexcept;

    // Thin wrapper - delegates to m_ciFinder.
    ULONG_PTR FindCiOptions(ULONG_PTR ciBase) noexcept;

    std::optional<std::pair<DWORD64, std::wstring>> GetKernelInfo() noexcept;

    // ========================================================================
    // HVCI DETECTION
    // ========================================================================

    // Check via g_CiOptions bits.
    // Bits 14=KMCI_ENABLED, 15=KMCI_AUDIT, 16=IUM_ENABLED.
    // On Win11 26H1+ bit 14 (0x4000) may be set even with HVCI off.
    // We consider HVCI enabled only if bit 15 or 16 is set.
    static bool IsHVCIEnabled(DWORD ciOptionsValue) noexcept {
        return (ciOptionsValue & 0x00018000) != 0;
    }

    // A direct write to g_CiOptions is unsafe whenever any KMCI/IUM mode bit
    // is present. In particular, 0x4000 can describe a runtime-protected
    // CiPolicy page even when the registry does not report HVCI as enabled.
    static bool IsDirectCiPatchUnsafe(DWORD ciOptionsValue) noexcept {
        return (ciOptionsValue & 0x0001C000) != 0;
    }

    // Registry fallback for 26H1+ where hypervisor may not expose HVCI bits.
    static bool CheckHVCIRegistry() noexcept;

    // ========================================================================
    // HVCI BYPASS (public for Controller to call after user confirmation)
    // ========================================================================

    bool RenameSkciLibrary()      noexcept;
    bool CreatePendingFileRename() noexcept;

private:
    std::unique_ptr<kvc>&       m_driver;
    TrustedInstallerIntegrator* m_trustedInstaller;
    CiOptionsFinder             m_ciFinder;
    SymbolEngine                m_symbolEngine;  // Lazy-initialized for Safe method

    // Cached state
    ULONG_PTR m_ciOptionsAddr    = 0;
    DWORD     m_originalCiOptions = 0;

    // ========================================================================
    // STANDARD METHOD
    // ========================================================================

    bool DisableStandard() noexcept;
    bool RestoreStandard() noexcept;
    bool RestoreSkciLibrary() noexcept;

    // ========================================================================
    // SAFE METHOD (SeCiCallbacks patching)
    // ========================================================================

    bool DisableSafe()  noexcept;
    bool RestoreSafe()  noexcept;

    std::wstring GetCurrentLCUVersion() noexcept;

    bool ApplyCallbackPatch(DWORD64 targetAddress,
                            DWORD64 safeFunction,
                            DWORD64 originalCallback) noexcept;
    bool RestoreCallbackPatch(DWORD64 targetAddress,
                              DWORD64 originalCallback) noexcept;
    bool ValidateOffsets(DWORD64 offSeCi,
                         DWORD64 offZwFlush,
                         DWORD64 kernelBase) noexcept;
};
