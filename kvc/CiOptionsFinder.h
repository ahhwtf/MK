// CiOptionsFinder.h
// Locates g_CiOptions in the loaded ci.dll kernel module.
//
// Win11 strategy: CiPolicy section found -> RIP-relative probe into CiPolicy -> build fallback.
// Win10 strategy: no CiPolicy section -> RIP-relative probe into .data with high/low-bit scoring.

#pragma once

#include "kvcDrv.h"
#include <memory>
#include <optional>
#include <utility>
#include <string>

class CiOptionsFinder {
public:
    explicit CiOptionsFinder(std::unique_ptr<kvc>& driver) noexcept;

    // Find g_CiOptions kernel address given the live ci.dll kernel base.
    // Returns 0 on failure.
    ULONG_PTR FindCiOptions(ULONG_PTR ciBase) noexcept;

private:
    std::unique_ptr<kvc>& m_driver;

    // Live kernel PE walk via driver reads - finds CiPolicy section address+size.
    std::optional<std::pair<ULONG_PTR, SIZE_T>> GetCiPolicySection(ULONG_PTR moduleBase) noexcept;

    // Offline disk probe: scan code sections of ci.dll for RIP-relative refs into CiPolicy.
    std::optional<DWORD> FindCiOptionsOffsetFromCiPolicy(const std::wstring& ciPath,
                                                          ULONG_PTR ciPolicyStart,
                                                          SIZE_T ciPolicySize) noexcept;

    // Build-number-based fallback offset (+0x4 pre-26H1, +0x8 from 26H1).
    std::optional<DWORD> GetCiOptionsBuildFallbackOffset() noexcept;

    // Win10 path: scan RIP-relative refs into .data with high/low-bit family scoring.
    // Returns kernel address directly (ciBase + rva), or nullopt on failure.
    std::optional<ULONG_PTR> FindCiOptionsInDataSection(const std::wstring& ciPath,
                                                         ULONG_PTR ciBase) noexcept;

    // Resolve on-disk path to ci.dll.
    std::optional<std::wstring> GetCiDllPath() noexcept;
};
