#pragma once

// WmiDefenderClient.h
// Direct WMI/COM interface to MSFT_MpPreference in ROOT\Microsoft\Windows\Defender
// Replaces powershell.exe -Command "Add-MpPreference / Remove-MpPreference" spawning.
// Initializes COM locally, so callers do not need to do CoInitializeEx beforehand.

#include <windows.h>
#include <wbemidl.h>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <algorithm>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "oleaut32.lib")

// RAII wrapper for COM interface pointers
template<typename T>
struct ComPtr {
    T* p = nullptr;
    ComPtr() = default;
    explicit ComPtr(T* raw) : p(raw) {}
    ~ComPtr() { if (p) p->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& o) noexcept : p(o.p) { o.p = nullptr; }
    ComPtr& operator=(ComPtr&& o) noexcept { if (p) p->Release(); p = o.p; o.p = nullptr; return *this; }
    T** operator&() { return &p; }
    T* operator->() { return p; }
    explicit operator bool() const { return p != nullptr; }
};

// RAII wrapper for SAFEARRAY
struct SafeArrayGuard {
    SAFEARRAY* sa = nullptr;
    explicit SafeArrayGuard(SAFEARRAY* s) : sa(s) {}
    ~SafeArrayGuard() { if (sa) SafeArrayDestroy(sa); }
    SafeArrayGuard(const SafeArrayGuard&) = delete;
};

// RAII wrapper for VARIANT (VariantClear on destroy)
struct VariantGuard {
    VARIANT v;
    VariantGuard() { VariantInit(&v); }
    ~VariantGuard() { VariantClear(&v); }
    VARIANT* operator&() { return &v; }
    VariantGuard(const VariantGuard&) = delete;
};

// Manages a single session with ROOT\Microsoft\Windows\Defender WMI namespace.
// Add/Remove methods mirror Add-MpPreference / Remove-MpPreference cmdlets.
// The caller is responsible for running in a context with sufficient privileges
// (SYSTEM / TrustedInstaller) — same requirement as the old PowerShell spawn.
class WmiDefenderClient
{
public:
    WmiDefenderClient();
    ~WmiDefenderClient();

    // Exclusion types matching MSFT_MpPreference parameter names
    enum class ExclusionType {
        Path,       // ExclusionPath
        Process,    // ExclusionProcess
        Extension,  // ExclusionExtension
        IpAddress   // ExclusionIpAddress
    };

    // Returns true if the WMI namespace connected successfully
    bool IsConnected() const noexcept { return static_cast<bool>(m_pSvc); }

    // Add a single exclusion value — equivalent to Add-MpPreference -<Type> <value>
    // No-ops (returns true) if the value is already present.
    bool Add(ExclusionType type, std::wstring_view value) noexcept;

    // Remove a single exclusion value — equivalent to Remove-MpPreference -<Type> <value>
    bool Remove(ExclusionType type, std::wstring_view value) noexcept;

    // Queries live MSFT_MpPreference instance; case-insensitive check.
    // Returns false on any WMI error (safe to call before Add).
    bool HasExclusion(ExclusionType type, std::wstring_view value) noexcept;

private:
    ComPtr<IWbemServices> m_pSvc;
    bool m_comInitialized = false;

    // Executes MSFT_MpPreference::<method>(ExclusionXxx = [value])
    bool ExecMpMethod(const wchar_t* method, const wchar_t* paramName,
                      std::wstring_view value) noexcept;

    // Reads ExclusionXxx SAFEARRAY<BSTR> from the live singleton instance.
    std::vector<std::wstring> QueryExclusionArray(const wchar_t* paramName) noexcept;

    // Maps ExclusionType → WMI parameter name
    static const wchar_t* ParamNameFor(ExclusionType type) noexcept;
};
