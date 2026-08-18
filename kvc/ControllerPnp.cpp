#include "Controller.h"
#include "Common.h"

#include <Windows.h>
#include <SetupAPI.h>
#include <newdev.h>

#include <algorithm>
#include <filesystem>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")

namespace
{
    class device_info_guard
    {
    public:
        explicit device_info_guard(HDEVINFO value) noexcept : value_(value) {}
        ~device_info_guard()
        {
            if (value_ != INVALID_HANDLE_VALUE)
                SetupDiDestroyDeviceInfoList(value_);
        }

        device_info_guard(const device_info_guard&) = delete;
        device_info_guard& operator=(const device_info_guard&) = delete;

        HDEVINFO get() const noexcept { return value_; }

    private:
        HDEVINFO value_ = INVALID_HANDLE_VALUE;
    };

    bool remove_created_devnode(HDEVINFO set, SP_DEVINFO_DATA& device) noexcept
    {
        SP_REMOVEDEVICE_PARAMS remove{};
        remove.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        remove.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        remove.Scope = DI_REMOVEDEVICE_GLOBAL;
        remove.HwProfile = 0;

        if (!SetupDiSetClassInstallParamsW(
                set,
                &device,
                &remove.ClassInstallHeader,
                sizeof(remove)))
        {
            ERROR(L"Failed to stage removal of orphaned devnode: %lu", GetLastError());
            return false;
        }

        if (!SetupDiCallClassInstaller(DIF_REMOVE, set, &device))
        {
            ERROR(L"Failed to remove orphaned devnode: %lu", GetLastError());
            return false;
        }

        return true;
    }

    bool device_has_hardware_id(
        HDEVINFO set,
        SP_DEVINFO_DATA& device,
        const std::wstring& hardwareId) noexcept
    {
        wchar_t ids[4096]{};
        DWORD propertyType = 0;
        DWORD required = 0;
        if (!SetupDiGetDeviceRegistryPropertyW(
                set,
                &device,
                SPDRP_HARDWAREID,
                &propertyType,
                reinterpret_cast<PBYTE>(ids),
                sizeof(ids),
                &required))
        {
            return false;
        }

        for (const wchar_t* id = ids; *id != L'\0'; id += wcslen(id) + 1)
        {
            if (_wcsicmp(id, hardwareId.c_str()) == 0)
                return true;
        }

        return false;
    }

    bool find_device_by_hardware_id(
        HDEVINFO set,
        const std::wstring& hardwareId,
        SP_DEVINFO_DATA& device) noexcept
    {
        for (DWORD index = 0;; ++index)
        {
            SP_DEVINFO_DATA candidate{};
            candidate.cbSize = sizeof(candidate);
            if (!SetupDiEnumDeviceInfo(set, index, &candidate))
                return false;

            if (device_has_hardware_id(set, candidate, hardwareId))
            {
                device = candidate;
                return true;
            }
        }
    }

}

bool Controller::InstallPnpDriver(
    const std::wstring& infPath,
    const std::wstring& hardwareId) noexcept
{
    if (infPath.empty() || hardwareId.empty())
    {
        ERROR(L"INF path and hardware ID are required");
        return false;
    }

    std::error_code pathError;
    const std::filesystem::path absoluteInf = std::filesystem::absolute(infPath, pathError);
    if (pathError || !std::filesystem::is_regular_file(absoluteInf, pathError))
    {
        ERROR(L"INF file not found: %s", infPath.c_str());
        return false;
    }

    GUID classGuid{};
    wchar_t className[256]{};
    if (!SetupDiGetINFClassW(
            absoluteInf.c_str(),
            &classGuid,
            className,
            ARRAYSIZE(className),
            nullptr))
    {
        ERROR(L"SetupDiGetINFClass failed: %lu", GetLastError());
        return false;
    }

    // Extension INFs target an existing device whose setup class is usually
    // different from the INF's Extension class. Search every device --
    // DIGCF_PRESENT is deliberately omitted: a root-enumerated devnode whose
    // driver failed to load (e.g. CM_PROB_UNSIGNED_DRIVER) still needs to be
    // found here so it gets reused/removed instead of leaking a fresh
    // ROOT\<class>\NNNN devnode on every retry.
    device_info_guard devices(SetupDiGetClassDevsW(
        nullptr, nullptr, nullptr, DIGCF_ALLCLASSES));
    if (devices.get() == INVALID_HANDLE_VALUE)
    {
        ERROR(L"SetupDiGetClassDevs failed: %lu", GetLastError());
        return false;
    }

    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    const bool existingDevice = find_device_by_hardware_id(devices.get(), hardwareId, device);
    if (existingDevice)
    {
        INFO(L"Reusing existing PnP device for hardware ID: %s", hardwareId.c_str());
    }
    else
    {
        if (_wcsicmp(className, L"Extension") == 0)
        {
            ERROR(L"Extension INF target was not found; refusing to create a root devnode");
            return false;
        }

        if (!SetupDiCreateDeviceInfoW(
                devices.get(),
                className,
                &classGuid,
                nullptr,
                nullptr,
                DICD_GENERATE_ID,
                &device))
        {
            ERROR(L"SetupDiCreateDeviceInfo failed: %lu", GetLastError());
            return false;
        }

        std::vector<wchar_t> multiSz(hardwareId.size() + 2, L'\0');
        std::copy(hardwareId.begin(), hardwareId.end(), multiSz.begin());
        if (!SetupDiSetDeviceRegistryPropertyW(
                devices.get(),
                &device,
                SPDRP_HARDWAREID,
                reinterpret_cast<const BYTE*>(multiSz.data()),
                static_cast<DWORD>(multiSz.size() * sizeof(wchar_t))))
        {
            ERROR(L"Failed to set root-device hardware ID: %lu", GetLastError());
            remove_created_devnode(devices.get(), device);
            return false;
        }

        if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devices.get(), &device))
        {
            ERROR(L"Failed to register root device: %lu", GetLastError());
            remove_created_devnode(devices.get(), device);
            return false;
        }
    }

    BOOL rebootRequired = FALSE;
    INFO(L"Installing PnP driver: %s", absoluteInf.c_str());
    INFO(L"Hardware ID: %s", hardwareId.c_str());
    INFO(L"Activating the scoped DSE window for PnP start...");
    if (!DisableDSESafe())
    {
        if (!existingDevice)
            remove_created_devnode(devices.get(), device);
        ERROR(L"Failed to activate DSE window for PnP installation");
        return false;
    }

    const BOOL installed = UpdateDriverForPlugAndPlayDevicesW(
            nullptr,
            hardwareId.c_str(),
            absoluteInf.c_str(),
            INSTALLFLAG_FORCE,
            &rebootRequired);
    const DWORD installError = installed ? ERROR_SUCCESS : GetLastError();

    INFO(L"Restoring DSE after PnP start...");
    const bool restored = RestoreDSESafe();
    if (!restored)
        ERROR(L"DSE restoration failed after PnP installation");

    if (!installed)
    {
        if (!existingDevice)
            remove_created_devnode(devices.get(), device);
        ERROR(L"PnP driver installation failed: %lu (0x%08lX)", installError, installError);
        return false;
    }

    if (!restored)
    {
        ERROR(L"PnP installation completed, but DSE was not restored");
        return false;
    }

    SUCCESS(L"PnP driver installed and root device started%s",
        rebootRequired ? L" (restart required)" : L"");
    return true;
}

bool Controller::RemovePnpDriver(const std::wstring& hardwareId) noexcept
{
    if (hardwareId.empty())
    {
        ERROR(L"Hardware ID is required for PnP removal");
        return false;
    }

    INFO(L"[MIOMI_HID] PnP remove requested: %s", hardwareId.c_str());

    // Enumerate every device, including non-present instances, so stale root
    // devnodes from interrupted installs are removed instead of accumulating.
    device_info_guard devices(SetupDiGetClassDevsW(
        nullptr, nullptr, nullptr, DIGCF_ALLCLASSES));
    if (devices.get() == INVALID_HANDLE_VALUE)
    {
        ERROR(L"[MIOMI_HID] SetupDiGetClassDevs failed during PnP removal: %lu", GetLastError());
        return false;
    }

    std::vector<SP_DEVINFO_DATA> matches;
    for (DWORD index = 0;; ++index)
    {
        SP_DEVINFO_DATA device{};
        device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(devices.get(), index, &device))
        {
            const DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS)
                ERROR(L"[MIOMI_HID] SetupDiEnumDeviceInfo failed during PnP removal: %lu", error);
            break;
        }

        if (device_has_hardware_id(devices.get(), device, hardwareId))
        {
            INFO(L"[MIOMI_HID] matching devnode found");
            matches.push_back(device);
        }
    }

    if (matches.empty())
    {
        INFO(L"[MIOMI_HID] PnP device is already absent: %s", hardwareId.c_str());
        return true;
    }

    bool allRemoved = true;
    for (auto& device : matches)
    {
        INFO(L"[MIOMI_HID] device removal requested");

        SP_REMOVEDEVICE_PARAMS remove{};
        remove.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        remove.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        remove.Scope = DI_REMOVEDEVICE_GLOBAL;
        remove.HwProfile = 0;

        if (!SetupDiSetClassInstallParamsW(
                devices.get(),
                &device,
                &remove.ClassInstallHeader,
                sizeof(remove)))
        {
            ERROR(L"[MIOMI_HID] SetupDiSetClassInstallParams(DIF_REMOVE) failed: %lu", GetLastError());
            allRemoved = false;
            continue;
        }

        if (!SetupDiCallClassInstaller(DIF_REMOVE, devices.get(), &device))
        {
            ERROR(L"[MIOMI_HID] PnP device removal failed for %s: %lu", hardwareId.c_str(), GetLastError());
            allRemoved = false;
            continue;
        }

        INFO(L"[MIOMI_HID] devnode absent");
        SUCCESS(L"[MIOMI_HID] Removed PnP device: %s", hardwareId.c_str());
    }

    if (!allRemoved)
        return false;

    // Verify device is actually gone (poll with timeout)
    INFO(L"[MIOMI_HID] Verifying device removal...");
    const ULONGLONG deadline = GetTickCount64() + 5000;
    while (GetTickCount64() < deadline)
    {
        device_info_guard verify_devices(SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES));
        if (verify_devices.get() == INVALID_HANDLE_VALUE)
        {
            Sleep(100);
            continue;
        }

        bool still_present = false;
        for (DWORD index = 0;; ++index)
        {
            SP_DEVINFO_DATA device{};
            device.cbSize = sizeof(device);
            if (!SetupDiEnumDeviceInfo(verify_devices.get(), index, &device))
                break;
            if (device_has_hardware_id(verify_devices.get(), device, hardwareId))
            {
                still_present = true;
                break;
            }
        }

        if (!still_present)
        {
            SUCCESS(L"[MIOMI_HID] Device removal verified complete");
            return true;
        }

        Sleep(100);
    }

    ERROR(L"[MIOMI_HID] Device still present after 5 second timeout: %s", hardwareId.c_str());
    return false;
}

