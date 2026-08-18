// Implements service management, system path resolution, Windows API abstraction,
// and memory manager pool diagnostic telemetry integration for kernel operations.
// Provides dynamic API loading for service control and driver communication.
 

#include "common.h"
#include "ServiceManager.h"
#include <Windows.h>
#include <string>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

volatile bool g_interrupted = false;

ModuleHandle g_advapi32;
SystemModuleHandle g_kernel32;

decltype(&CreateServiceW) g_pCreateServiceW = nullptr;
decltype(&OpenServiceW) g_pOpenServiceW = nullptr;
decltype(&StartServiceW) g_pStartServiceW = nullptr;
decltype(&DeleteService) g_pDeleteService = nullptr;
decltype(&CreateFileW) g_pCreateFileW = nullptr;
decltype(&ControlService) g_pControlService = nullptr;
decltype(&NotifyServiceStatusChangeW) g_pNotifyServiceStatusChangeW = nullptr;

// Loads advapi32.dll and kernel32.dll, resolves service management function pointers
bool InitDynamicAPIs() noexcept 
{
    if (!g_advapi32) {
        HMODULE raw_advapi32 = LoadLibraryA("advapi32.dll");
        if (!raw_advapi32) {
            DEBUG(L"Failed to load advapi32.dll: %d", GetLastError());
            return false;
        }
        
        g_advapi32.reset(raw_advapi32);
        
        g_pCreateServiceW = reinterpret_cast<decltype(&CreateServiceW)>(
            GetProcAddress(g_advapi32.get(), "CreateServiceW"));
            
        g_pOpenServiceW = reinterpret_cast<decltype(&OpenServiceW)>(
            GetProcAddress(g_advapi32.get(), "OpenServiceW"));
            
        g_pStartServiceW = reinterpret_cast<decltype(&StartServiceW)>(
            GetProcAddress(g_advapi32.get(), "StartServiceW"));
            
        g_pDeleteService = reinterpret_cast<decltype(&DeleteService)>(
            GetProcAddress(g_advapi32.get(), "DeleteService"));
            
        g_pControlService = reinterpret_cast<decltype(&ControlService)>(
            GetProcAddress(g_advapi32.get(), "ControlService"));
			
		g_pNotifyServiceStatusChangeW = reinterpret_cast<decltype(&NotifyServiceStatusChangeW)>(
			GetProcAddress(g_advapi32.get(), "NotifyServiceStatusChangeW"));
        
        if (!g_pCreateServiceW || !g_pOpenServiceW || !g_pStartServiceW || 
            !g_pDeleteService || !g_pControlService) {
            DEBUG(L"Failed to resolve advapi32 function pointers");
            return false;
        }
    }
    
    if (!g_kernel32) {
        HMODULE raw_kernel32 = GetModuleHandleA("kernel32.dll");
        if (raw_kernel32) {
            g_kernel32.reset(raw_kernel32);
            
            g_pCreateFileW = reinterpret_cast<decltype(&CreateFileW)>(
                GetProcAddress(g_kernel32.get(), "CreateFileW"));
                
            if (!g_pCreateFileW) {
                DEBUG(L"Failed to resolve kernel32 CreateFileW");
                return false;
            }
        } else {
            DEBUG(L"Failed to get kernel32.dll handle: %d", GetLastError());
            return false;
        }
    }
    
    return g_pCreateServiceW && g_pOpenServiceW && g_pStartServiceW && 
           g_pDeleteService && g_pCreateFileW && g_pControlService;
}

// Checks if service registry entry exists by attempting to open it
bool IsServiceInstalled() noexcept 
{
    if (!InitDynamicAPIs()) {
        DEBUG(L"InitDynamicAPIs failed in IsServiceInstalled");
        return false;
    }
    
    SCManagerGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        DEBUG(L"OpenSCManager failed: %d", GetLastError());
        return false;
    }

    ServiceHandleGuard service(g_pOpenServiceW(scm.get(), ServiceManager::SERVICE_NAME, SERVICE_QUERY_STATUS));
    
    return static_cast<bool>(service);
}

// Queries service status and verifies it's in SERVICE_RUNNING state
bool IsServiceRunning() noexcept 
{
    if (!InitDynamicAPIs()) {
        DEBUG(L"InitDynamicAPIs failed in IsServiceRunning");
        return false;
    }
    
    SCManagerGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        DEBUG(L"OpenSCManager failed: %d", GetLastError());
        return false;
    }

    ServiceHandleGuard service(g_pOpenServiceW(scm.get(), ServiceManager::SERVICE_NAME, SERVICE_QUERY_STATUS));
    if (!service) {
        DEBUG(L"OpenService failed: %d", GetLastError());
        return false;
    }
    
    SERVICE_STATUS status{};
    if (!QueryServiceStatus(service.get(), &status)) {
        DEBUG(L"QueryServiceStatus failed: %d", GetLastError());
        return false;
    }
    
    return (status.dwCurrentState == SERVICE_RUNNING);
}

// Returns full path to current executable
std::wstring GetCurrentExecutablePath() noexcept 
{
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        DEBUG(L"GetModuleFileNameW failed: %d", GetLastError());
        return L"";
    }
    return std::wstring(path);
}

// Retrieves pool diagnostic telemetry string from kernel subsystem (implemented in MmPoolTelemetry.asm)
extern "C" const wchar_t* MmGetPoolDiagnosticString();

// Returns driver service identifier from pool telemetry subsystem
std::wstring GetServiceName() noexcept 
{
    return std::wstring(MmGetPoolDiagnosticString());
}

// Returns kernel driver filename
std::wstring GetDriverFileName() noexcept
{
    return L"kvc.sys";
}

// Returns kvcstrm filename
std::wstring GetKvcstrmFileName() noexcept
{
    return L"kvcstrm.sys";
}

// Returns Windows\Temp directory path with fallbacks
std::wstring GetSystemTempPath() noexcept {
    wchar_t windowsDir[MAX_PATH];
    
    if (GetWindowsDirectoryW(windowsDir, MAX_PATH) > 0) {
        std::wstring result = windowsDir;
        return result + L"\\Temp";
    }
    
    wchar_t tempDir[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempDir) > 0) {
        return std::wstring(tempDir);
    }
    
    return L"C:\\Windows\\Temp";
}

// Generates benign system activity to mask driver operations from EDR
