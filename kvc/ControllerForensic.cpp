// ControllerForensic.cpp - KvcForensic module extraction and execution
//
// kvcforensic.dat layout (XOR-encrypted with KVC_XOR_KEY):
//   [KvcForensic.exe - PE, size from GetPEFileLength] | [KvcForensic.json - remainder]
//
// Built with KvcXor option 7. Deploy via kvc setup when kvcforensic.dat is present in CWD.
// At runtime kvc.exe extracts both files to %TEMP%\KvcForensic\, executes, cleans up.

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include <filesystem>
#include <ShlObj.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

namespace fs = std::filesystem;

// --- Internal helpers --------------------------------------------------------

static std::wstring GetTempForensicDir() noexcept {
    wchar_t tmp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n >= MAX_PATH) return L"";
    return std::wstring(tmp) + L"KvcForensic\\";
}

// Search for kvcforensic.dat: System32 first, then CWD.
static std::wstring FindForensicDat() noexcept {
    auto probe = [](const std::wstring& path) {
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    };

    wchar_t sys32[MAX_PATH];
    if (GetSystemDirectoryW(sys32, MAX_PATH)) {
        std::wstring p = std::wstring(sys32) + L"\\" + KVC_FORENSIC_FILE;
        if (probe(p)) return p;
    }

    wchar_t cwd[MAX_PATH];
    if (GetCurrentDirectoryW(MAX_PATH, cwd)) {
        std::wstring p = std::wstring(cwd) + L"\\" + KVC_FORENSIC_FILE;
        if (probe(p)) return p;
    }

    return L"";
}

// XOR-decrypt kvcforensic.dat, split into KvcForensic.exe + KvcForensic.json,
// write both to outDir. Returns path to extracted KvcForensic.exe or empty on failure.
static std::wstring ExtractForensic(const std::wstring& datPath, const std::wstring& outDir) noexcept {
    auto enc = Utils::ReadFile(datPath);
    if (enc.empty()) return L"";

    auto dec = Utils::DecryptXOR(enc, KVC_XOR_KEY);
    if (dec.empty()) return L"";

    auto exeLen = Utils::GetPEFileLength(dec, 0);
    if (!exeLen || *exeLen == 0 || *exeLen >= dec.size()) return L"";

    try { fs::create_directories(outDir); } catch (...) { return L""; }

    const std::wstring exePath  = outDir + KVC_FORENSIC_EXE;
    const std::wstring jsonPath = outDir + KVC_FORENSIC_JSON;

    std::vector<BYTE> exeData(dec.begin(), dec.begin() + static_cast<std::ptrdiff_t>(*exeLen));
    std::vector<BYTE> jsonData(dec.begin() + static_cast<std::ptrdiff_t>(*exeLen), dec.end());

    if (!Utils::WriteFile(exePath, exeData)) return L"";
    if (!Utils::WriteFile(jsonPath, jsonData)) return L"";

    return exePath;
}

static void CleanupForensicTemp(const std::wstring& dir) noexcept {
    try { fs::remove_all(dir); } catch (...) {}
}

// Launch exePath with optional args, inherit console, wait for exit.
static bool RunForensicProcess(const std::wstring& exePath, const std::wstring& args) noexcept {
    std::wstring cmdLine = L"\"" + exePath + L"\"";
    if (!args.empty()) { cmdLine += L" "; cmdLine += args; }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (!CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr,
                        TRUE,   // inherit console handles
                        0, nullptr, nullptr, &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// Download kvcforensic.dat from GitHub and save to System32.
// Prompts the user first. Returns the destination path on success, empty on failure/cancel.
static std::wstring PromptAndDownloadForensicDat() noexcept {
    printf("[*] kvcforensic.dat not found. Download from github? [Y/n]: ");
    fflush(stdout);
    wchar_t ch = static_cast<wchar_t>(_getwch());
    wprintf(L"%lc\n", ch);
    if (ch == L'n' || ch == L'N') {
        INFO(L"Download cancelled. Place kvcforensic.dat in the current directory and run 'kvc setup'.");
        return L"";
    }

    wchar_t sys32[MAX_PATH];
    if (GetSystemDirectoryW(sys32, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 path.");
        return L"";
    }
    const std::wstring destPath = std::wstring(sys32) + L"\\" + KVC_FORENSIC_FILE;

    INFO(L"Downloading kvcforensic.dat...");
    HRESULT hr = URLDownloadToFileW(nullptr,
        L"https://github.com/wesmar/kvc/releases/download/latest/kvcforensic.dat",
        destPath.c_str(), 0, nullptr);
    if (FAILED(hr)) {
        ERROR(L"Download failed (0x%08X). Check internet connection.", static_cast<unsigned>(hr));
        return L"";
    }

    SetFileAttributesW(destPath.c_str(), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
    SUCCESS(L"kvcforensic.dat downloaded to System32.");
    return destPath;
}

// --- Public Controller methods -----------------------------------------------

bool Controller::IsForensicAvailable() noexcept {
    return !FindForensicDat().empty();
}

// Deploy kvcforensic.dat from CWD to System32 (called from setup when file is present).
// Not an error if the file is absent — forensic module is optional.
bool Controller::DeployForensicModule() noexcept {
    const fs::path src = fs::current_path() / KVC_FORENSIC_FILE;
    if (!fs::exists(src)) return false;

    wchar_t sys32[MAX_PATH];
    if (GetSystemDirectoryW(sys32, MAX_PATH) == 0) {
        ERROR(L"Failed to get System32 path.");
        return false;
    }

    const std::wstring dst = std::wstring(sys32) + L"\\" + KVC_FORENSIC_FILE;

    auto data = Utils::ReadFile(src.wstring());
    if (data.empty()) {
        ERROR(L"Failed to read kvcforensic.dat.");
        return false;
    }

    INFO(L"Deploying kvcforensic.dat to System32...");
    if (!WriteFileWithPrivileges(dst, data)) {
        ERROR(L"Failed to deploy kvcforensic.dat to System32.");
        return false;
    }

    SetFileAttributesW(dst.c_str(), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
    SUCCESS(L"kvcforensic.dat deployed - forensic analysis available via 'kvc analyze'.");
    return true;
}

// Analyze a minidump using the embedded KvcForensic.exe.
// format: "txt" | "json" | "both" (default "both").
// Output files are written alongside the dump (same directory, same stem).
bool Controller::RunForensicAnalysis(const std::wstring& dumpPath,
                                     const std::wstring& format,
                                     bool full,
                                     const std::wstring& ticketsDir) noexcept {
    std::wstring datPath = FindForensicDat();
    if (datPath.empty()) {
        datPath = PromptAndDownloadForensicDat();
        if (datPath.empty()) return false;
    }

    // Validate input file
    if (GetFileAttributesW(dumpPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ERROR(L"Dump file not found: %s", dumpPath.c_str());
        return false;
    }

    const std::wstring tempDir = GetTempForensicDir();
    if (tempDir.empty()) { ERROR(L"Failed to resolve temp directory."); return false; }

    INFO(L"Extracting forensic module...");
    const std::wstring exePath = ExtractForensic(datPath, tempDir);
    if (exePath.empty()) {
        ERROR(L"Failed to extract KvcForensic from kvcforensic.dat.");
        CleanupForensicTemp(tempDir);
        return false;
    }

    // Derive output path alongside the dump file
    const fs::path dumpFs(dumpPath);
    const std::wstring outBase = (dumpFs.parent_path() / dumpFs.stem()).wstring();
    const std::wstring outTxt  = outBase + L".txt";

    // Build KvcForensic.exe argument list
    const std::wstring fmt = format.empty() ? L"both" : format;
    std::wstring args = L"--analyze-dump";
    args += L" --input \""  + dumpPath + L"\"";
    args += L" --output \"" + outTxt   + L"\"";
    args += L" --format "   + fmt;
    if (full) args += L" --full";
    if (!ticketsDir.empty()) args += L" --export-tickets \"" + ticketsDir + L"\"";

    INFO(L"Analyzing: %s", dumpPath.c_str());
    if (!RunForensicProcess(exePath, args)) {
        ERROR(L"Failed to launch KvcForensic.exe (error: %lu).", GetLastError());
        CleanupForensicTemp(tempDir);
        return false;
    }

    // Report output locations
    if (fmt == L"txt" || fmt == L"both")
        SUCCESS(L"Text report : %s", outTxt.c_str());
    if (fmt == L"json")
        SUCCESS(L"JSON report : %s", (outBase + L".json").c_str());
    else if (fmt == L"both")
        SUCCESS(L"JSON report : %s", (outBase + L".json").c_str());

    CleanupForensicTemp(tempDir);
    return true;
}

// Launch KvcForensic.exe in GUI mode (no --analyze-dump flag → window opens).
bool Controller::LaunchForensicGui() noexcept {
    std::wstring datPath = FindForensicDat();
    if (datPath.empty()) {
        datPath = PromptAndDownloadForensicDat();
        if (datPath.empty()) return false;
    }

    const std::wstring tempDir = GetTempForensicDir();
    if (tempDir.empty()) { ERROR(L"Failed to resolve temp directory."); return false; }

    INFO(L"Extracting forensic module...");
    const std::wstring exePath = ExtractForensic(datPath, tempDir);
    if (exePath.empty()) {
        ERROR(L"Failed to extract KvcForensic from kvcforensic.dat.");
        CleanupForensicTemp(tempDir);
        return false;
    }

    INFO(L"Launching KvcForensic GUI...");
    if (!RunForensicProcess(exePath, L"")) {
        ERROR(L"Failed to launch KvcForensic.exe (error: %lu).", GetLastError());
        CleanupForensicTemp(tempDir);
        return false;
    }

    CleanupForensicTemp(tempDir);
    return true;
}
