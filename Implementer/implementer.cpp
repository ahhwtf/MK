#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <string>
#include <string_view>
#include <span>
#include <ranges>
#include <algorithm>
#include <filesystem>
#include <optional>
#include <variant>
#include <cstdint>
#include <map>
#include <sstream>
#include <format>
#include <expected>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <fci.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <io.h>
#pragma comment(lib, "cabinet.lib")
#pragma comment(lib, "advapi32.lib")
#endif

namespace fs = std::filesystem;
namespace rng = std::ranges;

// XOR key (same as PowerShell version)
constexpr std::array<uint8_t, 7> XOR_KEY = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };

// Default file paths
constexpr std::string_view DEFAULT_CONFIG = "kvc.ini";
constexpr std::string_view TEMP_EVTX = "kvc.evtx";
constexpr std::string_view TEMP_CAB = "kvc.cab";

// Console colors
enum class Color : int {
    Default = 7,
    Green = 10,
    Red = 12,
    Yellow = 14,
    Cyan = 11
};

void set_color(Color color) {
#ifdef _WIN32
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<int>(color));
#else
    switch (color) {
        case Color::Green:   std::cout << "\033[32m"; break;
        case Color::Red:     std::cout << "\033[31m"; break;
        case Color::Yellow:  std::cout << "\033[33m"; break;
        case Color::Cyan:    std::cout << "\033[36m"; break;
        case Color::Default: std::cout << "\033[0m";  break;
    }
#endif
}

void reset_color() {
    set_color(Color::Default);
}

// RAII color guard
class ColorGuard {
public:
    explicit ColorGuard(Color new_color) {
        set_color(new_color);
    }
    ~ColorGuard() {
        reset_color();
    }
    ColorGuard(const ColorGuard&) = delete;
    ColorGuard& operator=(const ColorGuard&) = delete;
};

// Modern Result type using std::expected (C++23)
template<typename T>
using Result = std::expected<T, std::string>;

// Specialization for void
using ResultVoid = std::expected<void, std::string>;

// Configuration structure
struct Config {
    std::vector<std::string> payload_files;
    std::string icon_file;
    std::string output_file;
};

struct RunOptions {
    std::string config_file{ std::string(DEFAULT_CONFIG) };
    bool keep_temp_files{ false };
};

// WinAPI file operations
class WinFile {
    HANDLE handle{ INVALID_HANDLE_VALUE };
    
public:
    WinFile() = default;
    
    WinFile(const std::string& filename, DWORD desiredAccess, DWORD creationDisposition) {
        std::wstring wide_name;
        int size = MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, nullptr, 0);
        if (size > 0) {
            wide_name.resize(size);
            MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, wide_name.data(), size);
        }
        
        handle = CreateFileW(
            wide_name.c_str(),
            desiredAccess,
            FILE_SHARE_READ,
            nullptr,
            creationDisposition,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
    }
    
    ~WinFile() {
        if (is_valid()) {
            CloseHandle(handle);
        }
    }
    
    bool is_valid() const { return handle != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return handle; }
    
    WinFile(const WinFile&) = delete;
    WinFile& operator=(const WinFile&) = delete;
    
    WinFile(WinFile&& other) noexcept : handle(other.handle) {
        other.handle = INVALID_HANDLE_VALUE;
    }
    
    WinFile& operator=(WinFile&& other) noexcept {
        if (this != &other) {
            if (is_valid()) {
                CloseHandle(handle);
            }
            handle = other.handle;
            other.handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
};

// Check if file exists using WinAPI
bool file_exists_winapi(const std::string& filename) {
    std::wstring wide_filename;
    int size = MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, nullptr, 0);
    if (size > 0) {
        wide_filename.resize(size);
        MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, wide_filename.data(), size);
    }
    
    DWORD attrs = GetFileAttributesW(wide_filename.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

// Get file size using WinAPI
Result<size_t> get_file_size_winapi(const std::string& filename) {
    std::wstring wide_filename;
    int size = MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, nullptr, 0);
    if (size > 0) {
        wide_filename.resize(size);
        MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, wide_filename.data(), size);
    }
    
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(wide_filename.c_str(), GetFileExInfoStandard, &fileInfo)) {
        return std::unexpected("Cannot get file size: " + filename);
    }
    
    return (static_cast<uint64_t>(fileInfo.nFileSizeHigh) << 32) | fileInfo.nFileSizeLow;
}

// Helper functions
std::string format_size_kb(size_t bytes) {
    return std::format("{:.2f} KB", bytes / 1024.0);
}

std::string trim(std::string_view str) {
    const auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return "";
    const auto end = str.find_last_not_of(" \t\r\n");
    return std::string(str.substr(start, end - start + 1));
}

std::vector<std::string> split_list(std::string_view value, char delimiter = ',') {
    std::vector<std::string> items;
    size_t start = 0;

    while (start <= value.size()) {
        const size_t end = value.find(delimiter, start);
        const auto token = (end == std::string_view::npos)
            ? value.substr(start)
            : value.substr(start, end - start);

        std::string item = trim(token);
        if (!item.empty()) {
            items.push_back(std::move(item));
        }

        if (end == std::string_view::npos) {
            break;
        }

        start = end + 1;
    }

    return items;
}

// Read entire file into vector using WinAPI
Result<std::vector<uint8_t>> read_file_winapi(const std::string& filename) {
    WinFile file(filename, GENERIC_READ, OPEN_EXISTING);
    if (!file.is_valid()) {
        return std::unexpected("Cannot open file: " + filename);
    }

    auto size_result = get_file_size_winapi(filename);
    if (!size_result) {
        return std::unexpected(size_result.error());
    }

    std::vector<uint8_t> data(size_result.value());
    DWORD bytesRead = 0;
    
    if (!ReadFile(file.get(), data.data(), static_cast<DWORD>(data.size()), &bytesRead, nullptr)) {
        return std::unexpected("Error reading file: " + filename);
    }

    if (bytesRead != data.size()) {
        return std::unexpected("Incomplete read of file: " + filename);
    }

    return data;
}

// Write data to file using WinAPI
ResultVoid write_file_winapi(const std::string& filename, std::span<const uint8_t> data) {
    WinFile file(filename, GENERIC_WRITE, CREATE_ALWAYS);
    if (!file.is_valid()) {
        return std::unexpected("Cannot create file: " + filename);
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(file.get(), data.data(), static_cast<DWORD>(data.size()), &bytesWritten, nullptr)) {
        return std::unexpected("Error writing to file: " + filename);
    }

    if (bytesWritten != data.size()) {
        return std::unexpected("Incomplete write to file: " + filename);
    }

    return {};
}

// XOR operation
// Auto-vectorization disabled: MSVC generates AVX2 (vpermd/vpsllvd) for i%key.size()
// which crashes on CPUs without AVX2 support (pre-Haswell / Ivy Bridge and older).
#pragma optimize("", off)
void xor_data(std::span<uint8_t> data, std::span<const uint8_t> key) noexcept {
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.size()];
    }
}
#pragma optimize("", on)

// Read INI configuration
Result<Config> read_config(const std::string& config_path) {
    auto file_result = read_file_winapi(config_path);
    if (!file_result) {
        return std::unexpected(file_result.error());
    }

    Config config;
    std::string content(file_result->begin(), file_result->end());
    std::istringstream stream(content);
    std::string line;
    std::string current_section;

    while (std::getline(stream, line)) {
        line = trim(line);
        
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // Section header
        if (line.starts_with('[') && line.ends_with(']')) {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }

        // Key=Value pair
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            if (!current_section.empty() && current_section != "Files") {
                continue;
            }

            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));

            if (key == "DriverFile" || key == "DllFile" || key == "PayloadFile" || key == "ExeFile") {
                auto files = split_list(value);
                config.payload_files.insert(
                    config.payload_files.end(),
                    std::make_move_iterator(files.begin()),
                    std::make_move_iterator(files.end())
                );
            } else if (key == "IconFile") {
                config.icon_file = value;
            } else if (key == "OutputFile") {
                config.output_file = value;
            }
        }
    }

    // Validate config
    if (config.payload_files.empty() || config.icon_file.empty() || config.output_file.empty()) {
        return std::unexpected("Incomplete configuration in INI file");
    }

    return config;
}

void print_usage(std::string_view exe_name) {
    std::cout << "Usage: " << exe_name << " [config.ini] [--keep-temp]\n";
    std::cout << "  config.ini   Optional configuration file path (default: " << DEFAULT_CONFIG << ")\n";
    std::cout << "  --keep-temp  Keep kvc.evtx and kvc.cab after successful packaging\n";
}

Result<RunOptions> parse_command_line(int argc, char* argv[]) {
    RunOptions options;
    bool config_specified = false;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];

        if (arg == "--keep-temp" || arg == "-keep-temp") {
            options.keep_temp_files = true;
            continue;
        }

        if (arg == "--help" || arg == "-h" || arg == "/?") {
            print_usage(argc > 0 ? argv[0] : "implementer.exe");
            return std::unexpected("");
        }

        if (!arg.empty() && arg.front() == '-') {
            return std::unexpected("Unknown option: " + std::string(arg));
        }

        if (config_specified) {
            return std::unexpected("Multiple configuration files specified");
        }

        options.config_file = std::string(arg);
        config_specified = true;
    }

    return options;
}

#ifdef _WIN32
// Cabinet API callback structures
struct CabContext {
    std::string input_file;
    std::string output_file;
    UINT temp_file_counter = 0;
};

// FCI callbacks
FNFCIALLOC(fci_alloc) {
    return malloc(cb);
}

FNFCIFREE(fci_free) {
    free(memory);
}

FNFCIOPEN(fci_open) {
    int flags = 0;
        
    if (oflag & _O_RDWR) flags = GENERIC_READ | GENERIC_WRITE;
    else if (oflag & _O_WRONLY) flags = GENERIC_WRITE;
    else flags = GENERIC_READ;
    
    DWORD creation = OPEN_EXISTING;
    if (oflag & _O_CREAT) {
        creation = CREATE_ALWAYS;
    }
    
    HANDLE handle = CreateFileA(
        pszFile,
        flags,
        FILE_SHARE_READ,
        nullptr,
        creation,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    return (INT_PTR)handle;
}

FNFCIREAD(fci_read) {
    DWORD bytesRead = 0;
    if (!ReadFile((HANDLE)hf, memory, cb, &bytesRead, nullptr)) {
        return -1;
    }
    return bytesRead;
}

FNFCIWRITE(fci_write) {
    DWORD bytesWritten = 0;
    if (!WriteFile((HANDLE)hf, memory, cb, &bytesWritten, nullptr)) {
        return -1;
    }
    return bytesWritten;
}

FNFCICLOSE(fci_close) {
    CloseHandle((HANDLE)hf);
    return 0;
}

FNFCISEEK(fci_seek) {
    return SetFilePointer((HANDLE)hf, dist, nullptr, seektype);
}

FNFCIDELETE(fci_delete) {
    DeleteFileA(pszFile);
    return 0;
}

FNFCIGETTEMPFILE(fci_get_temp_file) {
    CabContext* ctx = static_cast<CabContext*>(pv);
    snprintf(pszTempName, cbTempName, "temp_cab_%u.tmp", ctx->temp_file_counter++);
    return TRUE;
}

FNFCIGETNEXTCABINET(fci_get_next_cabinet) {
    return TRUE;
}

FNFCIFILEPLACED(fci_file_placed) {
    return 0;
}

FNFCISTATUS(fci_status) {
    return 0;
}

FNFCIGETOPENINFO(fci_get_open_info) {
    WIN32_FIND_DATAA findData;
    HANDLE findHandle = FindFirstFileA(pszName, &findData);
    
    if (findHandle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    FindClose(findHandle);
    
    FILETIME ftLocal;
    FileTimeToLocalFileTime(&findData.ftLastWriteTime, &ftLocal);
    FileTimeToDosDateTime(&ftLocal, pdate, ptime);
    
    *pattribs = findData.dwFileAttributes & 
               (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | 
                FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE);
    
    HANDLE handle = CreateFileA(
        pszName,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    return (INT_PTR)handle;
}

// Create CAB file
ResultVoid create_cab_file(const std::string& input_file, const std::string& output_file) {
    CabContext context;
    context.input_file = input_file;
    context.output_file = output_file;

    ERF erf = {};
    CCAB ccab = {};
    
    // Setup cabinet parameters
    ccab.cb = 0x7FFFFFFF;  // Max cabinet size
    ccab.cbFolderThresh = 0x7FFFFFFF;
    ccab.cbReserveCFHeader = 0;
    ccab.cbReserveCFFolder = 0;
    ccab.cbReserveCFData = 0;
    ccab.iCab = 1;
    ccab.iDisk = 0;
    ccab.setID = 0;
    strncpy_s(ccab.szCab, output_file.c_str(), _TRUNCATE);
    strcpy_s(ccab.szCabPath, "");

    // Create FCI context
    HFCI hfci = FCICreate(
        &erf,
        fci_file_placed,
        fci_alloc,
        fci_free,
        fci_open,
        fci_read,
        fci_write,
        fci_close,
        fci_seek,
        fci_delete,
        fci_get_temp_file,
        &ccab,
        &context
    );

    if (!hfci) {
        return std::unexpected("Failed to create FCI context");
    }

    // Add file to cabinet with LZX compression
    BOOL result = FCIAddFile(
        hfci,
        const_cast<char*>(input_file.c_str()),
        const_cast<char*>(fs::path(input_file).filename().string().c_str()),
        FALSE,
        fci_get_next_cabinet,
        fci_status,
        fci_get_open_info,
        tcompTYPE_LZX | tcompLZX_WINDOW_HI
    );

    if (!result) {
        FCIDestroy(hfci);
        return std::unexpected("Failed to add file to cabinet");
    }

    // Flush and close cabinet
    result = FCIFlushCabinet(hfci, FALSE, fci_get_next_cabinet, fci_status);
    FCIDestroy(hfci);

    if (!result) {
        return std::unexpected("Failed to flush cabinet");
    }

    return {};
}
#endif

// Delete file using WinAPI
bool delete_file_winapi(const std::string& filename) {
    std::wstring wide_filename;
    int size = MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, nullptr, 0);
    if (size > 0) {
        wide_filename.resize(size);
        MultiByteToWideChar(CP_UTF8, 0, filename.c_str(), -1, wide_filename.data(), size);
    }
    return DeleteFileW(wide_filename.c_str());
}

// Detect if Windows Defender (or any AV) is likely running
bool is_av_likely_active() {
#ifdef _WIN32
    // Quick heuristic: check if MsMpEng.exe or common AV processes are running
    // via Windows Security Center WMI query would be ideal but heavy;
    // instead we check if the Defender service is running
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return false;

    // Known AV service names (common ones)
    const char* av_services[] = {
        "WinDefend",       // Windows Defender
        "MsMpSvc",         // Defender legacy
        "AVP",             // Kaspersky
        "avast! Antivirus",
        "avgwd",           // AVG
        "McShield",        // McAfee
        "SAVService",      // Sophos
        "ekrn",            // ESET
        "bdagent",         // Bitdefender
        nullptr
    };

    for (int i = 0; av_services[i] != nullptr; ++i) {
        SC_HANDLE svc = OpenServiceA(scm, av_services[i], SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS status{};
            bool running = QueryServiceStatus(svc, &status) &&
                           status.dwCurrentState == SERVICE_RUNNING;
            CloseServiceHandle(svc);
            if (running) {
                CloseServiceHandle(scm);
                return true;
            }
        }
    }
    CloseServiceHandle(scm);
#endif
    return false;
}

void print_av_warning() {
    const std::string border(60, '-');
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "  " << border << "\n";
        std::cout << "  ! ANTIVIRUS / WINDOWS DEFENDER WARNING\n";
        std::cout << "  " << border << "\n";
        std::cout << "  Cabinet API (FCIAddFile) was blocked - this is a known\n";
        std::cout << "  symptom of real-time AV protection intercepting file\n";
        std::cout << "  operations on .sys / .dll payloads.\n\n";
        std::cout << "  To proceed:\n";
        std::cout << "    1. Open Windows Security\n";
        std::cout << "       -> Virus & threat protection\n";
        std::cout << "       -> Manage settings\n";
        std::cout << "       -> Turn OFF Real-time protection\n";
        std::cout << "    2. Or add this folder to exclusions:\n";

        // Print current directory
        char cwd[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, cwd)) {
            std::cout << "       " << cwd << "\n";
        }

        std::cout << "    3. Re-run implementer.exe\n";
        std::cout << "    4. Re-enable protection after packaging\n\n";
        std::cout << "  Other AV products: temporarily disable real-time\n";
        std::cout << "  protection or add folder exclusion, then re-run.\n";
        std::cout << "  " << border << "\n";
    }
    std::cout << "\n";
}

// Main packaging function
ResultVoid package_files(const Config& config, bool keep_temp_files) {
    std::cout << "\n";
    {
        ColorGuard cyan(Color::Cyan);
        std::cout << "=== FILE PACKAGING SCRIPT ===\n";
    }
    {
        ColorGuard green(Color::Green);
        std::cout << "Starting packaging process...\n";
    }

    // Step 0: Display configuration
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "Step 0: Configuration loaded\n";
    }
    std::cout << "  - Payload files: " << config.payload_files.size() << "\n";
    for (size_t i = 0; i < config.payload_files.size(); ++i) {
        std::cout << "    [" << (i + 1) << "] " << config.payload_files[i] << "\n";
    }
    std::cout << "  - Icon: " << config.icon_file << "\n";
    std::cout << "  - Output: " << config.output_file << "\n";

    // Step 1: Verify input files using WinAPI
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "Step 1: Verifying input files...\n";
    }

    size_t total_payload_size = 0;
    for (const auto& file : config.payload_files) {
        if (!file_exists_winapi(file)) {
            ColorGuard red(Color::Red);
            std::cout << "  X File not found: " << file << "\n";
            
            // Debug info
            std::cout << "  Debug bytes: ";
            for (char c : file) {
                printf("%02X ", (unsigned char)c);
            }
            std::cout << "\n";
            
            return std::unexpected("ABORTING: Required file missing: " + file);
        }
        
        auto size_result = get_file_size_winapi(file);
        if (!size_result) {
            ColorGuard red(Color::Red);
            std::cout << "  X Cannot get size for: " << file << " - " << size_result.error() << "\n";
            return std::unexpected(size_result.error());
        }
        
        ColorGuard green(Color::Green);
        std::cout << "  + Found: " << file << " (" << format_size_kb(size_result.value()) << ")\n";
        total_payload_size += size_result.value();
    }

    if (!file_exists_winapi(config.icon_file)) {
        ColorGuard red(Color::Red);
        std::cout << "  X File not found: " << config.icon_file << "\n";
        return std::unexpected("ABORTING: Required file missing: " + config.icon_file);
    }

    auto icon_size_result = get_file_size_winapi(config.icon_file);
    if (!icon_size_result) {
        ColorGuard red(Color::Red);
        std::cout << "  X Cannot get size for: " << config.icon_file << " - " << icon_size_result.error() << "\n";
        return std::unexpected(icon_size_result.error());
    }

    {
        ColorGuard green(Color::Green);
        std::cout << "  + Found: " << config.icon_file << " (" << format_size_kb(icon_size_result.value()) << ")\n";
    }

    // Step 2: Build payload container
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "Step 2: Building payload container...\n";
    }

    std::vector<uint8_t> concatenated_data;
    concatenated_data.reserve(total_payload_size);

    for (size_t i = 0; i < config.payload_files.size(); ++i) {
        const auto& file = config.payload_files[i];

        auto file_result = read_file_winapi(file);
        if (!file_result) {
            ColorGuard red(Color::Red);
            std::cout << "  X Failed to read payload file: " << file_result.error() << "\n";
            return std::unexpected(file_result.error());
        }

        concatenated_data.insert(
            concatenated_data.end(),
            file_result->begin(),
            file_result->end()
        );

        ColorGuard green(Color::Green);
        std::cout << "  + Added [" << (i + 1) << "/" << config.payload_files.size()
                  << "]: " << file << " (" << format_size_kb(file_result->size()) << ")\n";
    }

    auto write_result = write_file_winapi(std::string(TEMP_EVTX), concatenated_data);
    if (!write_result) {
        ColorGuard red(Color::Red);
        std::cout << "  X Failed to create payload container: " << write_result.error() << "\n";
        return std::unexpected(write_result.error());
    }

    {
        ColorGuard green(Color::Green);
        std::cout << "  + Created: " << TEMP_EVTX << " (" 
                  << format_size_kb(concatenated_data.size()) << ")\n";
    }

    // Step 3: Compress with CAB
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "Step 3: Compressing with CAB...\n";
    }

#ifdef _WIN32
    auto cab_result = create_cab_file(std::string(TEMP_EVTX), std::string(TEMP_CAB));
    if (!cab_result) {
        {
            ColorGuard red(Color::Red);
            std::cout << "  X CAB compression failed: " << cab_result.error() << "\n";
        }
        // "Failed to add file to cabinet" is the exact error Defender produces
        // by blocking FCIAddFile mid-operation. Show AV advisory.
        if (cab_result.error().find("Failed to add file") != std::string::npos ||
            cab_result.error().find("Failed to create FCI") != std::string::npos) {
            print_av_warning();
        }
        return std::unexpected(cab_result.error());
    }

    auto cab_size_result = get_file_size_winapi(std::string(TEMP_CAB));
    if (!cab_size_result) {
        ColorGuard red(Color::Red);
        std::cout << "  X Cannot get CAB file size: " << cab_size_result.error() << "\n";
        return std::unexpected(cab_size_result.error());
    }

    {
        ColorGuard green(Color::Green);
        std::cout << "  + Created: " << TEMP_CAB << " (" << format_size_kb(cab_size_result.value()) << ")\n";
    }
#else
    ColorGuard red(Color::Red);
    std::cout << "  X CAB compression is only supported on Windows\n";
    return std::unexpected("CAB compression requires Windows Cabinet API");
#endif

    // Step 4: XOR encrypt the CAB file
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "Step 4: XOR encrypting CAB file...\n";
    }

    auto cab_data_result = read_file_winapi(std::string(TEMP_CAB));
    if (!cab_data_result) {
        ColorGuard red(Color::Red);
        std::cout << "  X Failed to read CAB file: " << cab_data_result.error() << "\n";
        return std::unexpected(cab_data_result.error());
    }

    std::vector<uint8_t> encrypted_cab = std::move(cab_data_result.value());
    xor_data(encrypted_cab, XOR_KEY);

    {
        ColorGuard green(Color::Green);
        std::cout << "  + CAB file encrypted (" << encrypted_cab.size() << " bytes)\n";
    }

    // Step 5: Create final package with icon
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "Step 5: Creating final package with icon...\n";
    }

    auto icon_result = read_file_winapi(config.icon_file);
    if (!icon_result) {
        ColorGuard red(Color::Red);
        std::cout << "  X Failed to read icon file: " << icon_result.error() << "\n";
        return std::unexpected(icon_result.error());
    }

    std::vector<uint8_t> final_package;
    final_package.reserve(icon_result->size() + encrypted_cab.size());
    final_package.insert(final_package.end(), icon_result->begin(), icon_result->end());
    final_package.insert(final_package.end(), encrypted_cab.begin(), encrypted_cab.end());

    auto final_write_result = write_file_winapi(config.output_file, final_package);
    if (!final_write_result) {
        ColorGuard red(Color::Red);
        std::cout << "  X Failed to create final package: " << final_write_result.error() << "\n";
        return std::unexpected(final_write_result.error());
    }

    {
        ColorGuard green(Color::Green);
        std::cout << "  + Final package created: " << config.output_file 
                  << " (" << format_size_kb(final_package.size()) << ")\n";
    }

    // Step 6: Cleanup temporary files
    std::cout << "\n";
    {
        ColorGuard yellow(Color::Yellow);
        std::cout << "Step 6: " << (keep_temp_files ? "Preserving" : "Cleaning up")
                  << " temporary files...\n";
    }

    std::vector<std::string_view> temp_files = { TEMP_EVTX, TEMP_CAB };
    if (keep_temp_files) {
        for (const auto& temp_file : temp_files) {
            if (file_exists_winapi(std::string(temp_file))) {
                ColorGuard green(Color::Green);
                std::cout << "  + Kept: " << temp_file << "\n";
            }
        }
    } else {
        for (const auto& temp_file : temp_files) {
            if (file_exists_winapi(std::string(temp_file))) {
                if (delete_file_winapi(std::string(temp_file))) {
                    ColorGuard green(Color::Green);
                    std::cout << "  + Removed: " << temp_file << "\n";
                } else {
                    ColorGuard yellow(Color::Yellow);
                    std::cout << "  ! Warning: Could not remove " << temp_file << "\n";
                }
            }
        }
    }

    // Final summary
    std::cout << "\n";
    {
        ColorGuard cyan(Color::Cyan);
        std::cout << "=== PACKAGING COMPLETED SUCCESSFULLY ===\n";
    }
    std::cout << "Output file: " << config.output_file << "\n";
    std::cout << "Total size: " << format_size_kb(final_package.size()) << "\n";
    std::cout << "Structure: [" << icon_result->size() << "-byte icon] + [XOR-encrypted CAB]\n";
    std::cout << "Breakdown:\n";
    std::cout << "  - Payload files: " << config.payload_files.size() << "\n";
    std::cout << "  - Payload container: " << concatenated_data.size() << " bytes\n";
    std::cout << "  - Icon: " << icon_result->size() << " bytes\n";
    std::cout << "  - Encrypted CAB: " << encrypted_cab.size() << " bytes\n";
    std::cout << "  - Temp files: " << (keep_temp_files ? "kept" : "removed") << "\n";
    {
        ColorGuard green(Color::Green);
        std::cout << "\nThe file is ready for embedding as a resource!\n";
    }

    return {};
}

int main(int argc, char* argv[]) {
    // Set console to UTF-8 mode
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    auto options_result = parse_command_line(argc, argv);
    if (!options_result) {
        if (!options_result.error().empty()) {
            ColorGuard red(Color::Red);
            std::cerr << "Error: " << options_result.error() << "\n";
            print_usage(argc > 0 ? argv[0] : "implementer.exe");
            return 1;
        }
        return 0;
    }

    const auto& options = options_result.value();

    std::cout << "Reading configuration from: " << options.config_file << "\n";
    if (options.keep_temp_files) {
        std::cout << "Keeping temporary files enabled (--keep-temp)\n";
    }

    auto config_result = read_config(options.config_file);
    if (!config_result) {
        ColorGuard red(Color::Red);
        std::cerr << "Error: " << config_result.error() << "\n";
        return 1;
    }

    auto result = package_files(config_result.value(), options.keep_temp_files);
    if (!result) {
        ColorGuard red(Color::Red);
        std::cerr << "\nError: " << result.error() << "\n";
        return 1;
    }

    return 0;
}
