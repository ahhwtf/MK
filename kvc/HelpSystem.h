#pragma once

#include <windows.h>
#include <string>

// Console layout constants for consistent formatting across help system
namespace HelpLayout {
    inline constexpr int WIDTH = 80;
    inline constexpr int COMMAND_WIDTH = 50;
    inline constexpr int EXAMPLE_CMD_WIDTH = 60;

    // Wide border (wcout / INFO / CRITICAL)
    inline std::wstring MakeBorder(wchar_t ch = L'=', int count = WIDTH) {
        return std::wstring(count, ch);
    }

    // Narrow border (printf)
    inline std::string MakeBorderA(char ch = '=', int count = WIDTH) {
        return std::string(count, ch);
    }
}

class HelpSystem
{
public:
    static void PrintUsage(std::wstring_view programName) noexcept;
    static void PrintUnknownCommandMessage(std::wstring_view command) noexcept;
    static void PrintBrowserCommands() noexcept;
    static void PrintBlockerCommands() noexcept;

private:
    // Main sections
    static void PrintHeader() noexcept;
    static void PrintFooter() noexcept;

    // Command categories
    static void PrintServiceCommands() noexcept;
    static void PrintDSECommands() noexcept;
    static void PrintDriverCommands() noexcept;
    static void PrintBasicCommands() noexcept;
    static void PrintModuleCommands() noexcept;
    static void PrintProcessTerminationCommands() noexcept;
    static void PrintProtectionCommands() noexcept;
    static void PrintSystemCommands() noexcept;
    static void PrintRegistryCommands() noexcept;
    static void PrintDefenderCommands() noexcept;
    static void PrintSecurityEngineCommands() noexcept;
    static void PrintDefenderUICommands() noexcept;
    static void PrintSessionManagement() noexcept;
    static void PrintDPAPICommands() noexcept;
    static void PrintWatermarkCommands() noexcept;
    static void PrintUnderVolterCommands() noexcept;
    static void PrintForensicCommands() noexcept;
    static void PrintEntertainmentCommands() noexcept;

    // Reference sections
    static void PrintProtectionTypes() noexcept;
    static void PrintExclusionTypes() noexcept;
    static void PrintPatternMatching() noexcept;
    static void PrintTechnicalFeatures() noexcept;
    static void PrintDefenderNotes() noexcept;
    static void PrintStickyKeysInfo() noexcept;
    static void PrintUndumpableProcesses() noexcept;
    static void PrintUsageExamples(std::wstring_view programName) noexcept;
    static void PrintSecurityNotice() noexcept;
    
    // Formatting helpers with cached console handle
    static void PrintSectionHeader(const wchar_t* title) noexcept;
    static void PrintCommandLine(const wchar_t* command, const wchar_t* description) noexcept;
    static void PrintNote(const wchar_t* note) noexcept;
    static void PrintWarning(const wchar_t* warning) noexcept;
    
    // Console color management
    static void PrintCentered(std::wstring_view text, HANDLE hConsole, WORD color) noexcept;
    static void PrintBoxLine(std::wstring_view text, HANDLE hConsole, 
                            WORD borderColor, WORD textColor) noexcept;
};
