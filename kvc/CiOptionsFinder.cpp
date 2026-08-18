// CiOptionsFinder.cpp
// Locates g_CiOptions in ci.dll using a two-stage strategy:
//   1. Semantic RIP-relative code probe - scans executable sections of the
//      on-disk ci.dll image for instructions that reference bytes inside the
//      first 0x40 bytes of the CiPolicy section.  Candidates are ranked by
//      instruction kind (test/bt/bts/cmp score higher than plain mov), flag
//      mask content, usage count, and proximity to the section start.
//   2. Build-number fallback - +0x4 pre-26H1, +0x8 from 26H1 onward.
//      Both candidates are checked with a value sanity filter; a WARNING log
//      is emitted so callers know the probe was not authoritative.

#include "CiOptionsFinder.h"
#include "common.h"
#include <shlwapi.h>
#include <algorithm>
#include <array>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// PRIVATE HELPERS (translation-unit scope)
// ============================================================================

namespace {

struct PeSectionView {
    std::array<char, 9> Name{};
    DWORD VirtualAddress = 0;
    DWORD VirtualSize    = 0;
    DWORD RawOffset      = 0;
    DWORD RawSize        = 0;
    DWORD Characteristics = 0;
};

struct RipReferenceHit {
    DWORD TargetRva = 0;
    int   Score     = 0;
    DWORD KindMask  = 0;
    DWORD InstrLen  = 0;  // total instruction length in bytes (filled by decoder)
    DWORD ImmValue  = 0;  // immediate operand: mask for test/cmp, bit index for bt/bts, 0 for mov
};

// Probe window inside CiPolicy where g_CiOptions is expected.
constexpr DWORD kCiPolicyProbeWindow    = 0x40;
constexpr DWORD kCiOptionsCandidateStep = sizeof(DWORD);

// Instruction kind bits used in scoring.
constexpr DWORD kRipKindMov = 0x0001;
constexpr DWORD kRipKindTest = 0x0002;
constexpr DWORD kRipKindBt   = 0x0004;
constexpr DWORD kRipKindBts  = 0x0008;
constexpr DWORD kRipKindCmp  = 0x0010;

// ------------------------------------------------------------------

bool LoadBinaryFile(const std::wstring& path, std::vector<BYTE>& outData) noexcept {
    FileGuard file(CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) {
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file.get(), &fileSize) ||
        fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > 0x10000000) {
        return false;
    }

    outData.resize(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(file.get(), outData.data(),
                  static_cast<DWORD>(outData.size()), &bytesRead, nullptr)) {
        return false;
    }

    return bytesRead == static_cast<DWORD>(outData.size());
}

bool ParsePeSections(const std::vector<BYTE>& image,
                     std::vector<PeSectionView>& sections) noexcept {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return false;
    }

    const DWORD ntOffset = static_cast<DWORD>(dos->e_lfanew);
    if (ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > image.size()) {
        return false;
    }

    const BYTE* nt = image.data() + ntOffset;
    if (*reinterpret_cast<const DWORD*>(nt) != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        nt + sizeof(DWORD));
    if (fileHeader->NumberOfSections == 0 ||
        fileHeader->NumberOfSections > 96) {
        return false;
    }

    const DWORD sectionOffset = ntOffset + sizeof(DWORD) +
                                sizeof(IMAGE_FILE_HEADER) +
                                fileHeader->SizeOfOptionalHeader;
    const size_t sectionBytes = static_cast<size_t>(fileHeader->NumberOfSections) *
                                sizeof(IMAGE_SECTION_HEADER);
    if (sectionOffset + sectionBytes > image.size()) {
        return false;
    }

    sections.clear();
    sections.reserve(fileHeader->NumberOfSections);

    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
        const auto* s = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            image.data() + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)));

        PeSectionView view{};
        memcpy(view.Name.data(), s->Name, 8);
        view.Name[8]         = '\0';
        view.VirtualAddress  = s->VirtualAddress;
        view.VirtualSize     = s->Misc.VirtualSize;
        view.RawOffset       = s->PointerToRawData;
        view.RawSize         = s->SizeOfRawData;
        view.Characteristics = s->Characteristics;
        sections.push_back(view);
    }

    return true;
}

const PeSectionView* FindSectionByName(const std::vector<PeSectionView>& sections,
                                       const char* name) noexcept {
    for (const auto& s : sections) {
        if (strcmp(s.Name.data(), name) == 0) {
            return &s;
        }
    }
    return nullptr;
}

bool IsExecutableSection(const PeSectionView& s) noexcept {
    return (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
           s.RawOffset != 0 &&
           s.RawSize   != 0;
}

// Win10 kernel drivers mark PAGE/INIT as IMAGE_SCN_CNT_CODE but often omit
// IMAGE_SCN_MEM_EXECUTE in the PE headers (execute permission granted at load
// time by the memory manager).  Use this broader check when scanning for
// RIP-relative references so we do not miss the PAGE section.
bool IsCodeSection(const PeSectionView& s) noexcept {
    return ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
            (s.Characteristics & IMAGE_SCN_CNT_CODE)    != 0) &&
           s.RawOffset != 0 &&
           s.RawSize   != 0;
}

DWORD GetSectionSpan(const std::vector<BYTE>& image,
                     const PeSectionView& s) noexcept {
    if (s.RawOffset >= image.size()) {
        return 0;
    }
    const size_t available = image.size() - s.RawOffset;
    return static_cast<DWORD>(std::min<size_t>(s.RawSize, available));
}

DWORD ComputeRipTargetRva(DWORD instrRva,
                           DWORD instrLen,
                           LONG displacement) noexcept {
    return static_cast<DWORD>(
        static_cast<LONGLONG>(instrRva) + instrLen + displacement);
}

int CountBits(DWORD value) noexcept {
    int n = 0;
    while (value != 0) {
        n += (value & 1U) ? 1 : 0;
        value >>= 1;
    }
    return n;
}

// Extra score for immediate masks that look like known CiOptions flag patterns.
int ScoreFlagMask(DWORD mask) noexcept {
    int score = 0;
    if ((mask & 0x00000006U) != 0) { score += 6; } // DSE bits
    if ((mask & 0x0001C000U) != 0) { score += 6; } // HVCI bits
    if ((mask & 0x00200000U) != 0) { score += 4; } // additional CI flag
    if ((mask & 0x00004000U) != 0 ||
        (mask & 0x00008000U) != 0) { score += 2; }
    return score;
}

// Light hint from the live kernel value at a candidate address.
// Zero is a valid CiOptions value (DSE disabled), so only penalise clearly
// wrong values (high bits set, negative-looking DWORDs).
int ScoreCurrentValueHint(DWORD value) noexcept {
    int score = 0;
    if ((value & 0xFF000000U) == 0) { score += 6; }
    if ((value & 0x0000FFFFU) != 0) { score += 2; }
    if ((value & 0x00000006U) != 0) { score += 8; } // DSE active
    if ((value & 0x0001C000U) != 0) { score += 6; } // HVCI active
    if ((value & 0x00200000U) != 0) { score += 4; }
    if (value == 0)                 { score += 2; } // DSE disabled, still valid
    if ((value & 0x80000000U) != 0) { score -= 8; } // sign bit - not a flags field
    return score;
}

// Attempt to decode one RIP-relative instruction at code[0..available-1].
// Recognised encodings:
//   REX.* 8B /5  -> mov r32, [rip+disp32]
//   8B /5        -> mov r32, [rip+disp32]   (no REX)
//   F7 /5 imm32  -> test [rip+disp32], imm32
//   0F BA /4 ib  -> bt  [rip+disp32], imm8
//   0F BA /5 ib  -> bts [rip+disp32], imm8
//   81 /7 imm32  -> cmp [rip+disp32], imm32
bool DecodeRipRelativeReference(const BYTE* code,
                                size_t available,
                                DWORD instrRva,
                                RipReferenceHit& outHit) noexcept {
    // REX + MOV r32, [RIP+disp32]  (7 bytes)
    if (available >= 7 &&
        (code[0] & 0xF0) == 0x40 &&
        code[1] == 0x8B &&
        (code[2] & 0xC7) == 0x05) {
        const LONG disp  = *reinterpret_cast<const LONG*>(code + 3);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 7, disp);
        outHit.Score     = 12;
        outHit.KindMask  = kRipKindMov;
        outHit.InstrLen  = 7;
        outHit.ImmValue  = 0;
        return true;
    }

    // MOV r32, [RIP+disp32]  (6 bytes, no REX)
    if (available >= 6 &&
        code[0] == 0x8B &&
        (code[1] & 0xC7) == 0x05) {
        const LONG disp  = *reinterpret_cast<const LONG*>(code + 2);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 6, disp);
        outHit.Score     = 12;
        outHit.KindMask  = kRipKindMov;
        outHit.InstrLen  = 6;
        outHit.ImmValue  = 0;
        return true;
    }

    // TEST [RIP+disp32], imm32  (10 bytes)
    if (available >= 10 &&
        code[0] == 0xF7 &&
        code[1] == 0x05) {
        const LONG  disp = *reinterpret_cast<const LONG*>(code + 2);
        const DWORD mask = *reinterpret_cast<const DWORD*>(code + 6);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 10, disp);
        outHit.Score     = 18 + ScoreFlagMask(mask);
        outHit.KindMask  = kRipKindTest;
        outHit.InstrLen  = 10;
        outHit.ImmValue  = mask;
        return true;
    }

    // BT / BTS [RIP+disp32], imm8  (8 bytes)
    if (available >= 8 &&
        code[0] == 0x0F &&
        code[1] == 0xBA &&
        (code[2] == 0x25 || code[2] == 0x2D)) {
        const LONG disp  = *reinterpret_cast<const LONG*>(code + 3);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 8, disp);
        outHit.Score     = 16;
        outHit.KindMask  = (code[2] == 0x25) ? kRipKindBt : kRipKindBts;
        outHit.InstrLen  = 8;
        outHit.ImmValue  = code[7]; // imm8 bit index
        return true;
    }

    // CMP [RIP+disp32], imm32  (10 bytes)
    if (available >= 10 &&
        code[0] == 0x81 &&
        code[1] == 0x3D) {
        const LONG  disp = *reinterpret_cast<const LONG*>(code + 2);
        const DWORD mask = *reinterpret_cast<const DWORD*>(code + 6);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 10, disp);
        outHit.Score     = 10 + ScoreFlagMask(mask);
        outHit.KindMask  = kRipKindCmp;
        outHit.InstrLen  = 10;
        outHit.ImmValue  = mask;
        return true;
    }

    // TEST [RIP+disp32], r32  (6 bytes, no REX)
    // Opcode: 85 (ModRM & 0xC7 == 0x05) disp32
    // Win10 ci.dll uses register-loaded masks (e.g. mov ebx,4000h / test [rip+x],ebx).
    // ImmValue=0 because the mask is in a register - scored conservatively.
    if (available >= 6 &&
        code[0] == 0x85 &&
        (code[1] & 0xC7) == 0x05) {
        const LONG disp  = *reinterpret_cast<const LONG*>(code + 2);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 6, disp);
        outHit.Score     = 15;
        outHit.KindMask  = kRipKindTest;
        outHit.InstrLen  = 6;
        outHit.ImmValue  = 0;
        return true;
    }

    // REX + TEST [RIP+disp32], r64/r32  (7 bytes)
    // Opcode: [REX] 85 (ModRM & 0xC7 == 0x05) disp32
    if (available >= 7 &&
        (code[0] & 0xF0) == 0x40 &&
        code[1] == 0x85 &&
        (code[2] & 0xC7) == 0x05) {
        const LONG disp  = *reinterpret_cast<const LONG*>(code + 3);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 7, disp);
        outHit.Score     = 15;
        outHit.KindMask  = kRipKindTest;
        outHit.InstrLen  = 7;
        outHit.ImmValue  = 0;
        return true;
    }

    return false;
}

// After a mov reg32, [rip+disp32], inspect the next few instructions for
// the immediate mask used in a test/and on that register.  Returns the full
// 32-bit mask so the caller can extract both low-bit evidence (bits 0-4) and
// high-bit family evidence (0x4000/0x8000/0x200000/0x800000) from one call.
// Returns 0 if no recognisable test pattern is found within the window.
DWORD LookAheadTestMask(const BYTE* code, size_t avail) noexcept {
    for (size_t i = 0; i < avail && i < 32; ) {
        // test al, imm8  (A8 ib) - 8-bit register, mask fits in byte
        if (code[i] == 0xA8 && i + 1 < avail) {
            return code[i + 1];
        }
        // test r8, imm8  (F6 /0 ib)  ModRM = 11 000 reg
        if (code[i] == 0xF6 && i + 2 < avail &&
            (code[i + 1] & 0xF8) == 0xC0) {
            return code[i + 2];
        }
        // test r32, imm32  (F7 /0 id) - return full mask, no 0x1F cap
        if (code[i] == 0xF7 && i + 5 < avail &&
            (code[i + 1] & 0xF8) == 0xC0) {
            return *reinterpret_cast<const DWORD*>(code + i + 2);
        }
        // and r32, imm8 sign-extended  (83 /4 ib)
        if (code[i] == 0x83 && i + 2 < avail &&
            (code[i + 1] & 0xF8) == 0xE0) {
            return code[i + 2];
        }
        // shr r32, imm8 - advance past it, test may follow
        if (code[i] == 0xC1 && i + 2 < avail &&
            (code[i + 1] & 0xF8) == 0xE8) {
            i += 3;
            continue;
        }
        i++;
    }
    return 0;
}

} // namespace

// ============================================================================
// CONSTRUCTION
// ============================================================================

CiOptionsFinder::CiOptionsFinder(std::unique_ptr<kvc>& driver) noexcept
    : m_driver(driver)
{
}

// ============================================================================
// PUBLIC ENTRY POINT
// ============================================================================

ULONG_PTR CiOptionsFinder::FindCiOptions(ULONG_PTR ciBase) noexcept {
    DEBUG(L"CiOptionsFinder: searching g_CiOptions in ci.dll at base 0x%llX", ciBase);

    const auto ciPath = GetCiDllPath();
    if (!ciPath) {
        return 0;
    }

    // Live kernel PE walk - check whether ci.dll exposes a CiPolicy section.
    const auto ciPolicy = GetCiPolicySection(ciBase);

    ULONG_PTR ciOptionsAddr = 0;

    if (ciPolicy) {
        // --- Win11 path: CiPolicy section present ---
        const ULONG_PTR ciPolicyStart = ciPolicy->first;
        const SIZE_T    ciPolicySize  = ciPolicy->second;
        DEBUG(L"CiPolicy live: 0x%llX  size: 0x%llX", ciPolicyStart, ciPolicySize);

        // Stage 1: semantic RIP-relative probe
        if (auto semanticOffset =
                FindCiOptionsOffsetFromCiPolicy(*ciPath, ciPolicyStart, ciPolicySize)) {
            ciOptionsAddr = ciPolicyStart + *semanticOffset;
            SUCCESS(L"g_CiOptions via CiPolicy probe: 0x%llX  (+0x%X)",
                    ciOptionsAddr, *semanticOffset);
        } else {
            // Stage 2: build-aware fallback (+0x4 or +0x8)
            INFO(L"WARNING: CiPolicy probe inconclusive, using build-aware fallback");

            auto fallbackOffset = GetCiOptionsBuildFallbackOffset();
            if (!fallbackOffset) {
                ERROR(L"Failed to determine build-aware fallback offset");
                return 0;
            }

            const std::array<DWORD, 2> fallbackCandidates = {
                *fallbackOffset,
                (*fallbackOffset == 0x8) ? 0x4U : 0x8U
            };

            for (DWORD candidateOffset : fallbackCandidates) {
                if (candidateOffset >= static_cast<DWORD>(ciPolicySize)) {
                    continue;
                }

                const ULONG_PTR candidateAddr = ciPolicyStart + candidateOffset;
                auto candidateValue = m_driver->Read32(candidateAddr);
                if (!candidateValue) {
                    continue;
                }

                if (ScoreCurrentValueHint(*candidateValue) < 0) {
                    continue;
                }

                ciOptionsAddr = candidateAddr;
                INFO(L"Fallback candidate +0x%X  value: 0x%08X",
                     candidateOffset, *candidateValue);
                break;
            }
        }

        if (!ciOptionsAddr) {
            ERROR(L"Failed to locate g_CiOptions in CiPolicy");
            return 0;
        }
    } else {
        // --- Win10 path: no CiPolicy - scan .data by high/low-bit family scoring ---
        INFO(L"CiPolicy section absent - trying Win10 .data semantic probe");

        auto addr = FindCiOptionsInDataSection(*ciPath, ciBase);
        if (!addr) {
            ERROR(L"g_CiOptions not found (no CiPolicy, .data probe failed)");
            return 0;
        }
        ciOptionsAddr = *addr;
    }

    auto currentValue = m_driver->Read32(ciOptionsAddr);
    if (!currentValue) {
        ERROR(L"Failed to read g_CiOptions at 0x%llX", ciOptionsAddr);
        return 0;
    }

    DEBUG(L"g_CiOptions: 0x%llX  value: 0x%08X", ciOptionsAddr, currentValue.value());
    return ciOptionsAddr;
}

// ============================================================================
// PRIVATE HELPERS
// ============================================================================

std::optional<std::wstring> CiOptionsFinder::GetCiDllPath() noexcept {
    wchar_t systemPath[MAX_PATH] = {};
    if (GetSystemDirectoryW(systemPath, MAX_PATH) == 0) {
        ERROR(L"Failed to get system directory for ci.dll");
        return std::nullopt;
    }

    std::wstring ciPath = std::wstring(systemPath) + L"\\ci.dll";
    if (!PathFileExistsW(ciPath.c_str())) {
        ERROR(L"ci.dll not found on disk: %s", ciPath.c_str());
        return std::nullopt;
    }

    return ciPath;
}

// Walk the live kernel image (via driver reads) to find the CiPolicy PE section.
std::optional<std::pair<ULONG_PTR, SIZE_T>>
CiOptionsFinder::GetCiPolicySection(ULONG_PTR moduleBase) noexcept {
    auto dosHeader = m_driver->Read16(moduleBase);
    if (!dosHeader || dosHeader.value() != 0x5A4D) {
        return std::nullopt;
    }

    auto e_lfanew = m_driver->Read32(moduleBase + 0x3C);
    if (!e_lfanew || e_lfanew.value() > 0x1000) {
        return std::nullopt;
    }

    ULONG_PTR ntHeaders = moduleBase + e_lfanew.value();

    auto peSignature = m_driver->Read32(ntHeaders);
    if (!peSignature || peSignature.value() != 0x4550) {
        return std::nullopt;
    }

    auto numSections = m_driver->Read16(ntHeaders + 0x6);
    if (!numSections || numSections.value() > 50) {
        return std::nullopt;
    }

    auto sizeOfOptionalHeader = m_driver->Read16(ntHeaders + 0x14);
    if (!sizeOfOptionalHeader) {
        return std::nullopt;
    }

    ULONG_PTR firstSection = ntHeaders + 4 + 20 + sizeOfOptionalHeader.value();

    DEBUG(L"Scanning %d sections for live CiPolicy...", numSections.value());

    for (WORD i = 0; i < numSections.value(); i++) {
        ULONG_PTR sectionHeader = firstSection + (i * 40);

        char name[9] = {0};
        for (int j = 0; j < 8; j++) {
            auto ch = m_driver->Read8(sectionHeader + j);
            if (ch) {
                name[j] = static_cast<char>(ch.value());
            }
        }

        if (strcmp(name, "CiPolicy") == 0) {
            auto virtualSize = m_driver->Read32(sectionHeader + 0x08);
            auto virtualAddr = m_driver->Read32(sectionHeader + 0x0C);

            if (virtualSize && virtualAddr) {
                DEBUG(L"Found CiPolicy at RVA 0x%06X  size 0x%06X",
                      virtualAddr.value(), virtualSize.value());
                return std::make_pair(
                    moduleBase + virtualAddr.value(),
                    static_cast<SIZE_T>(virtualSize.value()));
            }
        }
    }

    DEBUG(L"CiPolicy section not found in ci.dll");
    return std::nullopt;
}

// Scan all executable sections of the on-disk ci.dll for RIP-relative
// references that land within the first kCiPolicyProbeWindow bytes of
// the CiPolicy section.  Score and rank candidates, return the winner
// offset relative to CiPolicy start, or nullopt if inconclusive.
std::optional<DWORD> CiOptionsFinder::FindCiOptionsOffsetFromCiPolicy(
    const std::wstring& ciPath,
    ULONG_PTR ciPolicyStart,
    SIZE_T    ciPolicySize) noexcept {

    struct CandidateScore {
        DWORD Offset     = 0;
        LONG  Score      = 0;
        DWORD Hits       = 0;
        DWORD StrongHits = 0;
        DWORD KindMask   = 0;
    };

    std::vector<BYTE> image;
    if (!LoadBinaryFile(ciPath, image)) {
        ERROR(L"Failed to read ci.dll from disk for CiPolicy probe");
        return std::nullopt;
    }

    std::vector<PeSectionView> sections;
    if (!ParsePeSections(image, sections)) {
        ERROR(L"Failed to parse ci.dll PE headers for CiPolicy probe");
        return std::nullopt;
    }

    const PeSectionView* ciPolicy = FindSectionByName(sections, "CiPolicy");
    if (!ciPolicy) {
        INFO(L"CiPolicy section not present in ci.dll - semantic probe skipped");
        return std::nullopt;
    }

    const DWORD sectionSize =
        ciPolicy->VirtualSize != 0 ? ciPolicy->VirtualSize : ciPolicy->RawSize;
    DWORD probeWindow =
        static_cast<DWORD>(std::min<SIZE_T>(ciPolicySize, sectionSize));
    probeWindow = std::min<DWORD>(probeWindow, kCiPolicyProbeWindow);
    probeWindow -= (probeWindow % kCiOptionsCandidateStep);

    if (probeWindow < kCiOptionsCandidateStep) {
        INFO(L"CiPolicy section too small for semantic probe");
        return std::nullopt;
    }

    const DWORD numCandidates = probeWindow / kCiOptionsCandidateStep;
    std::vector<CandidateScore> candidates(numCandidates);

    for (DWORD i = 0; i < numCandidates; ++i) {
        auto& c = candidates[i];
        c.Offset = i * kCiOptionsCandidateStep;

        // Seed score with live value hint (read from kernel).
        auto liveValue = m_driver->Read32(ciPolicyStart + c.Offset);
        if (liveValue) {
            c.Score += ScoreCurrentValueHint(*liveValue);
        }

        // Bias towards lower offsets - g_CiOptions historically near start.
        const LONG proximityBias =
            std::max<LONG>(0, 6 - static_cast<LONG>(i));
        c.Score += proximityBias;
    }

    const DWORD ciPolicyRva    = ciPolicy->VirtualAddress;
    const DWORD ciPolicyEndRva = ciPolicyRva + probeWindow;

    for (const auto& section : sections) {
        if (!IsExecutableSection(section)) {
            continue;
        }

        const DWORD span = GetSectionSpan(image, section);
        if (span == 0) {
            continue;
        }

        const BYTE* code = image.data() + section.RawOffset;

        for (DWORD i = 0; i < span; ++i) {
            RipReferenceHit hit{};
            if (!DecodeRipRelativeReference(code + i, span - i,
                                            section.VirtualAddress + i, hit)) {
                continue;
            }

            if (hit.TargetRva < ciPolicyRva || hit.TargetRva >= ciPolicyEndRva) {
                continue;
            }

            const DWORD candidateOffset = hit.TargetRva - ciPolicyRva;
            if ((candidateOffset % kCiOptionsCandidateStep) != 0) {
                continue;
            }

            auto& c = candidates[candidateOffset / kCiOptionsCandidateStep];
            c.Score    += hit.Score;
            c.Hits     += 1;
            c.KindMask |= hit.KindMask;

            if (hit.Score >= 16) {
                c.StrongHits += 1;
            }
            if ((hit.KindMask &
                 (kRipKindTest | kRipKindBt | kRipKindBts | kRipKindCmp)) != 0) {
                c.Score += 2;
            }
        }
    }

    LONG bestScore   = -0x7FFFFFFF;
    LONG secondScore = -0x7FFFFFFF;
    const CandidateScore* best = nullptr;

    for (auto& c : candidates) {
        c.Score += static_cast<LONG>(CountBits(c.KindMask) * 6);
        c.Score += std::min<LONG>(static_cast<LONG>(c.Hits) * 3, 15);
        if (c.StrongHits >= 2) {
            c.Score += 10;
        }

        if (c.Score > bestScore) {
            secondScore = bestScore;
            bestScore   = c.Score;
            best        = &c;
        } else if (c.Score > secondScore) {
            secondScore = c.Score;
        }
    }

    if (!best) {
        return std::nullopt;
    }

    const bool hasFlagsLikeUse =
        (best->KindMask & (kRipKindTest | kRipKindBt | kRipKindBts | kRipKindCmp)) != 0;
    const bool clearWinner = (bestScore - secondScore) >= 8;
    const bool denseUsage  = best->Hits >= 3 && best->StrongHits >= 1;

    if (bestScore < 32 || !hasFlagsLikeUse || (!clearWinner && !denseUsage)) {
        INFO(L"CiPolicy probe inconclusive (best score=%ld, hits=%lu)",
             bestScore, best->Hits);
        return std::nullopt;
    }

    INFO(L"CiPolicy probe: g_CiOptions at +0x%X  (score=%ld, hits=%lu)",
         best->Offset, bestScore, best->Hits);
    return best->Offset;
}

// Win10 path: no CiPolicy section.
// Scan all executable sections of the on-disk ci.dll for RIP-relative references
// into .data, then rank candidates using a two-family scoring scheme:
//   High-bit family: direct test/cmp with masks 0x4000/0x8000/0x200000/0x800000
//   Low-bit family:  mov -> lookahead for test of bits 1/2/4/8/0x10
//                    or bt/bts operations
// False-positives (g_CiPolicyState, g_CiDeveloperMode) are filtered out by
// requiring BOTH a high-bit hit AND low-bit evidence, plus a 25% score margin.
// Runtime Read32 is applied only to the top-3 candidates as a tie-breaker.
std::optional<ULONG_PTR> CiOptionsFinder::FindCiOptionsInDataSection(
    const std::wstring& ciPath,
    ULONG_PTR ciBase) noexcept {

    struct Win10Candidate {
        DWORD    Rva              = 0;
        LONG     Score            = 0;
        DWORD    TotalHits        = 0;
        DWORD    DirectHighMasks  = 0; // bit0=0x4000/0x8000, bit1=0x200000/0x800000
        DWORD    LowBitEvidence   = 0; // OR of low bits from lookahead (bits 0..4)
        DWORD    BitOpsCount      = 0; // bt/bts hits
        DWORD    KindMask         = 0;
        DWORD    LastRefRva       = 0; // for distinct-function approximation
        DWORD    DistinctFuncApx  = 1; // at least 1
    };

    std::vector<BYTE> image;
    if (!LoadBinaryFile(ciPath, image)) {
        ERROR(L"Win10 .data probe: failed to read ci.dll from disk");
        return std::nullopt;
    }

    std::vector<PeSectionView> sections;
    if (!ParsePeSections(image, sections)) {
        ERROR(L"Win10 .data probe: failed to parse PE headers");
        return std::nullopt;
    }

    const PeSectionView* dataSec = FindSectionByName(sections, ".data");
    if (!dataSec || dataSec->RawOffset == 0) {
        INFO(L"Win10 .data probe: no .data section in ci.dll");
        return std::nullopt;
    }

    const DWORD dataRva    = dataSec->VirtualAddress;
    const DWORD dataSize   = dataSec->VirtualSize != 0 ? dataSec->VirtualSize
                                                        : dataSec->RawSize;
    const DWORD dataEndRva = dataRva + dataSize;

    if (dataSize < sizeof(DWORD)) {
        INFO(L"Win10 .data probe: .data section too small");
        return std::nullopt;
    }

    const DWORD numCandidates = dataSize / sizeof(DWORD);
    std::vector<Win10Candidate> candidates(numCandidates);
    for (DWORD i = 0; i < numCandidates; ++i) {
        candidates[i].Rva = dataRva + i * sizeof(DWORD);
    }

    // Scan all code sections: .text, PAGE, INIT (if present).
    // Use IsCodeSection (not IsExecutableSection) because Win10 kernel drivers
    // mark PAGE/INIT as IMAGE_SCN_CNT_CODE but omit IMAGE_SCN_MEM_EXECUTE.
    for (const auto& section : sections) {
        if (!IsCodeSection(section)) {
            continue;
        }

        const DWORD span = GetSectionSpan(image, section);
        if (span == 0) {
            continue;
        }

        const BYTE* code = image.data() + section.RawOffset;

        for (DWORD i = 0; i < span; ++i) {
            // Win10 ci.dll uses 0x2E (CS segment override) prefix on many
            // RIP-relative accesses - skip it transparently.
            DWORD prefixLen = 0;
            if (code[i] == 0x2E && (i + 1) < span) {
                prefixLen = 1;
            }

            if (i + prefixLen >= span) {
                continue;
            }

            const BYTE*  insn    = code + i + prefixLen;
            const size_t avail   = span - i - prefixLen;
            const DWORD  instrRva = section.VirtualAddress + i + prefixLen;

            RipReferenceHit hit{};
            if (!DecodeRipRelativeReference(insn, avail, instrRva, hit)) {
                continue;
            }

            // Only care about references landing in .data, 4-byte aligned.
            if (hit.TargetRva < dataRva || hit.TargetRva >= dataEndRva) {
                continue;
            }
            if ((hit.TargetRva % 4) != 0) {
                continue;
            }

            const DWORD idx = (hit.TargetRva - dataRva) / sizeof(DWORD);
            if (idx >= numCandidates) {
                continue;
            }

            auto& c = candidates[idx];
            const DWORD refRva = section.VirtualAddress + i;

            // Approximate distinct-function count: count a new function if the
            // previous reference was more than 0x200 bytes away.
            if (c.TotalHits > 0 && (refRva - c.LastRefRva) > 0x200) {
                c.DistinctFuncApx++;
            }
            c.LastRefRva = refRva;
            c.TotalHits++;
            c.KindMask |= hit.KindMask;

            // Base score from the generic scorer (flag mask awareness baked in).
            c.Score += hit.Score;

            // Win10-specific: extra weight for CI-critical high-bit families.
            if ((hit.KindMask & (kRipKindTest | kRipKindCmp)) != 0 &&
                hit.ImmValue != 0) {
                if ((hit.ImmValue & 0x200000U) || (hit.ImmValue & 0x800000U)) {
                    if ((c.DirectHighMasks & 0x2) == 0) {
                        c.DirectHighMasks |= 0x2;
                        c.Score += 30;
                    }
                } else if ((hit.ImmValue & 0x4000U) || (hit.ImmValue & 0x8000U)) {
                    if ((c.DirectHighMasks & 0x1) == 0) {
                        c.DirectHighMasks |= 0x1;
                        c.Score += 20;
                    }
                }
            }

            if ((hit.KindMask & (kRipKindBt | kRipKindBts)) != 0) {
                c.BitOpsCount++;
                // Score already in hit.Score; no double-count here.
            }

            // Lookahead after mov: check the next test/and for any mask bits.
            // Catches both low-bit evidence and high-bit family tests that the
            // compiler emits as "mov reg,[rip+x] / test reg,highMask" rather
            // than the direct "test [rip+x],highMask" memory form.
            if ((hit.KindMask & kRipKindMov) != 0 && hit.InstrLen > 0) {
                const DWORD afterByte = i + prefixLen + hit.InstrLen;
                if (afterByte < span) {
                    const DWORD fullMask =
                        LookAheadTestMask(code + afterByte, span - afterByte);

                    if (fullMask != 0) {
                        // High-bit family via register (lower bonus than direct test)
                        if ((fullMask & 0x200000U) || (fullMask & 0x800000U)) {
                            if ((c.DirectHighMasks & 0x2) == 0) {
                                c.DirectHighMasks |= 0x2;
                                c.Score += 20;
                            }
                        } else if ((fullMask & 0x4000U) || (fullMask & 0x8000U)) {
                            if ((c.DirectHighMasks & 0x1) == 0) {
                                c.DirectHighMasks |= 0x1;
                                c.Score += 15;
                            }
                        }

                        // Low-bit evidence (bits 0-4)
                        const DWORD lowBits = fullMask & 0x1F;
                        const DWORD newLow  = lowBits & ~c.LowBitEvidence;
                        if (newLow != 0) {
                            c.LowBitEvidence |= newLow;
                            c.Score += 12 * CountBits(newLow);
                        }
                    }
                }
            }
        }
    }

    // Post-scan bonuses
    for (auto& c : candidates) {
        // Distinct-function bonus (capped to avoid runaway)
        c.Score += std::min<LONG>(
            static_cast<LONG>(c.DistinctFuncApx) * 3, 60);

        // xref volume bonus (log-ish steps)
        if (c.TotalHits >= 5)  { c.Score +=  5; }
        if (c.TotalHits >= 15) { c.Score += 10; }
        if (c.TotalHits >= 30) { c.Score += 15; }
        if (c.TotalHits >= 60) { c.Score += 20; }

        // Penalty: candidate has only "policy/developer-like" masks without
        // any bit-test evidence - likely a different CI variable.
        if (c.DirectHighMasks == 0 && c.LowBitEvidence == 0 &&
            c.BitOpsCount == 0) {
            c.Score -= 40;
        }
    }

    // --- Select winner from semantically qualified candidates only ---
    //
    // Qualification requires EITHER a direct high-bit family test (memory form)
    // OR at least 2 bt/bts operations, PLUS low-bit evidence from mov->lookahead.
    //
    // Key insight: high-volume non-flag variables (locks, counters, pointers) may
    // accumulate a large raw score but lack bts ops and specific flag-bit tests.
    // By restricting the selection pool to qualified candidates and computing the
    // margin only within that pool, such variables cannot crowd out g_CiOptions.

    const Win10Candidate* winner = nullptr;
    const Win10Candidate* runner = nullptr;

    for (const auto& c : candidates) {
        if (c.Score < 50) {
            continue;
        }
        const bool cHasHighBit = (c.DirectHighMasks != 0);
        const bool cHasBitOps  = (c.BitOpsCount >= 2);
        const bool cHasLowBit  = (c.LowBitEvidence != 0) || (c.BitOpsCount > 0);

        if (!((cHasHighBit || cHasBitOps) && cHasLowBit)) {
            continue;
        }

        if (!winner || c.Score > winner->Score) {
            runner = winner;
            winner = &c;
        } else if (!runner || c.Score > runner->Score) {
            runner = &c;
        }
    }

    if (!winner) {
        INFO(L"Win10 .data probe: no qualified candidate found");
        return std::nullopt;
    }

    const LONG winScore = winner->Score;
    const LONG runScore = runner ? runner->Score : -1;

    // Margin check among qualified candidates only.
    const bool clearMargin = (runScore < 0) ||
                              (winScore >= runScore + std::max<LONG>(runScore / 4, 1));

    if (!clearMargin) {
        INFO(L"Win10 .data probe inconclusive: margin too small "
             L"(best=%ld, second=%ld, highMasks=0x%X, lowBits=0x%X, bitOps=%lu)",
             winScore, runScore,
             winner->DirectHighMasks, winner->LowBitEvidence, winner->BitOpsCount);
        return std::nullopt;
    }

    // Light sanity check: read live value to detect obvious misidentification.
    // A non-zero high byte suggests a pointer or counter, not a DWORD flags field.
    // Log a warning but still return - the caller validates and logs the value too.
    auto liveHint = m_driver->Read32(ciBase + winner->Rva);
    if (liveHint && (liveHint.value() & 0xFF000000U) != 0) {
        INFO(L"Win10 .data probe WARNING: winner RVA=0x%X live value=0x%08X "
             L"has high byte set (score=%ld, bitOps=%lu) - verify result",
             winner->Rva, liveHint.value(), winScore, winner->BitOpsCount);
    }

    const ULONG_PTR resultAddr = ciBase + winner->Rva;
    SUCCESS(L"g_CiOptions via Win10 .data probe: 0x%llX  "
            L"(RVA=0x%X, score=%ld, hits=%lu, highMasks=0x%X, lowBits=0x%X, bitOps=%lu)",
            resultAddr, winner->Rva, winScore, winner->TotalHits,
            winner->DirectHighMasks, winner->LowBitEvidence, winner->BitOpsCount);
    return resultAddr;
}

std::optional<DWORD> CiOptionsFinder::GetCiOptionsBuildFallbackOffset() noexcept {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return std::nullopt;
    }

    using RtlGetVersionFn = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);
    auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (!rtlGetVersion) {
        return std::nullopt;
    }

    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (rtlGetVersion(&vi) != 0) {
        return std::nullopt;
    }

    // 26H1 (build 26100) moved g_CiOptions from CiPolicy+0x4 to CiPolicy+0x8.
    return (vi.dwBuildNumber >= 26100)
        ? std::optional<DWORD>(0x8)
        : std::optional<DWORD>(0x4);
}
