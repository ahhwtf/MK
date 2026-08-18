; ==============================================================================
; Vault Guard - Theme / Appearance
;
; Author: Marek Wesołowski (wesmar)
; Purpose: DWM dark mode, Mica backdrop, font creation, WM_SETFONT helper.
;
; Exported:
;   _ReadDarkMode()          → void   [reads HKCU AppsUseLightTheme → g_isDarkMode]
;   ApplyDarkMode(rcx=hwnd)  → void
;   CreateFonts()            → void   [writes g_hFontMain, g_hFontSmall]
;   _SendFont(rcx=hwnd, rdx=hFont)  → void
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN DwmSetWindowAttribute     :PROC
EXTRN CreateFontW               :PROC
EXTRN SendMessageW              :PROC
EXTRN RegOpenKeyExW             :PROC
EXTRN RegQueryValueExW          :PROC
EXTRN RegCloseKey               :PROC
EXTRN CreateSolidBrush          :PROC
EXTRN DeleteObject              :PROC
EXTRN GetSysColor               :PROC
EXTRN SetWindowTheme            :PROC

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_fontname        dw 'S','e','g','o','e',' ','U','I',0
str_dark_explorer   dw 'D','a','r','k','M','o','d','e','_','E','x','p','l','o','r','e','r',0

; Registry path: HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
str_reg_themes_key  dw 'S','o','f','t','w','a','r','e','\','M','i','c','r','o','s','o','f','t'
                    dw '\','W','i','n','d','o','w','s','\','C','u','r','r','e','n','t','V','e','r'
                    dw 's','i','o','n','\','T','h','e','m','e','s','\','P','e','r','s','o','n'
                    dw 'a','l','i','z','e',0

; Value name: AppsUseLightTheme  (0=dark, 1=light)
str_reg_light_val   dw 'A','p','p','s','U','s','e','L','i','g','h','t','T','h','e','m','e',0

; ==============================================================================
; UNINITIALIZED DATA  (scratch for _ReadDarkMode)
; ==============================================================================
.data?

rdm_hkey    dq ?
rdm_val     dd ?
rdm_vtype   dd ?
rdm_vsize   dd ?

; ==============================================================================
; CODE
; ==============================================================================
.code

PUBLIC _ReadDarkMode
PUBLIC ApplyDarkMode
PUBLIC CreateFonts
PUBLIC _SendFont
PUBLIC _SetLvColors
PUBLIC _ApplyThemeColors

; ==============================================================================
; _ReadDarkMode  →  void
; Reads HKCU\...\Themes\Personalize\AppsUseLightTheme
; AppsUseLightTheme DWORD: 0 = dark, 1 = light
; Sets g_isDarkMode: 1 = dark, 0 = light
; Falls back to dark on any registry error.
;
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 38h (+56)→0 ✓
; RegOpenKeyExW  5 args: rcx,rdx,r8,r9,[+20h]
; RegQueryValueExW 6 args: rcx,rdx,r8,r9,[+20h],[+28h]
; ==============================================================================
_ReadDarkMode proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 38h

    ; RegOpenKeyExW(HKCU, str_reg_themes_key, 0, KEY_READ, &rdm_hkey)
    lea     rax, rdm_hkey
    mov     qword ptr [rsp+20h], rax
    mov     r9d, KEY_READ
    xor     r8d, r8d
    lea     rdx, str_reg_themes_key
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @rdm_default_dark

    ; RegQueryValueExW(rdm_hkey, str_reg_light_val, NULL, &rdm_vtype, &rdm_val, &rdm_vsize)
    mov     dword ptr rdm_vsize, 4
    lea     rax, rdm_vsize
    mov     qword ptr [rsp+28h], rax
    lea     rax, rdm_val
    mov     qword ptr [rsp+20h], rax
    lea     r9, rdm_vtype
    xor     r8d, r8d
    lea     rdx, str_reg_light_val
    mov     rcx, rdm_hkey
    call    RegQueryValueExW
    mov     rbx, rax            ; save return code

    ; RegCloseKey(rdm_hkey)
    mov     rcx, rdm_hkey
    call    RegCloseKey

    test    ebx, ebx
    jnz     @rdm_default_dark

    ; AppsUseLightTheme 0 → dark (g_isDarkMode=1), non-zero → light (g_isDarkMode=0)
    mov     eax, dword ptr rdm_val
    test    eax, eax
    jnz     @rdm_light
    mov     g_isDarkMode, 1
    jmp     @rdm_done

@rdm_light:
    mov     g_isDarkMode, 0
    jmp     @rdm_done

@rdm_default_dark:
    mov     g_isDarkMode, 1

@rdm_done:
    add     rsp, 38h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_ReadDarkMode endp

; ==============================================================================
; ApplyDarkMode  rcx=hwnd  →  void
; Sets DWM title-bar dark/light based on g_isDarkMode (1=dark, 0=light).
; Mica backdrop is always applied (looks fine in both modes).
;
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
ApplyDarkMode proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rbx, rcx

    ; DWMWA_USE_IMMERSIVE_DARK_MODE (attr 20) — Windows 11
    ; value = g_isDarkMode: 1 = enable dark title bar, 0 = light
    mov     eax, g_isDarkMode
    mov     dword ptr [rsp+20h], eax
    mov     r9d, 4
    lea     r8, [rsp+20h]
    mov     edx, DWMWA_USE_IMMERSIVE_DARK_MODE
    mov     rcx, rbx
    call    DwmSetWindowAttribute

    ; Legacy attr 19 for older builds
    mov     eax, g_isDarkMode
    mov     dword ptr [rsp+20h], eax
    mov     r9d, 4
    lea     r8, [rsp+20h]
    mov     edx, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD
    mov     rcx, rbx
    call    DwmSetWindowAttribute

    ; Mica DWMWA_SYSTEMBACKDROP_TYPE = DWMSBT_MAINWINDOW (2)
    mov     dword ptr [rsp+20h], DWMSBT_MAINWINDOW
    mov     r9d, 4
    lea     r8, [rsp+20h]
    mov     edx, DWMWA_SYSTEMBACKDROP_TYPE
    mov     rcx, rbx
    call    DwmSetWindowAttribute

    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
ApplyDarkMode endp

; ==============================================================================
; CreateFonts  →  void
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 78h (+120)→0 ✓
; CreateFontW: 14 args → rcx..r9 (4) + 10 stack slots = [+20h..+68h]
; ==============================================================================
CreateFonts proc
    push    rbx
    push    rsi
    sub     rsp, 78h

    ; Segoe UI 18pt bold — main labels
    lea     rax, str_fontname
    mov     qword ptr [rsp+68h], rax    ; lpszFace
    mov     dword ptr [rsp+60h], 0      ; iPitchAndFamily
    mov     dword ptr [rsp+58h], 5      ; iQuality = CLEARTYPE_QUALITY
    mov     dword ptr [rsp+50h], 0      ; iClipPrecision
    mov     dword ptr [rsp+48h], 0      ; iOutPrecision
    mov     dword ptr [rsp+40h], 1      ; iCharSet = DEFAULT_CHARSET
    mov     dword ptr [rsp+38h], 0      ; bStrikeOut
    mov     dword ptr [rsp+30h], 0      ; bUnderline
    mov     dword ptr [rsp+28h], 0      ; bItalic
    mov     dword ptr [rsp+20h], 600    ; cWeight = FW_SEMIBOLD
    xor     r9d, r9d                    ; cOrientation
    xor     r8d, r8d                    ; cEscapement
    xor     edx, edx                    ; cWidth
    mov     ecx, -18                    ; cHeight (negative = char height)
    call    CreateFontW
    mov     g_hFontMain, rax

    ; Segoe UI 14pt normal — list items, buttons
    lea     rax, str_fontname
    mov     qword ptr [rsp+68h], rax
    mov     dword ptr [rsp+60h], 0
    mov     dword ptr [rsp+58h], 5
    mov     dword ptr [rsp+50h], 0
    mov     dword ptr [rsp+48h], 0
    mov     dword ptr [rsp+40h], 1
    mov     dword ptr [rsp+38h], 0
    mov     dword ptr [rsp+30h], 0
    mov     dword ptr [rsp+28h], 0
    mov     dword ptr [rsp+20h], 400    ; FW_NORMAL
    xor     r9d, r9d
    xor     r8d, r8d
    xor     edx, edx
    mov     ecx, -14
    call    CreateFontW
    mov     g_hFontSmall, rax

    add     rsp, 78h
    pop     rsi
    pop     rbx
    ret
CreateFonts endp

; ==============================================================================
; _SendFont  rcx=hwnd  rdx=hFont  →  void
; Sends WM_SETFONT (lParam=1 = redraw)
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_SendFont proc
    push    rbx
    push    rsi
    sub     rsp, 28h
    mov     r9d, 1              ; lParam = redraw
    mov     r8, rdx             ; wParam = hFont
    mov     edx, WM_SETFONT
    call    SendMessageW        ; rcx = hwnd already
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_SendFont endp

; ==============================================================================
; _SetLvColors  rcx=hwndLv  rdx=isDark  →  void
; Sets SetWindowTheme + LVM text/bg colors for one ListView.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_SetLvColors proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rbx, rcx           ; hwndLv
    mov     esi, edx           ; isDark

    ; SetWindowTheme
    xor     r8d, r8d
    test    esi, esi
    jz      @slc_theme_light
    lea     rdx, str_dark_explorer
    jmp     @slc_theme_call
@slc_theme_light:
    xor     edx, edx
@slc_theme_call:
    mov     rcx, rbx
    call    SetWindowTheme

    ; LVM_SETTEXTCOLOR
    test    esi, esi
    jz      @slc_tc_light
    mov     r9d, COLORREF_DARK_TEXT
    jmp     @slc_tc_call
@slc_tc_light:
    mov     r9d, CLR_DEFAULT
@slc_tc_call:
    xor     r8d, r8d
    mov     edx, LVM_SETTEXTCOLOR
    mov     rcx, rbx
    call    SendMessageW

    ; LVM_SETTEXTBKCOLOR
    test    esi, esi
    jz      @slc_tbk_light
    mov     r9d, COLORREF_DARK_LV_BG
    jmp     @slc_tbk_call
@slc_tbk_light:
    mov     r9d, CLR_DEFAULT
@slc_tbk_call:
    xor     r8d, r8d
    mov     edx, LVM_SETTEXTBKCOLOR
    mov     rcx, rbx
    call    SendMessageW

    ; LVM_SETBKCOLOR
    test    esi, esi
    jz      @slc_bk_light
    mov     r9d, COLORREF_DARK_LV_BG
    jmp     @slc_bk_call
@slc_bk_light:
    mov     r9d, CLR_DEFAULT
@slc_bk_call:
    xor     r8d, r8d
    mov     edx, LVM_SETBKCOLOR
    mov     rcx, rbx
    call    SendMessageW

    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_SetLvColors endp

; ==============================================================================
; _ApplyThemeColors  →  void
; Recreates g_hBrushBg, calls _SetLvColors for both ListViews.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_ApplyThemeColors proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    ; ── Background brush ────────────────────────────────────────────────────
    mov     rcx, g_hBrushBg
    test    rcx, rcx
    jz      @atc_create_brush
    call    DeleteObject
    xor     eax, eax
    mov     g_hBrushBg, rax

@atc_create_brush:
    cmp     g_isDarkMode, 0
    je      @atc_light_brush
    mov     ecx, COLORREF_DARK_BG
    call    CreateSolidBrush
    jmp     @atc_brush_done

@atc_light_brush:
    mov     ecx, COLOR_WINDOW_VAL
    call    GetSysColor
    mov     ecx, eax
    call    CreateSolidBrush

@atc_brush_done:
    mov     g_hBrushBg, rax

    ; ── Paths ListView ──────────────────────────────────────────────────────
    mov     rcx, g_hwndLvPaths
    test    rcx, rcx
    jz      @atc_done
    mov     edx, g_isDarkMode
    call    _SetLvColors

    ; ── Trusted ListView ────────────────────────────────────────────────────
    mov     rcx, g_hwndLvTrusted
    test    rcx, rcx
    jz      @atc_done
    mov     edx, g_isDarkMode
    call    _SetLvColors

@atc_done:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_ApplyThemeColors endp

end
