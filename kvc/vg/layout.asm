; ==============================================================================
; Vault Guard - Window Layout
;
; Author: Marek Wesołowski (wesmar)
; Purpose: WM_CREATE handler — creates and configures all child controls.
;
; Exported:
;   _OnCreate(rcx=hwnd)  → void
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

; ── Win32 ─────────────────────────────────────────────────────────────────────
EXTRN CreateWindowExW           :PROC
EXTRN InitCommonControlsEx      :PROC
EXTRN SendMessageW              :PROC
EXTRN SetTimer                  :PROC
EXTRN DragAcceptFiles           :PROC
EXTRN ChangeWindowMessageFilterEx :PROC

; ── Sibling modules ───────────────────────────────────────────────────────────
EXTRN _ReadDarkMode             :PROC   ; theme.asm
EXTRN ApplyDarkMode             :PROC   ; theme.asm
EXTRN _ApplyThemeColors         :PROC   ; theme.asm
EXTRN _SendFont                 :PROC   ; theme.asm
EXTRN CreateFonts               :PROC   ; theme.asm
EXTRN _LvAddColumn              :PROC   ; listview.asm
EXTRN RefreshLists              :PROC   ; listview.asm
EXTRN UpdateStatusBar           :PROC   ; handlers.asm
EXTRN ConfigLoad                :PROC   ; config.asm

EXTRN str_btn_toggle_off        :WORD   ; handlers.asm
EXTRN g_wmTaskbarCreated        :DWORD  ; window.asm

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_buttoncls   dw 'B','U','T','T','O','N',0
str_staticcls   dw 'S','T','A','T','I','C',0
str_listviewcls dw 'S','y','s','L','i','s','t','V','i','e','w','3','2',0
str_editcls     dw 'E','D','I','T',0

str_btn_add_path    dw 'A','d','d',' ','p','a','t','h','.','.','.',0
str_btn_restore     dw 'R','e','m','o','v','e',' ','s','e','l','e','c','t','e','d',0
str_btn_add_proc    dw 'A','d','d',0
str_btn_remove_proc dw 'R','e','m','o','v','e',0

str_hdr_paths       dw 'P','r','o','t','e','c','t','e','d',' ','f','i','l','e','s','/','f','o','l','d','e','r','s',0
str_hdr_trusted     dw 'A','l','l','o','w','e','d',' ','a','p','p','s',' ','(','t','r','u','s','t','e','d',')',0

str_col_path        dw 'P','a','t','h',0
str_col_h           dw 'H','i','d','d','e','n',0
str_col_l           dw 'L','o','c','k','e','d',0
str_col_r           dw 'R','e','a','d','-','o','n','l','y',0
str_col_x           dw 'N','o',' ','r','u','n',0

str_col_process     dw 'P','r','o','c','e','s','s',' ','n','a','m','e',0

str_proc_hint       dw 'e','.','g','.',' ','t','o','t','a','l','c','m','d','6','4','.','e','x','e',0

; Author / copyright line shown at the bottom of the main window.
; Split across multiple dw lines to stay within MASM line-length limits.
; U+0142 = ł (l with stroke),  U+00AE = ® (registered sign)
str_author          dw 'A','u','t','h','o','r',':',' '
                    dw 'M','a','r','e','k',' '
                    dw 'W','e','s','o',0142h,'o','w','s','k','i'
                    dw ' ','-',' '
                    dw 'W','E','S','M','A','R',00AEh,' ','2','0','2','6'
                    dw ' ','-',' '
                    dw 'm','a','r','e','k','@','k','v','c','.','p','l'
                    dw ',',' '
                    dw 't','e','l','/','w','h','a','t','s','a','p','p'
                    dw ':',' ','+','4','8',' '
                    dw '6','0','7','-','4','4','0','-','2','8','3',0

; ==============================================================================
; DATA
; ==============================================================================
.data
    align 8

icc_ex  dd INITCOMMONCONTROLSEX_SIZE
        dd ICC_LISTVIEW_CLASSES

PUBLIC g_hwndEditTrusted
g_hwndEditTrusted   dq 0

; ==============================================================================
; CODE
; ==============================================================================
.code

PUBLIC _OnCreate

; ==============================================================================
; _OnCreate  rcx=hwnd  →  void
; Creates all child controls. Called from WM_CREATE.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12,r13,r14 (+48)→8; sub 68h (+104)→0 ✓
; CreateWindowExW: 12 args → rcx..r9 (4) + 8 stack = [+20h..+58h]
; ==============================================================================
_OnCreate proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 68h

    mov     rbx, rcx            ; hwnd
    mov     g_hwndMain, rbx

    ; Init common controls
    lea     rcx, icc_ex
    call    InitCommonControlsEx

    ; Create fonts
    call    CreateFonts

    ; Detect system dark/light mode → g_isDarkMode
    call    _ReadDarkMode

    ; Apply DWM dark title bar + Mica based on g_isDarkMode
    mov     rcx, rbx
    call    ApplyDarkMode

    ; Accept drops from Explorer
    mov     edx, 1                          ; fAccept = TRUE
    mov     rcx, rbx
    call    DragAcceptFiles
    ; Allow WM_DROPFILES etc. to cross the UAC integrity boundary
    ; (elevated process can receive from non-elevated Explorer)
    xor     r9d, r9d                        ; pdwStatus = NULL
    mov     r8d, MSGFLT_ALLOW
    mov     edx, WM_DROPFILES
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx
    xor     r9d, r9d
    mov     r8d, MSGFLT_ALLOW
    mov     edx, WM_COPYDATA
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx
    xor     r9d, r9d
    mov     r8d, MSGFLT_ALLOW
    mov     edx, WM_COPYGLOBALDATA
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx

    ; Allow TaskbarCreated (registered msg, ID>=C000h) from Medium-IL Explorer
    ; to cross UIPI into this High-IL process. Fixes tray icon not appearing
    ; on logon when launched elevated via Task Scheduler.
    mov     edx, g_wmTaskbarCreated
    test    edx, edx
    jz      @oc_skip_taskbar_flt
    xor     r9d, r9d
    mov     r8d, MSGFLT_ALLOW
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx
@oc_skip_taskbar_flt:

    ; ── Toggle button: x=182 y=8 w=178 h=26 ─────────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_TOGGLE
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 26
    mov     dword ptr [rsp+30h], 178
    mov     dword ptr [rsp+28h], 8
    mov     dword ptr [rsp+20h], 182
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_toggle_off
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     g_hwndBtnToggle, rax
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Paths header static: x=20 y=10 w=157 h=22 ───────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_STATIC_PATHS_HDR
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 22
    mov     dword ptr [rsp+30h], 157
    mov     dword ptr [rsp+28h], 10
    mov     dword ptr [rsp+20h], 20
    mov     r9d, STY_STATIC
    lea     r8, str_hdr_paths
    lea     rdx, str_staticcls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Add folder button: x=364 y=8 w=136 h=26 ─────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_ADD_PATH
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 26
    mov     dword ptr [rsp+30h], 136
    mov     dword ptr [rsp+28h], 8
    mov     dword ptr [rsp+20h], 364
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_add_path
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Remove selected button: x=504 y=8 w=139 h=26 ────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_REM_PATH
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 26
    mov     dword ptr [rsp+30h], 139
    mov     dword ptr [rsp+28h], 8
    mov     dword ptr [rsp+20h], 504
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_restore
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Paths ListView: x=20 y=40 w=624 h=220 ───────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_LV_PATHS
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 220
    mov     dword ptr [rsp+30h], 624
    mov     dword ptr [rsp+28h], 40
    mov     dword ptr [rsp+20h], 20
    mov     r9d, (WS_CHILD_VISIBLE + LVS_REPORT + LVS_SHOWSELALWAYS)
    xor     r8d, r8d
    lea     rdx, str_listviewcls
    mov     ecx, WS_EX_CLIENTEDGE
    call    CreateWindowExW
    mov     g_hwndLvPaths, rax

    ; Full-row select + grid lines + double-buffer (prevents flicker)
    mov     r9d, (LVS_EX_FULLROWSELECT + LVS_EX_GRIDLINES + LVS_EX_DOUBLEBUFFER)
    mov     r8d, (LVS_EX_FULLROWSELECT + LVS_EX_GRIDLINES + LVS_EX_DOUBLEBUFFER)
    mov     edx, LVM_SETEXTENDEDLISTVIEWSTYLE
    mov     rcx, g_hwndLvPaths
    call    SendMessageW

    ; Columns: Path(300) Hidden(80) Locked(80) Read-only(80) No run(80)  total=620=client
    mov     r9, offset str_col_path
    mov     r8d, 300
    xor     edx, edx
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_h
    mov     r8d, 80
    mov     edx, 1
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_l
    mov     r8d, 80
    mov     edx, 2
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_r
    mov     r8d, 80
    mov     edx, 3
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_x
    mov     r8d, 80
    mov     edx, 4
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    ; ── Trusted header: x=20 y=278 w=158 h=22 ───────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_STATIC_TRUSTED_HDR
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 22
    mov     dword ptr [rsp+30h], 158
    mov     dword ptr [rsp+28h], 278
    mov     dword ptr [rsp+20h], 20
    mov     r9d, STY_STATIC
    lea     r8, str_hdr_trusted
    lea     rdx, str_staticcls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted process edit: x=182 y=276 w=318 h=26 ────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_EDIT_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 26
    mov     dword ptr [rsp+30h], 318
    mov     dword ptr [rsp+28h], 276
    mov     dword ptr [rsp+20h], 182
    mov     r9d, (WS_CHILD_VISIBLE + WS_TABSTOP + ES_AUTOHSCROLL)
    lea     r8, str_proc_hint
    lea     rdx, str_editcls
    mov     ecx, WS_EX_CLIENTEDGE
    call    CreateWindowExW
    mov     g_hwndEditTrusted, rax
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted add button: x=504 y=276 w=66 h=26 ───────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_ADD_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 26
    mov     dword ptr [rsp+30h], 66
    mov     dword ptr [rsp+28h], 276
    mov     dword ptr [rsp+20h], 504
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_add_proc
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted remove button: x=574 y=276 w=68 h=26 ────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_REM_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 26
    mov     dword ptr [rsp+30h], 68
    mov     dword ptr [rsp+28h], 276
    mov     dword ptr [rsp+20h], 574
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_remove_proc
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted ListView: x=20 y=308 w=624 h=80 (3 items) ───────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_LV_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 80
    mov     dword ptr [rsp+30h], 624
    mov     dword ptr [rsp+28h], 308
    mov     dword ptr [rsp+20h], 20
    mov     r9d, (WS_CHILD_VISIBLE + LVS_REPORT + LVS_SHOWSELALWAYS + LVS_SINGLESEL)
    xor     r8d, r8d
    lea     rdx, str_listviewcls
    mov     ecx, WS_EX_CLIENTEDGE
    call    CreateWindowExW
    mov     g_hwndLvTrusted, rax

    ; No grid lines for trusted list (single-column list)
    mov     r9d, (LVS_EX_FULLROWSELECT + LVS_EX_DOUBLEBUFFER)
    mov     r8d, (LVS_EX_FULLROWSELECT + LVS_EX_DOUBLEBUFFER)
    mov     edx, LVM_SETEXTENDEDLISTVIEWSTYLE
    mov     rcx, g_hwndLvTrusted
    call    SendMessageW

    ; Column: Process name (620)
    mov     r9, offset str_col_process
    mov     r8d, 620
    xor     edx, edx
    mov     rcx, g_hwndLvTrusted
    call    _LvAddColumn

    ; ── Author / copyright static: x=20 y=396 w=624 h=18 ───────────────────
    ; Centered single-line label below the trusted list; uses STY_STATIC_CENTER
    ; (WS_CHILD | WS_VISIBLE | SS_CENTER).
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_STATIC_AUTHOR
    mov     qword ptr [rsp+40h], rbx
    mov     dword ptr [rsp+38h], 18
    mov     dword ptr [rsp+30h], 624
    mov     dword ptr [rsp+28h], 396
    mov     dword ptr [rsp+20h], 20
    mov     r9d, STY_STATIC_CENTER
    lea     r8, str_author
    lea     rdx, str_staticcls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; Apply theme: brush + SetWindowTheme + LV colors
    call    _ApplyThemeColors

    ; Start periodic refresh timer (polls driver status + updates ListView)
    xor     r9d, r9d                        ; lpTimerFunc = NULL (uses WM_TIMER)
    mov     r8d, TIMER_STATUS_MS            ; interval in ms
    mov     edx, TIMER_STATUS_ID
    mov     rcx, rbx
    call    SetTimer

    ; Bootstrap: read driver status, load persisted config, populate lists
    call    UpdateStatusBar                 ; sets title bar / toggle button text
    call    ConfigLoad                      ; adds saved paths to driver via IOCTL
    call    RefreshLists                    ; populates both ListViews from registry

    add     rsp, 68h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_OnCreate endp

end
