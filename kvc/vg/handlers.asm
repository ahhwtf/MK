; ==============================================================================
; Vault Guard - Command Handlers
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Status bar refresh and WM_COMMAND dispatch (toggle, add/remove
;          path, add/remove trusted process).
;
; Exported:
;   UpdateStatusBar()                        → void
;   _OnCommand(rcx=hwnd, rdx=wParam)         → void
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

; ── Win32 ─────────────────────────────────────────────────────────────────────
EXTRN SetWindowTextW            :PROC
EXTRN GetWindowTextW            :PROC
EXTRN SendMessageW              :PROC
EXTRN MessageBoxW               :PROC
EXTRN SHBrowseForFolderW        :PROC
EXTRN SHGetPathFromIDListW      :PROC
EXTRN CoTaskMemFree             :PROC
EXTRN DialogBoxIndirectParamW   :PROC
EXTRN IsDlgButtonChecked        :PROC
EXTRN EndDialog                 :PROC
EXTRN SetDlgItemTextW           :PROC
EXTRN DwmSetWindowAttribute     :PROC

EXTRN EnsureDriverReady         :PROC
EXTRN OpenDevice                :PROC
EXTRN CloseDevice               :PROC
EXTRN IoctlGetStatus            :PROC
EXTRN IoctlSetActive            :PROC
EXTRN IoctlAddPath              :PROC
EXTRN IoctlAddTrusted           :PROC
EXTRN IoctlRemoveTrusted        :PROC

EXTRN ConfigLoad                :PROC
EXTRN ConfigSavePath            :PROC
EXTRN ConfigRemovePath          :PROC
EXTRN ConfigSaveTrusted         :PROC
EXTRN ConfigRemoveTrusted       :PROC

EXTRN g_statusResult            :BYTE   ; defined in driver.asm

; ── Sibling modules ───────────────────────────────────────────────────────────
EXTRN RefreshLists              :PROC
EXTRN _LvGetSelIdx              :PROC
EXTRN _LvGetItemText            :PROC
EXTRN _LvSetRowParam            :PROC
EXTRN _LvGetRowParam            :PROC
EXTRN wcscmp_ci                 :PROC
EXTRN wcs_ascii_lower_inplace   :PROC

; ── Cross-module data (defined in layout.asm) ─────────────────────────────────
EXTRN g_hwndEditTrusted         :QWORD

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

; Status labels — also referenced by window.asm (_OnCreate initial text)
PUBLIC str_drv_stopped
PUBLIC str_prot_off
PUBLIC str_btn_toggle_off

str_drv_running     dw 'D','r','i','v','e','r',':',' ','T','R','A','N','S','I','E','N','T',0
str_drv_stopped     dw 'D','r','i','v','e','r',':',' ','S','T','O','P','P','E','D',0
str_prot_on         dw 'P','r','o','t','e','c','t','i','o','n',':',' ','O','N',0
str_prot_off        dw 'P','r','o','t','e','c','t','i','o','n',':',' ','O','F','F',0
str_btn_toggle_on   dw 'D','i','s','a','b','l','e',' ','p','r','o','t','e','c','t','i','o','n',0
str_btn_toggle_off  dw 'E','n','a','b','l','e',' ','p','r','o','t','e','c','t','i','o','n',0

; Window title strings — status embedded so no separate labels needed in client area
str_title_stopped   dw 'V','a','u','l','t','G','u','a','r','d',' ','|'
                    dw ' ','D','r','i','v','e','r',':',' ','S','T','O','P','P','E','D'
                    dw ' ','|',' ','P','r','o','t','e','c','t','i','o','n',':',' ','O','F','F',0
str_title_run_off   dw 'V','a','u','l','t','G','u','a','r','d',' ','|'
                    dw ' ','D','r','i','v','e','r',':',' ','T','R','A','N','S','I','E','N','T'
                    dw ' ','|',' ','P','r','o','t','e','c','t','i','o','n',':',' ','O','F','F',0
str_title_run_on    dw 'V','a','u','l','t','G','u','a','r','d',' ','|'
                    dw ' ','D','r','i','v','e','r',':',' ','T','R','A','N','S','I','E','N','T'
                    dw ' ','|',' ','P','r','o','t','e','c','t','i','o','n',':',' ','O','N',0

; Dialog strings
str_add_path_title  dw 'S','e','l','e','c','t',' ','F','o','l','d','e','r',0
str_err_nosel       dw 'N','o',' ','i','t','e','m',' ','s','e','l','e','c','t','e','d','.',0
str_err_empty_proc  dw 'E','n','t','e','r',' ','a',' ','p','r','o','c','e','s','s',' ','n','a','m','e',' ','f','i','r','s','t','.',0
str_err_title       dw 'E','r','r','o','r',0
str_blank           dw 0


; ==============================================================================
; DATA
; ==============================================================================
.data
    align 8

; BROWSEINFO scratch (72 bytes x64)
browse_info         db BROWSEINFO_SIZE dup(0)

; Path buffer for SHGetPathFromIDListW
path_pidl_buf       dw (MAX_PATH + 4) dup(0)

; Trusted process name buffer
trusted_edit_buf    dw (MAX_PATH + 4) dup(0)

; ==============================================================================
; In-memory DLGTEMPLATE for "Set protection" dialog (286 bytes total).
; Layout: STATIC(path) + 4×BS_AUTOCHECKBOX + BS_DEFPUSHBUTTON("Done").
; Positions in dialog units. No DS_SETFONT — uses system font.
; DWORD-alignment between DLGITEMTEMPLATE entries verified per offset.
; ==============================================================================
    align 4
dlg_prot_tmpl   label byte
    ; DLGTEMPLATE header — 52 bytes, DWORD aligned at offset 0
    dd  080C80880h          ; WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_MODALFRAME|DS_CENTER
    dd  0                   ; dwExtendedStyle
    dw  6                   ; cdit = 6 items
    dw  0, 0, 210, 110      ; x=0 y=0 cx=210 cy=110 DLU
    dw  0, 0                ; menu=none, class=default
    dw  'S','e','t',' ','p','r','o','t','e','c','t','i','o','n',0  ; title (15 WCHARs=30b)
    ; offset 52, DWORD aligned ✓

    ; Item 0: STATIC path display — 26 bytes at offset 52 → pad to 80
    dd  050000000h          ; WS_CHILD|WS_VISIBLE
    dd  0
    dw  5, 4, 200, 14       ; x=5 y=4 cx=200 cy=14
    dw  IDC_DLG_PATH        ; id=100
    dw  0FFFFh, 0082h       ; STATIC class atom
    dw  0                   ; empty title (filled via SetDlgItemTextW)
    dw  0                   ; extraCount=0
    dw  0                   ; alignment pad (78→80)

    ; Item 1: Hidden checkbox — 38 bytes at offset 80 → pad to 120
    dd  050010003h          ; WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX
    dd  0
    dw  10, 22, 100, 12
    dw  IDC_CHK_HIDDEN
    dw  0FFFFh, 0080h       ; BUTTON class atom
    dw  'H','i','d','d','e','n',0
    dw  0                   ; extraCount=0
    dw  0                   ; alignment pad (118→120)

    ; Item 2: Locked checkbox — 38 bytes at offset 120 → pad to 160
    dd  050010003h
    dd  0
    dw  10, 36, 100, 12
    dw  IDC_CHK_LOCKED
    dw  0FFFFh, 0080h
    dw  'L','o','c','k','e','d',0
    dw  0
    dw  0                   ; alignment pad (158→160)

    ; Item 3: Read-only checkbox — 44 bytes at offset 160 → aligned at 204
    dd  050010003h
    dd  0
    dw  10, 50, 100, 12
    dw  IDC_CHK_READONLY
    dw  0FFFFh, 0080h
    dw  'R','e','a','d','-','o','n','l','y',0
    dw  0                   ; extraCount=0
    ; 160+44=204, 204%4=0 — no pad needed

    ; Item 4: No execute checkbox — 46 bytes at offset 204 → pad to 252
    dd  050010003h
    dd  0
    dw  10, 64, 100, 12
    dw  IDC_CHK_NOEXEC
    dw  0FFFFh, 0080h
    dw  'N','o',' ','e','x','e','c','u','t','e',0
    dw  0                   ; extraCount=0
    dw  0                   ; alignment pad (250→252)

    ; Item 5: Done button — 34 bytes at offset 252 → total 286 bytes
    dd  050010001h          ; WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON
    dd  0
    dw  75, 90, 60, 14
    dw  IDOK                ; id=1
    dw  0FFFFh, 0080h
    dw  'D','o','n','e',0
    dw  0                   ; extraCount=0

.data?
    lv_text_buf     dw 520 dup(?)   ; GetItemText scratch
    dlg_path_ptr    dq ?            ; ptr to current path string (set before dialog opens)
    dlg_cur_flags   dd ?            ; current applied flags in protection dialog

PUBLIC g_pendingPath
g_pendingPath   dw (MAX_PATH + 4) dup(?)

; ==============================================================================
; CODE
; ==============================================================================
.code

PUBLIC UpdateStatusBar
PUBLIC _OnCommand
PUBLIC _OnNotify

; ==============================================================================
; UpdateStatusBar  →  void
; Refreshes driver/protection status labels and toggle button text.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
UpdateStatusBar proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    call    EnsureDriverReady
    test    eax, eax
    jz      @usb_no_driver

    call    IoctlGetStatus
    test    eax, eax
    jz      @usb_close_no_status

    ; ── Driver label: only repaint when state transitions → running ──────────
    cmp     byte ptr [g_prevDrvOk], 1
    je      @usb_drv_label_skip
    mov     byte ptr [g_prevDrvOk], 1
    lea     rdx, str_drv_running
    mov     rcx, g_hwndDrvStatus        ; NULL → no-op; status lives in title bar
    call    SetWindowTextW
@usb_drv_label_skip:

    ; ── Prot + toggle: only repaint when prot state changes ──────────────────
    movzx   eax, byte ptr [g_statusResult + VG_ST_ISACTIVE]
    mov     g_protActive, eax
    movzx   ecx, byte ptr [g_prevProtActive]
    cmp     ecx, eax
    je      @usb_prot_skip
    mov     byte ptr [g_prevProtActive], al

    test    eax, eax
    lea     rdx, str_prot_on
    jnz     @usb_prot_yes
    lea     rdx, str_prot_off
@usb_prot_yes:
    mov     rcx, g_hwndProtStatus       ; NULL → no-op
    call    SetWindowTextW

    test    g_protActive, 1
    lea     rdx, str_btn_toggle_on
    jnz     @usb_toggle_yes
    lea     rdx, str_btn_toggle_off
@usb_toggle_yes:
    mov     rcx, g_hwndBtnToggle
    call    SetWindowTextW

    ; ── Update window title with combined status ──────────────────────────────
    test    g_protActive, 1
    lea     rdx, str_title_run_on
    jnz     @usb_title_yes
    lea     rdx, str_title_run_off
@usb_title_yes:
    mov     rcx, g_hwndMain
    call    SetWindowTextW
@usb_prot_skip:

    call    CloseDevice
    jmp     @usb_ret

@usb_close_no_status:
    call    CloseDevice
@usb_no_driver:
    ; Only repaint when state transitions → stopped; reset prot sentinel too
    cmp     byte ptr [g_prevDrvOk], 0
    je      @usb_ret
    mov     byte ptr [g_prevDrvOk], 0
    mov     byte ptr [g_prevProtActive], 0FFh
    lea     rdx, str_drv_stopped
    mov     rcx, g_hwndDrvStatus        ; NULL → no-op
    call    SetWindowTextW
    lea     rdx, str_prot_off
    mov     rcx, g_hwndProtStatus       ; NULL → no-op
    call    SetWindowTextW
    lea     rdx, str_btn_toggle_off
    mov     rcx, g_hwndBtnToggle
    call    SetWindowTextW
    ; ── Update title to stopped state ────────────────────────────────────────
    lea     rdx, str_title_stopped
    mov     rcx, g_hwndMain
    call    SetWindowTextW

@usb_ret:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
UpdateStatusBar endp

; ==============================================================================
; _FlagsDlgApply  rcx=hwndDlg  →  void
; Reads 4 checkbox states → builds flags → applies via IOCTL + registry.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_FlagsDlgApply proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx                    ; dialog hwnd

    ; Read checkbox states → accumulate flags in r12d
    xor     r12d, r12d                  ; flags = 0 (clear all bits first)

    mov     edx, IDC_CHK_HIDDEN
    mov     rcx, rbx
    call    IsDlgButtonChecked
    test    eax, eax
    jz      @fda_no_h
    or      r12d, VG_FLAG_HIDDEN         ; hide folder from shell
@fda_no_h:
    mov     edx, IDC_CHK_LOCKED
    mov     rcx, rbx
    call    IsDlgButtonChecked
    test    eax, eax
    jz      @fda_no_l
    or      r12d, VG_FLAG_LOCKED         ; block all file writes
@fda_no_l:
    mov     edx, IDC_CHK_READONLY
    mov     rcx, rbx
    call    IsDlgButtonChecked
    test    eax, eax
    jz      @fda_no_r
    or      r12d, VG_FLAG_READONLY       ; block writes, allow reads
@fda_no_r:
    mov     edx, IDC_CHK_NOEXEC
    mov     rcx, rbx
    call    IsDlgButtonChecked
    test    eax, eax
    jz      @fda_no_x
    or      r12d, VG_FLAG_NOEXEC         ; block process creation inside folder
@fda_no_x:

    call    EnsureDriverReady
    test    eax, eax
    jz      @fda_done

    test    r12d, r12d
    jz      @fda_zero_flags

    ; flags > 0: add/update path protection in driver + persist to registry
    mov     rdx, qword ptr [dlg_path_ptr]   ; target path
    mov     ecx, r12d                       ; new flag bitmask
    call    IoctlAddPath                    ; tell driver: protect this path
    mov     ecx, 1
    call    IoctlSetActive                  ; ensure protection is globally enabled
    call    CloseDevice
    mov     edx, r12d
    mov     rcx, qword ptr [dlg_path_ptr]
    call    ConfigSavePath                  ; persist flags to registry
    jmp     @fda_commit

@fda_zero_flags:
    ; flags = 0: unprotect this path only; keep zero entry in registry (retains row)
    mov     rdx, qword ptr [dlg_path_ptr]
    xor     ecx, ecx                        ; flags = 0 = unprotect
    call    IoctlAddPath
    call    CloseDevice
    xor     edx, edx
    mov     rcx, qword ptr [dlg_path_ptr]
    call    ConfigSavePath                  ; write flags=0 to registry

@fda_commit:
    mov     dword ptr [dlg_cur_flags], r12d ; remember for next change check

@fda_done:
    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_FlagsDlgApply endp

; ==============================================================================
; _FlagsDlgProc  rcx=hwnd  rdx=msg  r8=wParam  r9=lParam  →  rax=TRUE/FALSE
; Dialog proc for protection flags dialog. Checkboxes apply changes live.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_FlagsDlgProc proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx                    ; hwnd
    mov     esi, edx                    ; msg
    mov     rdi, r8                     ; wParam

    cmp     esi, WM_INITDIALOG
    je      @fdp_init
    cmp     esi, WM_COMMAND
    je      @fdp_cmd
    cmp     esi, WM_CLOSE
    je      @fdp_close
    xor     eax, eax
    jmp     @fdp_ret

@fdp_init:
    ; Dark title bar if dark mode active
    mov     r9d, 4                          ; cbAttribute = sizeof(BOOL)
    lea     r8, g_isDarkMode                ; pvAttribute
    mov     edx, DWMWA_USE_IMMERSIVE_DARK_MODE
    mov     rcx, rbx
    call    DwmSetWindowAttribute           ; set dark/light title bar

    ; Show current path in the STATIC label at top of dialog
    mov     r8, qword ptr [dlg_path_ptr]    ; path string set by _ShowFlagsDialog
    mov     edx, IDC_DLG_PATH
    mov     rcx, rbx
    call    SetDlgItemTextW

    mov     eax, 1
    jmp     @fdp_ret

@fdp_cmd:
    movzx   ecx, di                     ; low word of wParam = control ID
    cmp     ecx, IDC_CHK_HIDDEN
    jb      @fdp_cmd_ok
    cmp     ecx, IDC_CHK_NOEXEC
    ja      @fdp_cmd_ok
    ; Any of the 4 protection checkboxes toggled → re-apply all flags live
    mov     rcx, rbx
    call    _FlagsDlgApply              ; reads all checkboxes, IOCTLs, saves
    mov     eax, 1
    jmp     @fdp_ret

@fdp_cmd_ok:
    cmp     ecx, IDOK
    jne     @fdp_cmd_done
    xor     edx, edx
    mov     rcx, rbx
    call    EndDialog
    mov     eax, 1
    jmp     @fdp_ret

@fdp_cmd_done:
    xor     eax, eax
    jmp     @fdp_ret

@fdp_close:
    xor     edx, edx
    mov     rcx, rbx
    call    EndDialog
    mov     eax, 1

@fdp_ret:
    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_FlagsDlgProc endp

; ==============================================================================
; _ShowFlagsDialog  rcx=hwndOwner  rdx=pathPtr  →  void
; Opens protection flags dialog; checkbox toggles apply changes live.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 28h (+40)→0 ✓
; [rsp+20h] = 5th arg (lParam) for DialogBoxIndirectParamW.
; ==============================================================================
_ShowFlagsDialog proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx                    ; hwndOwner
    mov     qword ptr [dlg_path_ptr], rdx
    mov     dword ptr [dlg_cur_flags], 0

    xor     eax, eax
    mov     qword ptr [rsp+20h], rax    ; lParam = 0
    lea     r9, _FlagsDlgProc
    mov     r8, rbx
    lea     rdx, dlg_prot_tmpl
    mov     rcx, g_hInstance
    call    DialogBoxIndirectParamW

    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_ShowFlagsDialog endp

; ==============================================================================
; _OnNotify  rcx=hwnd  rdx=NMHDR*  →  void
; Handles WM_NOTIFY from g_hwndLvPaths: NM_CLICK → inline checkbox toggle.
; Stack: push rbx,rsi,rdi,r12,r13,r14 (6×8=48)→rsp%16=8; sub 48h (+72)→0 ✓
; [rsp+40h] = temp slot for original_flags
; ==============================================================================
_OnNotify proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 48h

    mov     rbx, rcx            ; hwnd (unused after entry)
    mov     rsi, rdx            ; NMHDR*

    ; Only handle clicks on g_hwndLvPaths
    mov     rax, qword ptr [rsi + 0]    ; NMHDR.hwndFrom
    cmp     rax, g_hwndLvPaths          ; only handle clicks on protected paths list
    jne     @on_ret

    ; Only NM_CLICK (not NM_DBLCLK etc.)
    mov     eax, dword ptr [rsi + 16]   ; NMHDR.nCode (offset 16 in x64 NMHDR)
    cmp     eax, NM_CLICK
    jne     @on_ret

    ; iItem (row): must be >= 0 (not a header click)
    mov     r12d, dword ptr [rsi + NMIA_iItem]
    cmp     r12d, 0
    jl      @on_ret

    ; iSubItem (col): 1=Hidden 2=Locked 3=ReadOnly 4=NoExec
    mov     r13d, dword ptr [rsi + NMIA_iSubItem]
    cmp     r13d, 1
    jl      @on_ret                     ; col 0 = path text, not a flag
    cmp     r13d, 4
    jg      @on_ret

    ; map column to flag bit: col1->bit0 col2->bit1 col3->bit2 col4->bit3
    mov     ecx, r13d
    dec     ecx                         ; ecx = iSubItem - 1
    mov     r14d, 1
    shl     r14d, cl                    ; r14d = VG_FLAG_* to toggle

    ; Get current flags (lParam) for this row -- stored by RefreshLists
    mov     rdx, r12
    mov     rcx, g_hwndLvPaths
    call    _LvGetRowParam
    mov     edi, eax                    ; edi = original_flags (DWORD)

    ; lParam == 0 means this is the "pending" row (not yet applied to driver)
    mov     dword ptr [rsp + 40h], edi

    ; Toggle the clicked flag bit
    xor     edi, r14d                   ; edi = new_flags after toggle

    ; Get path text (col 0) into lv_text_buf
    lea     r9, lv_text_buf
    xor     r8d, r8d
    mov     rdx, r12
    mov     rcx, g_hwndLvPaths
    call    _LvGetItemText

    ; Clear pending marker only when this row's path matches g_pendingPath
    ; (lParam==0 is not a reliable sentinel: registry entries with flags=0 also have lParam=0)
    cmp     word ptr [g_pendingPath], 0
    je      @on_not_pending
    lea     rdx, lv_text_buf
    lea     rcx, g_pendingPath
    call    wcscmp_ci
    test    eax, eax
    jnz     @on_not_pending
    mov     word ptr [g_pendingPath], 0
@on_not_pending:

    call    EnsureDriverReady
    test    eax, eax
    jz      @on_ret

    test    edi, edi
    jz      @on_zero_flags

    ; flags > 0: add/update path protection
    lea     rdx, lv_text_buf
    mov     ecx, edi
    call    IoctlAddPath
    mov     ecx, 1
    call    IoctlSetActive
    call    CloseDevice
    mov     edx, edi
    lea     rcx, lv_text_buf
    call    ConfigSavePath
    jmp     @on_refresh

@on_zero_flags:
    ; All flags cleared: remove protection in driver; keep registry entry with flags=0
    lea     rdx, lv_text_buf
    xor     ecx, ecx                    ; flags = 0 = unprotect
    call    IoctlAddPath
    call    CloseDevice
    xor     edx, edx                    ; flags = 0
    lea     rcx, lv_text_buf
    call    ConfigSavePath              ; persist inactive entry so row survives restart

@on_refresh:
    call    RefreshLists

@on_ret:
    add     rsp, 48h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_OnNotify endp

; ==============================================================================
; _OnCommand  rcx=hwnd  rdx=wParam(controlId in low word)  →  void
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12,r13,r14 (+48)→8; sub 38h (+56)→0 ✓
; ==============================================================================
_OnCommand proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 38h

    mov     rbx, rcx            ; hwnd
    movzx   rsi, dx             ; control ID (low word of wParam)

    ; ── Toggle ───────────────────────────────────────────────────────────────
    cmp     esi, IDC_BTN_TOGGLE
    jne     @oc_not_toggle

    call    EnsureDriverReady
    test    eax, eax
    jz      @oc_toggle_done

    test    g_protActive, 1
    jnz     @oc_toggle_disable
    ; Enable: paths loaded at startup via ConfigLoad; just flip the active bit
    mov     ecx, 1                      ; active = 1
    call    IoctlSetActive
    jmp     @oc_toggle_close
@oc_toggle_disable:
    xor     ecx, ecx                    ; active = 0
    call    IoctlSetActive
@oc_toggle_close:
    call    CloseDevice
    call    UpdateStatusBar
@oc_toggle_done:
    jmp     @oc_done

    ; ── Add Path ─────────────────────────────────────────────────────────────
@oc_not_toggle:
    cmp     esi, IDC_BTN_ADD_PATH
    jne     @oc_not_add_path

    ; Zero browse_info
    lea     rcx, browse_info
    xor     eax, eax
    mov     r10, BROWSEINFO_SIZE / 8
@oc_bi_zero:
    mov     qword ptr [rcx], rax
    add     rcx, 8
    dec     r10
    jnz     @oc_bi_zero

    lea     r10, browse_info
    mov     qword ptr [r10 + 0], rbx           ; hwndOwner
    lea     rax, str_add_path_title
    mov     qword ptr [r10 + 24], rax           ; lpszTitle
    mov     dword ptr [r10 + 32], (BIF_USENEWUI + BIF_BROWSEINCLUDEFILES)  ; folder or file

    lea     rcx, browse_info
    call    SHBrowseForFolderW
    test    rax, rax
    jz      @oc_add_path_done

    mov     r12, rax            ; pidl

    lea     rdx, path_pidl_buf
    mov     rcx, r12
    call    SHGetPathFromIDListW

    mov     rcx, r12
    call    CoTaskMemFree

    ; Stage path as "pending": shown with empty checkboxes until user ticks one
    lea     r10, path_pidl_buf          ; source: path resolved from PIDL
    lea     r11, g_pendingPath          ; destination: global pending path
    xor     ecx, ecx                    ; WCHAR index
@oc_copy_pending:
    movzx   eax, word ptr [r10 + rcx * 2]
    mov     word ptr [r11 + rcx * 2], ax
    test    ax, ax
    jz      @oc_copy_done               ; null terminator copied
    inc     ecx
    cmp     ecx, MAX_PATH
    jl      @oc_copy_pending
    mov     word ptr [r11 + rcx * 2], 0 ; force-null at MAX_PATH
@oc_copy_done:
    call    RefreshLists

@oc_add_path_done:
    jmp     @oc_done

    ; ── Restore (Remove) Path — multi-select, no confirmation ───────────────────
@oc_not_add_path:
    cmp     esi, IDC_BTN_REM_PATH
    jne     @oc_not_rem_path

    ; Bail if nothing selected
    mov     r9d, LVNI_SELECTED
    mov     r8d, -1
    mov     edx, LVM_GETNEXTITEM
    mov     rcx, g_hwndLvPaths
    call    SendMessageW
    cmp     rax, -1
    je      @oc_rem_path_nosel

@oc_rem_path_loop:
    ; Restart from -1: LVM_DELETEITEM shifts indices, so first selected is always stable
    mov     r9d, LVNI_SELECTED
    mov     r8d, -1
    mov     edx, LVM_GETNEXTITEM
    mov     rcx, g_hwndLvPaths
    call    SendMessageW
    cmp     rax, -1
    je      @oc_rem_path_done           ; no more selected items

    mov     r12, rax

    lea     r9, lv_text_buf
    xor     r8d, r8d
    mov     rdx, r12
    mov     rcx, g_hwndLvPaths
    call    _LvGetItemText

    ; Clear g_pendingPath if removing the pending row
    cmp     word ptr [g_pendingPath], 0
    je      @oc_rem_loop_not_pending
    lea     rdx, lv_text_buf
    lea     rcx, g_pendingPath
    call    wcscmp_ci
    test    eax, eax
    jnz     @oc_rem_loop_not_pending
    mov     word ptr [g_pendingPath], 0
@oc_rem_loop_not_pending:

    call    OpenDevice
    test    eax, eax
    jz      @oc_rem_loop_delete

    lea     rdx, lv_text_buf
    xor     ecx, ecx
    call    IoctlAddPath
    test    eax, eax
    jz      @oc_rem_loop_close
    lea     rcx, lv_text_buf
    call    ConfigRemovePath
@oc_rem_loop_close:
    call    CloseDevice

@oc_rem_loop_delete:
    xor     r9d, r9d
    mov     r8, r12
    mov     edx, LVM_DELETEITEM
    mov     rcx, g_hwndLvPaths
    call    SendMessageW
    jmp     @oc_rem_path_loop

@oc_rem_path_done:
    call    RefreshLists
    jmp     @oc_done

@oc_rem_path_nosel:
    mov     r9d, MB_OK + MB_ICONINFORMATION
    lea     r8, str_err_title
    lea     rdx, str_err_nosel
    mov     rcx, rbx
    call    MessageBoxW
    jmp     @oc_done

    ; ── Add Trusted ──────────────────────────────────────────────────────────
@oc_not_rem_path:
    cmp     esi, IDC_BTN_ADD_TRUSTED
    jne     @oc_not_add_trusted

    mov     r8d, MAX_PATH
    lea     rdx, trusted_edit_buf
    mov     rcx, g_hwndEditTrusted
    call    GetWindowTextW
    test    eax, eax
    jz      @oc_add_trusted_empty

    lea     rcx, trusted_edit_buf
    call    wcs_ascii_lower_inplace     ; normalize: driver compares lowercase names

    call    EnsureDriverReady
    test    eax, eax
    jz      @oc_done

    lea     rcx, trusted_edit_buf
    call    IoctlAddTrusted             ; add process name to driver allow-list
    test    eax, eax
    jz      @oc_add_trusted_close
    lea     rcx, trusted_edit_buf
    call    ConfigSaveTrusted           ; persist to HKCU\Software\VG\Trusted
    lea     rdx, str_blank
    mov     rcx, g_hwndEditTrusted
    call    SetWindowTextW              ; clear edit box after successful add
@oc_add_trusted_close:
    call    CloseDevice
    call    RefreshLists
    jmp     @oc_done

@oc_add_trusted_empty:
    mov     r9d, MB_OK + MB_ICONINFORMATION
    lea     r8, str_err_title
    lea     rdx, str_err_empty_proc
    mov     rcx, rbx
    call    MessageBoxW
    jmp     @oc_done

    ; ── Remove Trusted ───────────────────────────────────────────────────────
@oc_not_add_trusted:
    cmp     esi, IDC_BTN_REM_TRUSTED
    jne     @oc_done

    mov     rcx, g_hwndLvTrusted
    call    _LvGetSelIdx
    cmp     rax, -1
    je      @oc_done

    mov     r12, rax

    lea     r9, lv_text_buf
    xor     r8d, r8d
    mov     rdx, r12
    mov     rcx, g_hwndLvTrusted
    call    _LvGetItemText

    ; Registry key uses original casing; driver requires lowercase -- do both.
    lea     rcx, lv_text_buf
    call    ConfigRemoveTrusted         ; delete by original name from registry
    lea     rcx, lv_text_buf
    call    wcs_ascii_lower_inplace     ; normalize for driver

    call    OpenDevice
    test    eax, eax
    jz      @oc_done
    lea     rcx, lv_text_buf
    call    IoctlRemoveTrusted          ; zero-size send clears driver trusted list
    call    CloseDevice
    call    ConfigLoad                  ; reload remaining trusted entries to driver
    call    RefreshLists                ; re-populate ListView from registry

@oc_done:
    add     rsp, 38h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_OnCommand endp

end
