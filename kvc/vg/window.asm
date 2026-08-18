; ==============================================================================
; Vault Guard - Window Scaffold
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Window class registration, creation, message loop dispatch.
;
; Exported:
;   MainWndProc(rcx=hwnd, rdx=msg, r8=wParam, r9=lParam)  → rax
;   CreateMainWindow()                                      → rax = hwnd or NULL
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

; ── Win32 ─────────────────────────────────────────────────────────────────────
EXTRN RegisterClassExW          :PROC
EXTRN CreateWindowExW           :PROC
EXTRN DefWindowProcW            :PROC
EXTRN ShowWindow                :PROC
EXTRN UpdateWindow              :PROC
EXTRN DestroyWindow             :PROC
EXTRN PostQuitMessage           :PROC
EXTRN LoadCursorW               :PROC
EXTRN LoadIconW                 :PROC
EXTRN KillTimer                 :PROC
EXTRN DeleteObject              :PROC
EXTRN GetClientRect             :PROC
EXTRN FillRect                  :PROC
EXTRN SetBkMode                 :PROC
EXTRN SetBkColor                :PROC
EXTRN SetTextColor              :PROC
EXTRN InvalidateRect            :PROC
EXTRN GetKeyState               :PROC
EXTRN RegisterWindowMessageW    :PROC

; ── Sibling modules ───────────────────────────────────────────────────────────
EXTRN _ReadDarkMode             :PROC   ; theme.asm
EXTRN ApplyDarkMode             :PROC   ; theme.asm
EXTRN _ApplyThemeColors         :PROC   ; theme.asm
EXTRN _OnCreate                 :PROC   ; layout.asm
EXTRN _OnDropFiles              :PROC   ; drop.asm
EXTRN RefreshLists              :PROC   ; listview.asm
EXTRN UpdateStatusBar           :PROC   ; handlers.asm
EXTRN _OnCommand                :PROC   ; handlers.asm
EXTRN _OnNotify                 :PROC   ; handlers.asm
EXTRN SendMessageW              :PROC
EXTRN _TrayAdd                  :PROC   ; tray.asm
EXTRN _TrayRemove               :PROC   ; tray.asm
EXTRN _OnTrayMsg                :PROC   ; tray.asm
EXTRN _LoadPadlockIcon          :PROC   ; tray.asm

; ==============================================================================
; CONSTANT STRINGS  (owned by this module)
; ==============================================================================
.const

str_wndclass        dw 'V','G','M','a','i','n','W','n','d',0
str_title           dw 'V','a','u','l','t','G','u','a','r','d',0
str_taskbarcreated  dw 'T','a','s','k','b','a','r','C','r','e','a','t','e','d',0

; ==============================================================================
; MUTABLE DATA
; ==============================================================================
.data
    align 4
PUBLIC g_wmTaskbarCreated
    g_wmTaskbarCreated  dd 0    ; message ID from RegisterWindowMessageW("TaskbarCreated")

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; MainWndProc  rcx=hwnd  rdx=msg  r8=wParam  r9=lParam  →  rax=result
;
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 38h (+56)→0 ✓
; ==============================================================================
PUBLIC MainWndProc
MainWndProc proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 38h

    mov     rbx, rcx                        ; hwnd → rbx
    mov     rsi, rdx                        ; msg  → rsi
    mov     rdi, r8                         ; wParam → rdi
    mov     r12, r9                         ; lParam → r12

    cmp     esi, WM_CREATE
    jne     @wnd_not_create
    mov     rcx, rbx                        ; hwnd
    call    _OnCreate                       ; build all child controls

    ; Set golden padlock icon AFTER controls created - avoids activation context
    ; contamination from LoadLibraryExW that would cause old-style Win32 controls.
    mov     edx, 32
    mov     ecx, 32
    call    _LoadPadlockIcon                ; hIcon32 -> rax
    test    rax, rax
    jz      @wnd_create_icon_done
    mov     r12, rax                        ; save hIcon32
    mov     r9,  r12
    mov     r8d, 1                          ; ICON_BIG = 1
    mov     edx, 80h                        ; WM_SETICON
    mov     rcx, rbx
    call    SendMessageW

    mov     edx, 16
    mov     ecx, 16
    call    _LoadPadlockIcon                ; hIcon16 -> rax
    test    rax, rax
    jz      @wnd_create_icon_done
    mov     r9,  rax
    mov     r8d, 0                          ; ICON_SMALL = 0
    mov     edx, 80h                        ; WM_SETICON
    mov     rcx, rbx
    call    SendMessageW

@wnd_create_icon_done:
    xor     eax, eax                        ; return 0 = accept creation
    jmp     @wnd_ret

@wnd_not_create:
    cmp     esi, WM_DESTROY
    jne     @wnd_not_destroy

    mov     rcx, rbx
    call    _TrayRemove                     ; remove tray icon if visible

    mov     edx, TIMER_STATUS_ID
    mov     rcx, rbx
    call    KillTimer                       ; stop periodic refresh

    mov     rcx, g_hFontMain
    call    DeleteObject                    ; free main font GDI object
    mov     rcx, g_hFontSmall
    call    DeleteObject                    ; free small font GDI object
    mov     rcx, g_hBrushBg
    call    DeleteObject                    ; free background brush

    xor     ecx, ecx
    call    PostQuitMessage                 ; nExitCode = 0 → breaks msg loop
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_destroy:
    cmp     esi, WM_CLOSE
    jne     @wnd_not_close
    mov     rcx, rbx
    call    DestroyWindow                   ; triggers WM_DESTROY chain
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_close:
    cmp     esi, WM_SIZE
    jne     @wnd_not_size
    cmp     edi, SIZE_MINIMIZED             ; wParam = 1 when minimized
    jne     @wnd_not_size
    mov     ecx, VK_SHIFT
    call    GetKeyState
    test    ax, 8000h                       ; high bit = key currently pressed
    jz      @wnd_not_size
    mov     rcx, rbx
    call    _TrayAdd                        ; Shift+Minimize → hide to tray
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_size:
    cmp     esi, WM_TRAY
    jne     @wnd_not_tray
    mov     rdx, r12                        ; lParam = mouse event
    mov     rcx, rbx
    call    _OnTrayMsg
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_tray:
    cmp     esi, WM_DROPFILES
    jne     @wnd_not_dropfiles
    mov     rdx, rbx                        ; hMainWnd (for drop target detection)
    mov     rcx, rdi                        ; wParam = HDROP handle
    call    _OnDropFiles                    ; resolves .lnk, routes by drop target
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_dropfiles:
    cmp     esi, WM_NOTIFY
    jne     @wnd_not_notify
    mov     rdx, r12                        ; lParam = NMHDR*
    mov     rcx, rbx
    call    _OnNotify                       ; handles LV column checkbox clicks
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_notify:
    cmp     esi, WM_COMMAND
    jne     @wnd_not_command
    mov     rdx, rdi                        ; wParam (low word = control ID)
    mov     rcx, rbx
    call    _OnCommand                      ; toggle / add / remove path / trusted
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_command:
    cmp     esi, WM_TIMER
    jne     @wnd_not_timer
    cmp     edi, TIMER_STATUS_ID            ; ignore any other timer id
    jne     @wnd_not_timer
    call    UpdateStatusBar                 ; poll IOCTL → update title / labels
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_timer:
    ; TaskbarCreated: Explorer restarted → re-add tray icon if we were in tray mode
    mov     eax, g_wmTaskbarCreated
    test    eax, eax
    jz      @wnd_not_taskbar
    cmp     esi, eax
    jne     @wnd_not_taskbar
    cmp     g_startMinimized, 0
    je      @wnd_not_taskbar
    mov     rcx, rbx
    call    _TrayAdd
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_taskbar:
    cmp     esi, WM_SETTINGCHANGE
    jne     @wnd_not_setting
    call    _ReadDarkMode                   ; re-read AppsUseLightTheme registry val
    mov     rcx, rbx
    call    ApplyDarkMode                   ; DWM Mica + dark title bar
    call    _ApplyThemeColors               ; brush + SetWindowTheme + LV colors
    mov     r8d, 1                          ; bErase = TRUE
    xor     edx, edx                        ; lpRect = NULL (entire client)
    mov     rcx, rbx
    call    InvalidateRect                  ; force WM_PAINT / WM_ERASEBKGND
    xor     eax, eax
    jmp     @wnd_ret

@wnd_not_setting:
    cmp     esi, WM_ERASEBKGND
    jne     @wnd_not_erase
    lea     rdx, [rsp+20h]                  ; &RECT (stack local)
    mov     rcx, rbx
    call    GetClientRect                   ; fill RECT with client dimensions

    mov     r8, g_hBrushBg                  ; our solid background brush
    lea     rdx, [rsp+20h]                  ; lprc
    mov     rcx, rdi                        ; wParam = HDC
    call    FillRect                        ; paint client area with theme bg

    mov     eax, 1                          ; return 1 = background was erased
    jmp     @wnd_ret

@wnd_not_erase:
    cmp     esi, WM_CTLCOLORSTATIC
    jne     @wnd_def

    cmp     g_isDarkMode, 0                 ; skip dark paint in light mode
    je      @wnd_def

    mov     edx, OPAQUE_VAL
    mov     rcx, rdi                        ; wParam = HDC
    call    SetBkMode                       ; opaque so bg color is used
    mov     edx, COLORREF_DARK_BG
    mov     rcx, rdi
    call    SetBkColor                      ; static bg = dark panel color
    mov     edx, COLORREF_DARK_TEXT
    mov     rcx, rdi
    call    SetTextColor                    ; static text = light foreground
    mov     rax, g_hBrushBg                 ; return brush to paint control bg
    jmp     @wnd_ret

@wnd_def:
    mov     r9, r12
    mov     r8, rdi
    mov     rdx, rsi
    mov     rcx, rbx
    call    DefWindowProcW

@wnd_ret:
    add     rsp, 38h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MainWndProc endp

; ==============================================================================
; CreateMainWindow  →  rax = hwnd or NULL
;
; Registers class, creates a fixed modern Mica window.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 78h (+120)→0 ✓
; WNDCLASSEXW at [rsp+20h] (80 bytes)
; ==============================================================================
PUBLIC CreateMainWindow
CreateMainWindow proc
    push    rbx
    push    rsi
    sub     rsp, 78h

    ; Register "TaskbarCreated" message so WndProc can re-add tray icon
    ; if Explorer restarts (e.g. crash, logon race condition at startup).
    lea     rcx, str_taskbarcreated
    call    RegisterWindowMessageW
    mov     g_wmTaskbarCreated, eax

    ; Zero WNDCLASSEXW at [rsp+20h]
    lea     r10, [rsp+20h]                  ; struct base on stack
    xor     eax, eax
    mov     ecx, WNDCLASSEXW_SIZE / 8       ; zero in 8-byte chunks
@cmw_zero:
    mov     qword ptr [r10], rax
    add     r10, 8
    dec     ecx
    jnz     @cmw_zero

    lea     r10, [rsp+20h]
    mov     dword ptr [r10 + 0],  WNDCLASSEXW_SIZE  ; cbSize
    mov     dword ptr [r10 + 4],  (CS_HREDRAW + CS_VREDRAW)  ; style: repaint on resize
    lea     rax, MainWndProc
    mov     qword ptr [r10 + 8],  rax              ; lpfnWndProc
    mov     rax, g_hInstance
    mov     qword ptr [r10 + 24], rax              ; hInstance
    mov     edx, IDI_ICON1                          ; try resource icon first
    mov     rcx, g_hInstance
    call    LoadIconW
    test    rax, rax
    jnz     @icon_ok
    mov     edx, 32516                              ; IDI_APPLICATION fallback
    xor     ecx, ecx
    call    LoadIconW
@icon_ok:
    lea     r10, [rsp+20h]
    mov     qword ptr [r10 + 32], rax              ; hIcon (large)
    mov     qword ptr [r10 + 72], rax              ; hIconSm (small taskbar)
    mov     edx, IDC_ARROW_ATOM                     ; standard arrow cursor
    xor     ecx, ecx
    call    LoadCursorW
    lea     r10, [rsp+20h]
    mov     qword ptr [r10 + 40], rax              ; hCursor
    lea     rax, str_wndclass
    mov     qword ptr [r10 + 64], rax              ; lpszClassName

    lea     rcx, [rsp+20h]
    call    RegisterClassExW
    test    ax, ax
    jz      @cmw_fail

    mov     rax, g_hInstance
    mov     qword ptr [rsp+58h], 0              ; lpParam = NULL
    mov     qword ptr [rsp+50h], rax            ; hInstance
    mov     qword ptr [rsp+48h], 0              ; hMenu = NULL
    mov     qword ptr [rsp+40h], 0              ; hWndParent = NULL (top-level)
    mov     dword ptr [rsp+38h], 472            ; nHeight (increased for author label)
    mov     dword ptr [rsp+30h], 680            ; nWidth
    mov     dword ptr [rsp+28h], 080000000h     ; Y = CW_USEDEFAULT
    mov     dword ptr [rsp+20h], 080000000h     ; X = CW_USEDEFAULT
    mov     r9d, (STY_MAINWIN + WS_CLIPCHILDREN)
    cmp     g_startMinimized, 0
    je      @cmw_style_ok
    and     r9d, NOT WS_VISIBLE                 ; /tray: create hidden, no flash
@cmw_style_ok:
    lea     r8, str_title                       ; lpWindowName
    lea     rdx, str_wndclass                   ; lpClassName
    xor     ecx, ecx                            ; dwExStyle = 0
    call    CreateWindowExW
    test    rax, rax
    jz      @cmw_fail

    mov     rbx, rax

    cmp     g_startMinimized, 0
    jne     @cmw_tray           ; /tray: _TrayAdd in mode_gui will handle show

    mov     edx, SW_SHOWNORMAL
    mov     rcx, rbx
    call    ShowWindow

    mov     rcx, rbx
    call    UpdateWindow

@cmw_tray:
    mov     rax, rbx
    jmp     @cmw_ret

@cmw_fail:
    xor     eax, eax
@cmw_ret:
    add     rsp, 78h
    pop     rsi
    pop     rbx
    ret
CreateMainWindow endp

end
