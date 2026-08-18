; ==============================================================================
; Vault Guard - Global Data and GUI Entry
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Global data storage. VgGuiMain: creates window, runs message loop.
;          Called from kvc.cpp when user issues 'kvc vg --gui'.
; ==============================================================================

option casemap:none

include consts.inc

EXTRN GetModuleHandleW      :PROC
EXTRN GetMessageW           :PROC
EXTRN TranslateMessage      :PROC
EXTRN DispatchMessageW      :PROC
EXTRN AttachConsole         :PROC
EXTRN GetStdHandle          :PROC
EXTRN GetFileType           :PROC

EXTRN InitCommonControlsEx  :PROC
EXTRN CreateMainWindow      :PROC
EXTRN _TrayAdd              :PROC

; ==============================================================================
; INITIALIZED DATA
; ==============================================================================
.data
    align 8

PUBLIC g_hInstance, g_hwndMain
PUBLIC g_hwndLvPaths, g_hwndLvTrusted
PUBLIC g_hwndBtnToggle
PUBLIC g_hwndDrvStatus, g_hwndProtStatus
PUBLIC g_hDevice
PUBLIC g_hFontMain, g_hFontSmall
PUBLIC g_hBrushBg
PUBLIC g_isDarkMode
PUBLIC g_driverInstalled, g_driverRunning, g_protActive
PUBLIC g_cliMode
PUBLIC g_prevDrvOk, g_prevProtActive
PUBLIC g_startMinimized

g_hInstance         dq 0
g_hwndMain          dq 0
g_hwndLvPaths       dq 0
g_hwndLvTrusted     dq 0
g_hwndBtnToggle     dq 0
g_hwndDrvStatus     dq 0
g_hwndProtStatus    dq 0
g_hDevice           dq 0
g_hFontMain         dq 0
g_hFontSmall        dq 0
g_hBrushBg          dq 0
g_isDarkMode        dd 1        ; default dark
                    dd 0
g_driverInstalled   dd 0
                    dd 0
g_driverRunning     dd 0
                    dd 0
g_protActive        dd 0
                    dd 0
g_cliMode           dd 0
                    dd 0
g_startMinimized    dd 0
                    dd 0
; State cache for UpdateStatusBar — prevents flicker on unchanged labels.
; 0xFF = sentinel "never set", forces update on first call.
g_prevDrvOk         db 0FFh
                    db 0, 0, 0
g_prevProtActive    db 0FFh
                    db 0, 0, 0

; ==============================================================================
; UNINITIALIZED DATA
; ==============================================================================
.data?

PUBLIC g_ioBuf, g_pathBuf, g_tempBuf, g_statusBuf

g_ioBuf     db VG_IOCTL_BUF_SIZE dup(?)    ; 64 KB IOCTL enum buffer
g_pathBuf   dw 520 dup(?)                  ; path edit scratch (MAX_PATH+1)
g_tempBuf   dw 520 dup(?)                  ; general scratch
g_statusBuf dw 520 dup(?)                  ; status text scratch

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; VgGuiMain - GUI Entry Point (called from kvc.cpp)
;
; Gets hInstance, creates window, runs message loop until WM_QUIT.
; Returns to caller when window is closed (does NOT call ExitProcess).
;
; Stack: entry rsp%16=8 (called via CALL, return address pushed).
;        sub 58h (88) → rsp%16=0 ✓
; MSG at [rsp+20h] (48 bytes)
; ==============================================================================
PUBLIC VgGuiMain
VgGuiMain proc
    sub     rsp, 58h

    ; Attach console if stdin is a real console (for any diagnostic output)
    mov     ecx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    test    rax, rax
    jz      @vg_attach
    cmp     rax, INVALID_HANDLE_VALUE
    je      @vg_attach
    mov     rcx, rax
    call    GetFileType
    cmp     eax, FILE_TYPE_CHAR
    jne     @vg_no_attach
@vg_attach:
    mov     ecx, ATTACH_PARENT_PROCESS
    call    AttachConsole
@vg_no_attach:

    xor     ecx, ecx                ; lpModuleName = NULL -> this EXE
    call    GetModuleHandleW
    mov     g_hInstance, rax        ; store hInstance for class registration

    ; InitCommonControlsEx - loads ComCtl32 v6, registers ListView/TreeView/etc.
    mov     dword ptr [rsp+50h], 8      ; INITCOMMONCONTROLSEX.dwSize = 8
    mov     dword ptr [rsp+54h], 4100h  ; dwICC = ICC_STANDARD_CLASSES|ICC_LISTVIEW_CLASSES
    lea     rcx, [rsp+50h]
    call    InitCommonControlsEx

    call    CreateMainWindow        ; register class, create window, show
    test    rax, rax
    jz      @vg_exit                ; NULL = creation failed

    cmp     g_startMinimized, 0
    je      @vg_loop
    mov     rcx, rax                ; hwnd
    call    _TrayAdd                ; hide to tray immediately

@vg_loop:
    lea     rcx, [rsp+20h]          ; lpMsg
    xor     edx, edx                ; hWnd = NULL (all windows)
    xor     r8d, r8d
    xor     r9d, r9d
    call    GetMessageW
    test    eax, eax
    jz      @vg_exit                ; WM_QUIT
    js      @vg_exit                ; error

    lea     rcx, [rsp+20h]
    call    TranslateMessage

    lea     rcx, [rsp+20h]
    call    DispatchMessageW

    jmp     @vg_loop

@vg_exit:
    add     rsp, 58h
    ret                             ; return to kvc.cpp, do not ExitProcess
VgGuiMain endp

end
