; ==============================================================================
; Vault Guard - System Tray
;
; Author: Marek Wesolowski (wesmar)
; Purpose: Tray icon management. Shift+Minimize hides to tray.
;          Double-click or menu Restore brings window back.
;
; Exported:
;   _TrayAdd(hwnd)    - load icon, add to tray, SW_HIDE window
;   _TrayRemove(hwnd) - NIM_DELETE, SW_RESTORE window
;   _OnTrayMsg(rcx=hwnd, rdx=lParam) - dispatch tray mouse events
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

; ---- Win32 ------------------------------------------------------------------
EXTRN Shell_NotifyIconW     :PROC
EXTRN LoadIconW             :PROC
EXTRN LoadLibraryExW        :PROC
EXTRN FreeLibrary           :PROC
EXTRN LoadImageW            :PROC
EXTRN ShowWindow            :PROC
EXTRN CreatePopupMenu       :PROC
EXTRN AppendMenuW           :PROC
EXTRN TrackPopupMenu        :PROC
EXTRN DestroyMenu           :PROC
EXTRN SetForegroundWindow   :PROC
EXTRN GetCursorPos          :PROC
EXTRN DestroyWindow         :PROC
EXTRN PostMessageW          :PROC

; ==============================================================================
; DATA
; ==============================================================================
.data
align 8

g_trayVisible   dd 0
                dd 0                    ; pad to 8

; NOTIFYICONDATAW v1 (168 bytes on x64):
;   [+0]   DWORD  cbSize
;   [+4]   DWORD  (pad)
;   [+8]   QWORD  hWnd
;   [+16]  DWORD  uID
;   [+20]  DWORD  uFlags
;   [+24]  DWORD  uCallbackMessage
;   [+28]  DWORD  (pad)
;   [+32]  QWORD  hIcon
;   [+40]  WCHAR[64] szTip
tray_nid        dd NID_CBSIZE           ; cbSize = 168
                dd 0                    ; pad
                dq 0                    ; hWnd     (set at runtime)
                dd 1                    ; uID
                dd (NIF_MESSAGE + NIF_ICON + NIF_TIP)
                dd WM_TRAY              ; uCallbackMessage
                dd 0                    ; pad
                dq 0                    ; hIcon    (set at runtime)
                dw 'V','a','u','l','t','G','u','a','r','d',0
                db 106 dup (0)          ; szTip remainder (128-22 = 106 bytes)

str_tray_restore dw 'R','e','s','t','o','r','e',0
str_tray_exit    dw 'E','x','i','t',0

; C:\Windows\SystemResources\imageres.dll.mun  (direct load, PowerShell-confirmed ResourceID 1304)
str_imageres dw 'C',':','\','W','i','n','d','o','w','s','\','S','y','s','t','e','m','R','e','s','o','u','r','c','e','s','\','i','m','a','g','e','r','e','s','.','d','l','l','.','m','u','n',0

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; _TrayAdd  rcx=hwnd  ->  void
;
; Loads tray icon: LoadLibraryExW on imageres.dll.mun (direct path, no MUI
; needed), then LoadImageW ResourceID 1304 (golden padlock, Win11).
; LR_DEFAULTCOLOR = standalone copy - survives FreeLibrary.
; Falls back to IDI_ICON1 then IDI_APPLICATION.
;
; Stack: entry rsp%16=8; push rbx (+8)->0; push rsi (+8)->8; push rdi (+8)->0; sub 30h (+48)->0
;   [rsp+00..1F] shadow space
;   [rsp+20h]    LoadImageW 5th arg (cy=16)
;   [rsp+28h]    LoadImageW 6th arg (fuLoad=0)
; ==============================================================================
PUBLIC _TrayAdd
_TrayAdd proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 30h

    mov     rbx, rcx                    ; rbx = hwnd

    ; LoadLibraryExW(mun_path, NULL, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE|LOAD_LIBRARY_AS_IMAGE_RESOURCE)
    ; ExtractIconExW bypassed: imageres.dll is a stub on Win11, MUI routing not
    ; applied at PE-parse level, returns 0. Direct .mun load is reliable.
    mov     r8d, 60h                    ; 0x40 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | 0x20 LOAD_LIBRARY_AS_IMAGE_RESOURCE
    xor     edx, edx                    ; hFile = NULL
    lea     rcx, str_imageres
    call    LoadLibraryExW
    mov     rsi, rax                    ; rsi = hMod
    test    rsi, rsi
    jz      @ta_fallback

    ; LoadImageW(hMod, 1304, IMAGE_ICON=1, cx=16, cy=16, LR_DEFAULTCOLOR=0)
    mov     dword ptr [rsp+28h], 0      ; fuLoad = LR_DEFAULTCOLOR
    mov     dword ptr [rsp+20h], 16     ; cyDesired = 16
    mov     r9d,  16                    ; cxDesired = 16
    mov     r8d,  1                     ; uType = IMAGE_ICON
    mov     edx,  1304                  ; MAKEINTRESOURCEW(1304)
    mov     rcx,  rsi                   ; hModule
    call    LoadImageW
    mov     rdi,  rax                   ; rdi = hIcon

    mov     rcx,  rsi
    call    FreeLibrary                 ; module unneeded after icon copy made

    test    rdi, rdi
    jnz     @ta_icon_ok

    ; --- Fallback: IDI_ICON1 from own resources ---
@ta_fallback:
    mov     edx, IDI_ICON1
    mov     rcx, g_hInstance
    call    LoadIconW
    mov     rdi, rax
    test    rdi, rdi
    jnz     @ta_icon_ok

    ; --- Last resort: system IDI_APPLICATION ---
    mov     edx, 32516
    xor     ecx, ecx
    call    LoadIconW
    mov     rdi, rax

@ta_icon_ok:
    lea     rcx, tray_nid
    mov     qword ptr [rcx + 8],  rbx   ; hWnd
    mov     qword ptr [rcx + 32], rdi   ; hIcon

    lea     rdx, tray_nid
    xor     ecx, ecx                    ; NIM_ADD = 0
    call    Shell_NotifyIconW

    mov     edx, SW_HIDE
    mov     rcx, rbx
    call    ShowWindow

    mov     g_trayVisible, 1

    add     rsp, 30h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_TrayAdd endp

; ==============================================================================
; _LoadPadlockIcon  rcx=cx  rdx=cy  ->  rax=hIcon or 0
;
; Loads ResourceID 1304 (golden padlock) from imageres.dll.mun at given size.
; LR_DEFAULTCOLOR: standalone copy, survives FreeLibrary, lives for process
; lifetime (no explicit DestroyIcon needed for window class / tray icons).
;
; Stack: entry rsp%16=8; push rbx (+8)->0; push rsi (+8)->8; push rdi (+8)->0; sub 30h (+48)->0
;   [rsp+20h]  LoadImageW 5th arg (cy)
;   [rsp+28h]  LoadImageW 6th arg (fuLoad=0)
; ==============================================================================
PUBLIC _LoadPadlockIcon
_LoadPadlockIcon proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 30h

    mov     ebx, ecx                    ; save cx
    mov     esi, edx                    ; save cy

    mov     r8d, 60h                    ; LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE|LOAD_LIBRARY_AS_IMAGE_RESOURCE
    xor     edx, edx                    ; hFile = NULL
    lea     rcx, str_imageres
    call    LoadLibraryExW
    mov     rdi, rax                    ; rdi = hMod
    test    rdi, rdi
    jz      @lpi_fail

    mov     dword ptr [rsp+28h], 0      ; fuLoad = LR_DEFAULTCOLOR
    mov     dword ptr [rsp+20h], esi    ; cyDesired
    mov     r9d,  ebx                   ; cxDesired
    mov     r8d,  1                     ; uType = IMAGE_ICON
    mov     edx,  1304                  ; MAKEINTRESOURCEW(1304)
    mov     rcx,  rdi
    call    LoadImageW
    mov     rsi,  rax                   ; rsi = hIcon

    mov     rcx,  rdi
    call    FreeLibrary                 ; module unneeded; icon copy is standalone

    mov     rax,  rsi
    jmp     @lpi_ret

@lpi_fail:
    xor     eax, eax
@lpi_ret:
    add     rsp, 30h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_LoadPadlockIcon endp

; ==============================================================================
; _TrayRemove  rcx=hwnd  ->  void
; No-op if tray icon not active.
; Stack: entry rsp%16=8; push rbx (+8)->0; sub 20h (+32)->0
; ==============================================================================
PUBLIC _TrayRemove
_TrayRemove proc
    push    rbx
    sub     rsp, 20h

    mov     rbx, rcx

    cmp     g_trayVisible, 0
    je      @trm_done

    lea     rdx, tray_nid
    mov     ecx, NIM_DELETE
    call    Shell_NotifyIconW

    mov     g_trayVisible, 0

    mov     edx, SW_RESTORE
    mov     rcx, rbx
    call    ShowWindow

    ; Bring window to front
    mov     rcx, rbx
    call    SetForegroundWindow

@trm_done:
    add     rsp, 20h
    pop     rbx
    ret
_TrayRemove endp

; ==============================================================================
; _OnTrayMsg  rcx=hwnd  rdx=lParam (mouse event in low word)  ->  void
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)->0; sub 40h (+64)->0
;        [rsp+20h..2Fh] = TrackPopupMenu stack args (5th/6th/7th)
;        [rsp+38h..3Fh] = POINT scratch for GetCursorPos
; ==============================================================================
PUBLIC _OnTrayMsg
_OnTrayMsg proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 40h

    mov     rbx, rcx
    movzx   esi, dx                     ; low word of lParam = mouse message

    cmp     esi, WM_LBUTTONDBLCLK
    jne     @otm_rbtn
    mov     rcx, rbx
    call    _TrayRemove
    jmp     @otm_done

@otm_rbtn:
    cmp     esi, WM_RBUTTONUP
    jne     @otm_done

    call    CreatePopupMenu
    test    rax, rax
    jz      @otm_done
    mov     rdi, rax                    ; hMenu

    ; "Restore"
    lea     r9, str_tray_restore
    mov     r8d, IDM_TRAY_RESTORE
    xor     edx, edx                    ; MF_STRING = 0
    mov     rcx, rdi
    call    AppendMenuW

    ; separator
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, MF_SEPARATOR
    mov     rcx, rdi
    call    AppendMenuW

    ; "Exit"
    lea     r9, str_tray_exit
    mov     r8d, IDM_TRAY_EXIT
    xor     edx, edx
    mov     rcx, rdi
    call    AppendMenuW

    ; Required: SetForegroundWindow before TrackPopupMenu so menu closes on click-away
    mov     rcx, rbx
    call    SetForegroundWindow

    ; Get cursor position into scratch [rsp+38h]
    lea     rcx, [rsp+38h]
    call    GetCursorPos

    ; TrackPopupMenu(hMenu, TPM_RIGHTBUTTON|TPM_RETURNCMD, x, y, 0, hwnd, NULL)
    mov     qword ptr [rsp+30h], 0          ; prcRect = NULL (7th arg)
    mov     qword ptr [rsp+28h], rbx        ; hWnd    (6th arg)
    mov     dword ptr [rsp+20h], 0          ; nReserved = 0 (5th arg)
    mov     r9d,  dword ptr [rsp+3Ch]       ; y = POINT.y at [rsp+3Ch]
    mov     r8d,  dword ptr [rsp+38h]       ; x = POINT.x at [rsp+38h]
    mov     edx, (TPM_RIGHTBUTTON + TPM_RETURNCMD)
    mov     rcx, rdi
    call    TrackPopupMenu
    mov     esi, eax                        ; save selected ID

    mov     rcx, rdi
    call    DestroyMenu

    ; WM_NULL post — clears foreground state (required after SetForegroundWindow+TPM trick)
    xor     r9d, r9d
    xor     r8d, r8d
    xor     edx, edx                        ; WM_NULL = 0
    mov     rcx, rbx
    call    PostMessageW

    cmp     esi, IDM_TRAY_RESTORE
    jne     @otm_exit_check
    mov     rcx, rbx
    call    _TrayRemove
    jmp     @otm_done

@otm_exit_check:
    cmp     esi, IDM_TRAY_EXIT
    jne     @otm_done
    mov     rcx, rbx
    call    DestroyWindow

@otm_done:
    add     rsp, 40h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_OnTrayMsg endp

end
