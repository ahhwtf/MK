; ==============================================================================
; Vault Guard - String Utilities
;
; Author: Marek Wesołowski (wesmar)
; Functions:
;   wcscpy_p(dst, src)          — wide strcpy, returns dst
;   wcscat_p(dst, src)          — wide strcat, returns dst
;   wcscmp_ci(a, b)             — wide strcmp case-insensitive, 0=equal/nonzero=diff
;   wcs_ascii_lower_inplace(s)  — lowercase ASCII A-Z in a wide string
;   wcslen_p(s)                 — wide strlen, returns char count (not bytes)
;   IntToDecW(val, buf)         — DWORD → wide decimal string, returns ptr past last char
;   IntToHexW(val, buf)         — DWORD → 8-char wide hex string, returns ptr past last char
;   WideWriteConsole(handle, s) — write wide string to console or ASCII pipe
;   WideWriteLn(s)              — write wide string + CRLF to stdout
; ==============================================================================

option casemap:none

include consts.inc

EXTRN WriteFile             :PROC
EXTRN WriteConsoleW         :PROC
EXTRN GetStdHandle          :PROC
EXTRN CharLowerW            :PROC
EXTRN WriteConsoleInputW    :PROC

.data?
    wcc_written dd ?    ; scratch for WriteFile lpNumberOfBytesWritten
    ansi_out_buf db 4096 dup(?)

.code

; ==============================================================================
; wcscpy_p  rcx=dst  rdx=src  → rax=dst
; Stack: entry rsp%16=8; sub 28h → rsp%16=0 ✓
; ==============================================================================
PUBLIC wcscpy_p
wcscpy_p proc
    sub     rsp, 28h
    mov     rax, rcx        ; save dst
@wcp_loop:
    mov     r10w, word ptr [rdx]
    mov     word ptr [rcx], r10w
    test    r10w, r10w
    jz      @wcp_done
    add     rcx, 2
    add     rdx, 2
    jmp     @wcp_loop
@wcp_done:
    add     rsp, 28h
    ret
wcscpy_p endp

; ==============================================================================
; wcscat_p  rcx=dst  rdx=src  → rax=dst
; Stack: entry rsp%16=8; sub 28h → rsp%16=0 ✓
; ==============================================================================
PUBLIC wcscat_p
wcscat_p proc
    sub     rsp, 28h
    mov     rax, rcx
@wccat_find_end:
    cmp     word ptr [rcx], 0
    je      @wccat_copy
    add     rcx, 2
    jmp     @wccat_find_end
@wccat_copy:
    mov     r10w, word ptr [rdx]
    mov     word ptr [rcx], r10w
    test    r10w, r10w
    jz      @wccat_done
    add     rcx, 2
    add     rdx, 2
    jmp     @wccat_copy
@wccat_done:
    add     rsp, 28h
    ret
wcscat_p endp

; ==============================================================================
; wcslen_p  rcx=str  → rax=char count (not bytes)
; Stack: entry rsp%16=8; sub 28h → rsp%16=0 ✓
; ==============================================================================
PUBLIC wcslen_p
wcslen_p proc
    sub     rsp, 28h
    xor     rax, rax
@wlen_loop:
    cmp     word ptr [rcx + rax*2], 0
    je      @wlen_done
    inc     rax
    jmp     @wlen_loop
@wlen_done:
    add     rsp, 28h
    ret
wcslen_p endp

; ==============================================================================
; wcs_ascii_lower_inplace  rcx=str  → rax=str
; Lowercases ASCII A-Z only. Good for Win32 process image names used by driver.
; Stack: entry rsp%16=8; sub 28h → rsp%16=0 ✓
; ==============================================================================
PUBLIC wcs_ascii_lower_inplace
wcs_ascii_lower_inplace proc
    sub     rsp, 28h
    mov     rax, rcx
@wali_loop:
    movzx   edx, word ptr [rcx]
    test    dx, dx
    jz      @wali_done
    cmp     edx, 'A'
    jb      @wali_next
    cmp     edx, 'Z'
    ja      @wali_next
    add     edx, 20h
    mov     word ptr [rcx], dx
@wali_next:
    add     rcx, 2
    jmp     @wali_loop
@wali_done:
    add     rsp, 28h
    ret
wcs_ascii_lower_inplace endp

; ==============================================================================
; wcscmp_ci  rcx=a  rdx=b  -> rax=0 equal, nonzero diff
; ASCII case-insensitive wide compare for switches/modes.
; Stack: entry rsp%16=8; push rbx,rsi,rdi -> 8; sub 20h -> rsp%16=0
; ==============================================================================
PUBLIC wcscmp_ci
wcscmp_ci proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    mov     rsi, rcx        ; a
    mov     rdi, rdx        ; b

@wcci_loop:
    movzx   eax, word ptr [rsi]
    movzx   ebx, word ptr [rdi]

    cmp     eax, 'A'
    jb      @wcci_a_done
    cmp     eax, 'Z'
    ja      @wcci_a_done
    add     eax, 20h
@wcci_a_done:
    cmp     ebx, 'A'
    jb      @wcci_b_done
    cmp     ebx, 'Z'
    ja      @wcci_b_done
    add     ebx, 20h
@wcci_b_done:

    cmp     ax, bx
    jne     @wcci_diff

    test    ax, ax
    jz      @wcci_equal

    add     rsi, 2
    add     rdi, 2
    jmp     @wcci_loop

@wcci_equal:
    xor     eax, eax
    jmp     @wcci_ret

@wcci_diff:
    mov     eax, 1

@wcci_ret:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
wcscmp_ci endp

; ==============================================================================
; IntToDecW  rcx=val(DWORD)  rdx=buf(WCHAR*)  → rax=ptr past null terminator
;
; Converts unsigned DWORD to wide decimal string. buf must be ≥ 12 WCHARs.
; Stack: entry rsp%16=8; push rbx,rsi → 8; sub 20h → rsp%16=0 ✓
; ==============================================================================
PUBLIC IntToDecW
IntToDecW proc
    push    rbx
    push    rsi
    sub     rsp, 20h

    mov     rbx, rdx        ; buf start
    mov     rsi, rdx        ; write ptr

    ; special case: 0
    test    ecx, ecx
    jnz     @itd_nonzero
    mov     word ptr [rsi], '0'
    add     rsi, 2
    mov     word ptr [rsi], 0
    lea     rax, [rsi+2]
    jmp     @itd_ret

@itd_nonzero:
    ; Write digits in reverse into buf
    mov     eax, ecx
@itd_loop:
    xor     edx, edx
    mov     r10d, 10
    div     r10d            ; eax=quot, edx=rem
    add     edx, '0'
    mov     word ptr [rsi], dx
    add     rsi, 2
    test    eax, eax
    jnz     @itd_loop

    ; null terminate
    mov     word ptr [rsi], 0
    mov     r11, rsi        ; save end ptr

    ; reverse rbx..rsi-2
    lea     rsi, [rsi-2]    ; point to last digit
@itd_rev:
    cmp     rbx, rsi
    jge     @itd_rev_done
    mov     ax, word ptr [rbx]
    mov     r10w, word ptr [rsi]
    mov     word ptr [rbx], r10w
    mov     word ptr [rsi], ax
    add     rbx, 2
    sub     rsi, 2
    jmp     @itd_rev
@itd_rev_done:
    lea     rax, [r11+2]    ; ptr past null

@itd_ret:
    add     rsp, 20h
    pop     rsi
    pop     rbx
    ret
IntToDecW endp

; ==============================================================================
; IntToHexW  rcx=val(DWORD)  rdx=buf(WCHAR*)  → rax=ptr past null
; Writes exactly 8 wide hex digits, no prefix.
; Stack: entry rsp%16=8; sub 28h → rsp%16=0 ✓
; ==============================================================================
PUBLIC IntToHexW
IntToHexW proc
    sub     rsp, 28h
    mov     rax, rcx        ; value
    lea     r10, hex_digits
    mov     r11, rdx        ; buf
    mov     ecx, 28         ; start shift (7*4)
@ihex_loop:
    mov     rdx, rax
    shr     rdx, cl
    and     rdx, 0Fh
    movzx   edx, byte ptr [r10 + rdx]
    mov     word ptr [r11], dx
    add     r11, 2
    sub     ecx, 4
    jns     @ihex_loop
    mov     word ptr [r11], 0
    lea     rax, [r11+2]
    add     rsp, 28h
    ret
IntToHexW endp

; ==============================================================================
; WideWriteConsole  rcx=handle  rdx=wide_str  -> void
; Stack: entry rsp%16=8; push rbx,rsi,rdi -> 0; sub 30h -> rsp%16=0
; ==============================================================================
PUBLIC WideWriteConsole
WideWriteConsole proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 30h

    mov     rbx, rcx        ; handle
    mov     rsi, rdx        ; str

    ; compute length
    mov     rcx, rsi
    call    wcslen_p
    test    rax, rax
    jz      @wwc_done
    mov     edi, eax

    mov     qword ptr [rsp+20h], 0  ; lpOverlapped = NULL
    lea     r9, wcc_written         ; lpNumberOfBytesWritten
    mov     r8d, eax                ; nNumberOfCharsToWrite
    mov     rdx, rsi                ; lpBuffer
    mov     rcx, rbx                ; hFile
    call    WriteConsoleW
    test    eax, eax
    jnz     @wwc_done

    ; Redirected output is not a console. Help/status text is ASCII, so emit
    ; low bytes as a readable fallback instead of UTF-16 with embedded NULs.
    mov     ecx, edi
    cmp     ecx, 4095
    jbe     @wwc_count_ok
    mov     ecx, 4095
@wwc_count_ok:
    mov     edi, ecx
    lea     r10, ansi_out_buf
    mov     r11, rsi

@wwc_ascii_loop:
    test    ecx, ecx
    jz      @wwc_write_ascii
    mov     ax, word ptr [r11]
    cmp     ax, 80h
    jb      @wwc_ascii_store
    mov     al, '?'
@wwc_ascii_store:
    mov     byte ptr [r10], al
    add     r11, 2
    inc     r10
    dec     ecx
    jmp     @wwc_ascii_loop

@wwc_write_ascii:
    mov     qword ptr [rsp+20h], 0
    lea     r9, wcc_written
    mov     r8d, edi
    lea     rdx, ansi_out_buf
    mov     rcx, rbx
    call    WriteFile

@wwc_done:
    add     rsp, 30h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
WideWriteConsole endp

; ==============================================================================
; WideWriteLn  rcx=wide_str  -> write str + CRLF to stdout
; Stack: entry rsp%16=8; push rbx,rsi -> 8; sub 28h -> rsp%16=0
; ==============================================================================
PUBLIC WideWriteLn
WideWriteLn proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rsi, rcx

    mov     ecx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     rbx, rax

    mov     rdx, rsi
    mov     rcx, rbx
    call    WideWriteConsole

    lea     rdx, str_crlf
    mov     rcx, rbx
    call    WideWriteConsole

    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
WideWriteLn endp

; ==============================================================================
; ConsoleSendEnter  →  void
; Injects a fake Enter keypress into the console input buffer so that the
; parent CMD prompt reappears after AttachConsole + ExitProcess without the
; user having to press Enter manually.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 38h (+56)→0 ✓
; INPUT_RECORD layout at [rsp+20h]:
;   +0  WORD EventType = KEY_EVENT (1)
;   +2  WORD padding
;   +4  DWORD bKeyDown = 1
;   +8  WORD wRepeatCount = 1
;   +A  WORD wVirtualKeyCode = VK_RETURN
;   +C  WORD wVirtualScanCode = ENTER_SCAN
;   +E  WORD uChar.UnicodeChar = '\r'
;  +10  DWORD dwControlKeyState = 0
; Total: 20 bytes → [rsp+20h..rsp+33h]
; written DWORD at [rsp+34h]
; ==============================================================================
PUBLIC ConsoleSendEnter
ConsoleSendEnter proc
    push    rbx
    push    rsi
    sub     rsp, 38h

    mov     ecx, STD_INPUT_HANDLE
    call    GetStdHandle
    test    rax, rax
    jz      @cse_done
    cmp     rax, INVALID_HANDLE_VALUE
    je      @cse_done
    mov     rbx, rax                        ; hConIn

    xor     eax, eax
    mov     qword ptr [rsp+20h], rax
    mov     qword ptr [rsp+28h], rax
    mov     dword ptr [rsp+30h], eax        ; dwControlKeyState
    mov     dword ptr [rsp+34h], eax        ; written

    mov     word ptr [rsp+20h], KEY_EVENT_ID
    mov     dword ptr [rsp+24h], 1          ; bKeyDown = TRUE
    mov     word ptr [rsp+28h], 1           ; wRepeatCount
    mov     word ptr [rsp+2Ah], VK_RETURN   ; wVirtualKeyCode
    mov     word ptr [rsp+2Ch], ENTER_SCAN  ; wVirtualScanCode
    mov     word ptr [rsp+2Eh], VK_RETURN   ; uChar.UnicodeChar

    lea     r9, [rsp+34h]                   ; lpNumberOfEventsWritten
    mov     r8d, 1                          ; nLength
    lea     rdx, [rsp+20h]                  ; lpBuffer (INPUT_RECORD)
    mov     rcx, rbx
    call    WriteConsoleInputW

@cse_done:
    add     rsp, 38h
    pop     rsi
    pop     rbx
    ret
ConsoleSendEnter endp

; ==============================================================================
; CONST DATA
; ==============================================================================
.const

hex_digits  db '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
str_crlf    dw 0Dh, 0Ah, 0

end
