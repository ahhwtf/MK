; ==============================================================================
; Vault Guard - Registry Config Persistence
;
; Author: Marek Wesołowski (wesmar)
; Registry root: HKCU\Software\kvc\lock
;   \Paths   value_name=path(WCHAR*), type=REG_DWORD, data=flags(DWORD)
;   \Trusted value_name=name(WCHAR*), type=REG_DWORD, data=1
;
; Exported:
;   ConfigLoad()                 — restore all entries from registry → driver
;   ConfigSavePath(path, flags)  — rcx=WCHAR*, edx=DWORD
;   ConfigRemovePath(path)       — rcx=WCHAR*
;   ConfigSaveTrusted(name)      — rcx=WCHAR*
;   ConfigRemoveTrusted(name)    — rcx=WCHAR*
; ==============================================================================

option casemap:none
include consts.inc

EXTRN RegCreateKeyExW   :PROC
EXTRN RegOpenKeyExW     :PROC
EXTRN RegSetValueExW    :PROC
EXTRN RegDeleteValueW   :PROC
EXTRN RegEnumValueW     :PROC
EXTRN RegCloseKey       :PROC
EXTRN EnsureDriverReady :PROC
EXTRN CloseDevice       :PROC
EXTRN IoctlAddPath      :PROC
EXTRN IoctlAddTrusted   :PROC
EXTRN wcs_ascii_lower_inplace :PROC

.data?
    cfg_hkey     dq ?           ; phkResult scratch
    cfg_disp     dd ?           ; lpdwDisposition scratch
    cfg_type     dd ?           ; value type scratch
    cfg_namelen  dd ?           ; lpcchValueName for RegEnumValueW
    cfg_datalen  dd ?           ; lpcbData for RegEnumValueW
    cfg_flags    dd ?           ; value data (flags DWORD)

    cfg_name_buf dw 520 dup(?)  ; value name / path buffer (MAX_PATH+1 WCHARs)

.const
    str_key_paths   dw 'S','o','f','t','w','a','r','e','\','k','v','c','\','l','o','c','k','\','P','a','t','h','s',0
    str_key_trusted dw 'S','o','f','t','w','a','r','e','\','k','v','c','\','l','o','c','k','\','T','r','u','s','t','e','d',0

.code

; ==============================================================================
; _CfgCreate  rcx=subkey(WCHAR*)  →  rax=HKEY or 0
; RegCreateKeyExW(HKCU, subkey, 0, NULL, 0, KEY_ALL_ACCESS, NULL,
;                 &cfg_hkey, &cfg_disp)
; Stack: entry rsp%16=8; push rbx (+8)→0; sub 50h (+80)→0 ✓
; RegCreateKeyExW 9 args: stack args at [rsp+20h]..[rsp+40h] (5 slots)
; ==============================================================================
_CfgCreate proc
    push    rbx
    sub     rsp, 50h

    mov     rbx, rcx                        ; save subkey ptr

    lea     rax, cfg_disp
    mov     qword ptr [rsp+40h], rax        ; lpdwDisposition
    lea     rax, cfg_hkey
    mov     qword ptr [rsp+38h], rax        ; phkResult
    mov     qword ptr [rsp+30h], 0          ; lpSecurityAttributes = NULL
    mov     dword ptr [rsp+28h], KEY_ALL_ACCESS
    mov     dword ptr [rsp+20h], REG_OPTION_NON_VOLATILE
    xor     r9d, r9d                        ; lpClass = NULL
    xor     r8d, r8d                        ; Reserved = 0
    mov     rdx, rbx                        ; lpSubKey
    mov     rcx, HKEY_CURRENT_USER
    call    RegCreateKeyExW
    test    eax, eax
    jnz     @cc_fail
    mov     rax, cfg_hkey
    jmp     @cc_ret
@cc_fail:
    xor     eax, eax
@cc_ret:
    add     rsp, 50h
    pop     rbx
    ret
_CfgCreate endp

; ==============================================================================
; _CfgOpen  rcx=subkey(WCHAR*)  →  rax=HKEY or 0 (0 if key does not exist)
; RegOpenKeyExW(HKCU, subkey, 0, KEY_READ, &cfg_hkey)
; Stack: entry rsp%16=8; push rbx (+8)→0; sub 30h (+48)→0 ✓
; RegOpenKeyExW 5 args: 1 stack arg at [rsp+20h]
; ==============================================================================
_CfgOpen proc
    push    rbx
    sub     rsp, 30h

    mov     rbx, rcx

    lea     rax, cfg_hkey
    mov     qword ptr [rsp+20h], rax        ; phkResult
    mov     r9d, KEY_READ
    xor     r8d, r8d                        ; ulOptions = 0
    mov     rdx, rbx
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @co_fail
    mov     rax, cfg_hkey
    jmp     @co_ret
@co_fail:
    xor     eax, eax
@co_ret:
    add     rsp, 30h
    pop     rbx
    ret
_CfgOpen endp

; ==============================================================================
; ConfigSavePath  rcx=path(WCHAR*)  edx=flags(DWORD)  →  void
; HKCU\Software\VG\Paths\<path> = flags (REG_DWORD)
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)→0; sub 50h (+80)→0 ✓
; RegSetValueExW 6 args: 2 stack args at [rsp+20h],[rsp+28h]
; ==============================================================================
PUBLIC ConfigSavePath
ConfigSavePath proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 50h

    mov     rbx, rcx                ; path
    mov     esi, edx                ; flags

    lea     rcx, str_key_paths
    call    _CfgCreate
    test    rax, rax
    jz      @csp_ret
    mov     rdi, rax                ; hKey

    ; cfg_flags ← esi  (lpData must point to stable memory through the call)
    lea     rax, cfg_flags
    mov     dword ptr [rax], esi

    lea     rax, cfg_flags
    mov     dword ptr [rsp+28h], 4          ; cbData = sizeof(DWORD)
    mov     qword ptr [rsp+20h], rax        ; lpData = &cfg_flags
    mov     r9d, REG_DWORD
    xor     r8d, r8d                        ; Reserved = 0
    mov     rdx, rbx                        ; lpValueName = path
    mov     rcx, rdi
    call    RegSetValueExW

    mov     rcx, rdi
    call    RegCloseKey

@csp_ret:
    add     rsp, 50h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ConfigSavePath endp

; ==============================================================================
; ConfigRemovePath  rcx=path(WCHAR*)  →  void
; Deletes HKCU\Software\VG\Paths\<path>.
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)→0; sub 50h (+80)→0 ✓
; ==============================================================================
PUBLIC ConfigRemovePath
ConfigRemovePath proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 50h

    mov     rbx, rcx

    lea     rcx, str_key_paths
    call    _CfgCreate
    test    rax, rax
    jz      @crp_ret
    mov     rdi, rax

    mov     rdx, rbx
    mov     rcx, rdi
    call    RegDeleteValueW

    mov     rcx, rdi
    call    RegCloseKey

@crp_ret:
    add     rsp, 50h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ConfigRemovePath endp

; ==============================================================================
; ConfigSaveTrusted  rcx=name(WCHAR*)  →  void
; HKCU\Software\VG\Trusted\<name> = 1 (REG_DWORD)
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)→0; sub 50h (+80)→0 ✓
; ==============================================================================
PUBLIC ConfigSaveTrusted
ConfigSaveTrusted proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 50h

    mov     rbx, rcx

    lea     rcx, str_key_trusted
    call    _CfgCreate
    test    rax, rax
    jz      @cst_ret
    mov     rdi, rax

    lea     rax, cfg_flags
    mov     dword ptr [rax], 1              ; value = 1 (Enabled)

    lea     rax, cfg_flags
    mov     dword ptr [rsp+28h], 4
    mov     qword ptr [rsp+20h], rax
    mov     r9d, REG_DWORD
    xor     r8d, r8d
    mov     rdx, rbx
    mov     rcx, rdi
    call    RegSetValueExW

    mov     rcx, rdi
    call    RegCloseKey

@cst_ret:
    add     rsp, 50h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ConfigSaveTrusted endp

; ==============================================================================
; ConfigRemoveTrusted  rcx=name(WCHAR*)  →  void
; Deletes HKCU\Software\VG\Trusted\<name>.
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)→0; sub 50h (+80)→0 ✓
; ==============================================================================
PUBLIC ConfigRemoveTrusted
ConfigRemoveTrusted proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 50h

    mov     rbx, rcx

    lea     rcx, str_key_trusted
    call    _CfgCreate
    test    rax, rax
    jz      @crt_ret
    mov     rdi, rax

    mov     rdx, rbx
    mov     rcx, rdi
    call    RegDeleteValueW

    mov     rcx, rdi
    call    RegCloseKey

@crt_ret:
    add     rsp, 50h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ConfigRemoveTrusted endp

; ==============================================================================
; ConfigLoad  →  void
; Enumerates both registry keys and pushes every entry to the driver.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 48h (+72)→0 ✓
; RegEnumValueW 8 args: 4 stack args at [rsp+20h]..[rsp+38h] (within 72 bytes ✓)
; Control flow:
;   open key → if fail jump past section
;   EnsureDriverReady → if fail jump to close-key label (no CloseDevice)
;   loop: RegEnumValueW → Ioctl* → inc index
;   @done: CloseDevice; falls through to @drv_fail: RegCloseKey
; ==============================================================================
PUBLIC ConfigLoad
ConfigLoad proc
    push    rbx
    push    rsi
    sub     rsp, 48h

    ; ── Paths ──────────────────────────────────────────────────────────────────
    lea     rcx, str_key_paths
    call    _CfgOpen
    test    rax, rax
    jz      @cl_do_trusted          ; key not present, skip to Trusted

    mov     rbx, rax                ; hKey (paths)

    call    EnsureDriverReady
    test    eax, eax
    jz      @cl_paths_drv_fail      ; driver not ready — close key only

    xor     esi, esi                ; dwIndex = 0

@cl_paths_loop:
    mov     cfg_namelen, 520        ; buffer capacity in WCHARs (reset each iter)
    mov     cfg_datalen, 4

    lea     rax, cfg_datalen
    mov     qword ptr [rsp+38h], rax        ; lpcbData
    lea     rax, cfg_flags
    mov     qword ptr [rsp+30h], rax        ; lpData = &cfg_flags
    lea     rax, cfg_type
    mov     qword ptr [rsp+28h], rax        ; lpType
    mov     qword ptr [rsp+20h], 0          ; lpReserved = NULL
    lea     r9, cfg_namelen                 ; lpcchValueName
    lea     r8, cfg_name_buf                ; lpValueName (output: path string)
    mov     edx, esi                        ; dwIndex
    mov     rcx, rbx
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @cl_paths_done
    test    eax, eax
    jnz     @cl_paths_next                  ; other error — skip entry

    mov     ecx, cfg_flags                  ; flags (value data from registry)
    and     ecx, 0Fh
    jz      @cl_paths_next                  ; zero = remembered but inactive
    lea     rdx, cfg_name_buf               ; path (value name from registry)
    call    IoctlAddPath

@cl_paths_next:
    inc     esi
    jmp     @cl_paths_loop

@cl_paths_done:
    call    CloseDevice
@cl_paths_drv_fail:
    mov     rcx, rbx
    call    RegCloseKey

    ; ── Trusted ────────────────────────────────────────────────────────────────
@cl_do_trusted:
    lea     rcx, str_key_trusted
    call    _CfgOpen
    test    rax, rax
    jz      @cl_done

    mov     rbx, rax

    call    EnsureDriverReady
    test    eax, eax
    jz      @cl_trusted_drv_fail

    xor     esi, esi

@cl_trusted_loop:
    mov     cfg_namelen, 520
    mov     cfg_datalen, 4

    lea     rax, cfg_datalen
    mov     qword ptr [rsp+38h], rax
    lea     rax, cfg_flags
    mov     qword ptr [rsp+30h], rax
    lea     rax, cfg_type
    mov     qword ptr [rsp+28h], rax
    mov     qword ptr [rsp+20h], 0
    lea     r9, cfg_namelen
    lea     r8, cfg_name_buf
    mov     edx, esi
    mov     rcx, rbx
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @cl_trusted_done
    test    eax, eax
    jnz     @cl_trusted_next

    lea     rcx, cfg_name_buf
    call    wcs_ascii_lower_inplace
    lea     rcx, cfg_name_buf
    call    IoctlAddTrusted

@cl_trusted_next:
    inc     esi
    jmp     @cl_trusted_loop

@cl_trusted_done:
    call    CloseDevice
@cl_trusted_drv_fail:
    mov     rcx, rbx
    call    RegCloseKey

@cl_done:
    add     rsp, 48h
    pop     rsi
    pop     rbx
    ret
ConfigLoad endp

end
