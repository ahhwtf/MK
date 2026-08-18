; ==============================================================================
; Vault Guard - ListView Helpers
;
; Author: Marek Wesołowski (wesmar)
; Purpose: SysListView32 column/item management. Refresh both lists from:
;          - Paths: scanned from driver IOCTL buffer (DWORD flags + WCHAR path)
;          - Trusted: enumerated from HKCU\Software\kvc\lock\Trusted (driver does
;                     not return reliable process names)
;          Flicker eliminated via WM_SETREDRAW freeze/thaw + InvalidateRect.
;          Paths shown as DOS via QueryDosDeviceW cache.
;
; Exported:
;   _LvAddColumn(rcx=hwndLv, rdx=colIdx, r8=width, r9=pszText)  → void
;   _LvInsertItem(rcx=hwndLv, rdx=row, r8=col, r9=pszText)      → void
;   _LvGetSelIdx(rcx=hwndLv)                                     → rax = idx|-1
;   _LvGetItemText(rcx=hwndLv, rdx=row, r8=col, r9=buf)         → void
;   RefreshLists()                                               → void
;
; Internal:
;   _NtDosCacheInit()                                            → void
;   _NtPathToDos(rcx=nt, rdx=out, r8d=outChars)                  → eax(1=ok)
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN SendMessageW              :PROC
EXTRN InvalidateRect            :PROC
EXTRN QueryDosDeviceW           :PROC
EXTRN RegOpenKeyExW             :PROC
EXTRN RegEnumValueW             :PROC
EXTRN RegCloseKey               :PROC
EXTRN EnsureDriverReady         :PROC
EXTRN IoctlEnumPaths            :PROC
EXTRN CloseDevice               :PROC
EXTRN wcscmp_ci                 :PROC

EXTRN g_pendingPath             :WORD

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

PUBLIC str_check
PUBLIC str_empty
str_check       dw 2611h,0          ; ☑ checked box
str_empty       dw 2610h,0          ; ☐ empty box

lv_str_trust_key dw 'S','o','f','t','w','a','r','e','\','k','v','c','\','l','o','c','k','\','T','r','u','s','t','e','d',0
lv_str_paths_key dw 'S','o','f','t','w','a','r','e','\','k','v','c','\','l','o','c','k','\','P','a','t','h','s',0

; ==============================================================================
; DATA
; ==============================================================================
.data
    align 8

lv_item             db LVITEMW_SIZE dup(0)
lv_col              db LVCOLUMNW_SIZE dup(0)

.data?
    align 8
    ; NT→DOS conversion cache (26 drives × 64 WCHARs)
    dos_drives_buf   dw 26 * 64 dup(?)
    dos_drives_len   dd 26 dup(?)
    dos_cache_inited dd ?
    dos_drive_name   dw 8 dup(?)
    nt_dos_scratch   dw 520 dup(?)

    ; Trusted enum (registry)
    lv_trust_hkey    dq ?
    lv_trust_namelen dd ?
    lv_trust_name_buf dw 520 dup(?)

    ; Paths enum (registry)
    lv_path_hkey     dq ?
    lv_path_namelen  dd ?
    lv_path_datalen  dd ?
    lv_path_type     dd ?
    lv_path_flags    dd ?
    lv_path_name_buf dw 520 dup(?)

    ; Selection preservation across refresh
    lv_saved_path_buf  dw 520 dup(?)
    lv_saved_trust_buf dw 520 dup(?)
    lv_compare_buf     dw 520 dup(?)

; ==============================================================================
; CODE
; ==============================================================================
.code

PUBLIC _LvAddColumn
PUBLIC _LvInsertItem
PUBLIC _LvGetSelIdx
PUBLIC _LvGetItemText
PUBLIC _LvSetRowParam
PUBLIC _LvGetRowParam
PUBLIC RefreshLists

; ==============================================================================
; _NtDosCacheInit  →  void
; Idempotent. Fills cache via QueryDosDeviceW for drives A..Z.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_NtDosCacheInit proc
    cmp     dos_cache_inited, 0
    jne     @ndc_already

    push    rbx
    push    rsi
    sub     rsp, 28h

    xor     ebx, ebx                        ; drive index 0..25
@ndc_loop:
    cmp     ebx, 26
    jge     @ndc_done

    ; Build L"X:\0" drive query string for this index
    movzx   eax, bl
    add     eax, 'A'                            ; drive letter: A + index
    mov     word ptr [dos_drive_name],     ax   ; e.g. L'C'
    mov     word ptr [dos_drive_name + 2], ':' ; L':'
    mov     word ptr [dos_drive_name + 4], 0   ; null terminator

    ; rsi = &dos_drives_buf[drive_index * 64 WCHARs]
    mov     rax, rbx
    shl     rax, 7                              ; *128 = *64 WCHARs * 2 bytes
    lea     rsi, dos_drives_buf
    add     rsi, rax

    mov     r8d, 64                             ; output buffer: 64 WCHARs
    mov     rdx, rsi
    lea     rcx, dos_drive_name                 ; e.g. "C:"
    call    QueryDosDeviceW                     ; -> "\Device\HarddiskVolume3"
    test    eax, eax
    jz      @ndc_invalid

    ; measure NT prefix length (up to 64 WCHARs) for prefix matching later
    xor     ecx, ecx
@ndc_strlen:
    cmp     ecx, 64
    jge     @ndc_invalid
    cmp     word ptr [rsi + rcx * 2], 0
    je      @ndc_got_len
    inc     ecx
    jmp     @ndc_strlen
@ndc_got_len:
    test    ecx, ecx
    jz      @ndc_invalid                        ; empty result -- drive not ready
    lea     r10, dos_drives_len
    mov     dword ptr [r10 + rbx * 4], ecx      ; store length for _NtPathToDos
    jmp     @ndc_next

@ndc_invalid:
    lea     r10, dos_drives_len
    mov     dword ptr [r10 + rbx * 4], 0

@ndc_next:
    inc     ebx
    jmp     @ndc_loop

@ndc_done:
    mov     dos_cache_inited, 1
    add     rsp, 28h
    pop     rsi
    pop     rbx
@ndc_already:
    ret
_NtDosCacheInit endp

; ==============================================================================
; _NtPathToDos  rcx=ntPath  rdx=outBuf  r8d=outBufChars  →  eax(1=ok)
; Case-insensitive prefix match (ASCII fold) → "X:" + remainder.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_NtPathToDos proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx                        ; ntPath
    mov     rsi, rdx                        ; outBuf
    mov     r12d, r8d                       ; outBufChars

    call    _NtDosCacheInit

    cmp     r12d, 3
    jl      @npd_fail

    xor     edi, edi
@npd_drv_loop:
    cmp     edi, 26
    jge     @npd_fail

    lea     r10, dos_drives_len
    mov     r11d, dword ptr [r10 + rdi * 4]
    test    r11d, r11d
    jz      @npd_next

    mov     rax, rdi
    shl     rax, 7
    lea     rdx, dos_drives_buf
    add     rdx, rax
    mov     r10, rbx
    mov     r9d, r11d

@npd_cmp:
    test    r9d, r9d
    jz      @npd_matched
    mov     ax,  word ptr [rdx]
    mov     r8w, word ptr [r10]
    cmp     ax, 'A'
    jb      @npd_cmp_pok
    cmp     ax, 'Z'
    ja      @npd_cmp_pok
    or      ax, 20h
@npd_cmp_pok:
    cmp     r8w, 'A'
    jb      @npd_cmp_sok
    cmp     r8w, 'Z'
    ja      @npd_cmp_sok
    or      r8w, 20h
@npd_cmp_sok:
    cmp     ax, r8w
    jne     @npd_next
    add     rdx, 2
    add     r10, 2
    dec     r9d
    jmp     @npd_cmp

@npd_matched:
    movzx   eax, dil
    add     eax, 'A'
    mov     word ptr [rsi],     ax
    mov     word ptr [rsi + 2], ':'

    lea     r11, [rsi + 4]
    mov     r9d, r12d
    sub     r9d, 2

@npd_copy:
    test    r9d, r9d
    jz      @npd_trunc
    mov     ax, word ptr [r10]
    mov     word ptr [r11], ax
    test    ax, ax
    jz      @npd_ok
    add     r10, 2
    add     r11, 2
    dec     r9d
    jmp     @npd_copy

@npd_trunc:
    mov     word ptr [r11 - 2], 0

@npd_ok:
    mov     eax, 1
    jmp     @npd_ret

@npd_next:
    inc     edi
    jmp     @npd_drv_loop

@npd_fail:
    xor     eax, eax
@npd_ret:
    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_NtPathToDos endp

; ==============================================================================
; _LvSetRowParam  rcx=hwndLv  rdx=row  r8=lParam  →  void
; Stores lParam (flags DWORD) in LVITEMW for the given row.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 38h (+56)→0 ✓
; ==============================================================================
_LvSetRowParam proc
    push    rbx
    push    rsi
    sub     rsp, 38h

    mov     rbx, rcx
    mov     esi, edx

    lea     r10, lv_item
    mov     dword ptr [r10 + LVITEMW_mask],     LVIF_PARAM
    mov     dword ptr [r10 + LVITEMW_iItem],    esi
    mov     dword ptr [r10 + LVITEMW_iSubItem], 0
    mov     qword ptr [r10 + LVITEMW_lParam],   r8

    lea     r9, lv_item
    xor     r8d, r8d
    mov     edx, LVM_SETITEMW
    mov     rcx, rbx
    call    SendMessageW

    add     rsp, 38h
    pop     rsi
    pop     rbx
    ret
_LvSetRowParam endp

; ==============================================================================
; _LvGetRowParam  rcx=hwndLv  rdx=row  →  rax = lParam
; Retrieves lParam (flags DWORD) from LVITEMW for the given row.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_LvGetRowParam proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rbx, rcx
    mov     esi, edx

    lea     r10, lv_item
    mov     dword ptr [r10 + LVITEMW_mask],     LVIF_PARAM
    mov     dword ptr [r10 + LVITEMW_iItem],    esi
    mov     dword ptr [r10 + LVITEMW_iSubItem], 0
    mov     qword ptr [r10 + LVITEMW_pszText],  0

    lea     r9, lv_item
    xor     r8d, r8d
    mov     edx, LVM_GETITEMW
    mov     rcx, rbx
    call    SendMessageW

    lea     r10, lv_item
    mov     rax, qword ptr [r10 + LVITEMW_lParam]

    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_LvGetRowParam endp

; ==============================================================================
; _LvAddColumn  rcx=hwndLv  rdx=colIdx  r8=width  r9=pszText  →  void
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_LvAddColumn proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx
    mov     rsi, rdx
    mov     rdi, r8
    mov     r12, r9

    lea     r10, lv_col
    mov     dword ptr [r10 + LVCOLUMNW_mask],    (LVCF_TEXT + LVCF_WIDTH + LVCF_FMT + LVCF_SUBITEM)
    mov     dword ptr [r10 + LVCOLUMNW_fmt],     LVCFMT_LEFT
    mov     dword ptr [r10 + LVCOLUMNW_cx],      edi
    mov     qword ptr [r10 + LVCOLUMNW_pszText], r12
    mov     dword ptr [r10 + LVCOLUMNW_iSubItem],esi

    lea     r9, lv_col
    mov     r8d, esi
    mov     edx, LVM_INSERTCOLUMNW
    mov     rcx, rbx
    call    SendMessageW

    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_LvAddColumn endp

; ==============================================================================
; _LvInsertItem  rcx=hwndLv  rdx=row  r8=col  r9=pszText  →  void
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_LvInsertItem proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx
    mov     rsi, rdx
    mov     rdi, r8
    mov     r12, r9

    lea     r10, lv_item
    xor     eax, eax
    mov     dword ptr [r10 + LVITEMW_mask],       (LVIF_TEXT)
    mov     dword ptr [r10 + LVITEMW_iItem],       esi
    mov     dword ptr [r10 + LVITEMW_iSubItem],    edi
    mov     dword ptr [r10 + LVITEMW_state],       0
    mov     dword ptr [r10 + LVITEMW_stateMask],   0
    mov     qword ptr [r10 + LVITEMW_pszText],     r12
    mov     dword ptr [r10 + LVITEMW_cchTextMax],  260
    mov     dword ptr [r10 + LVITEMW_iImage],      0
    mov     qword ptr [r10 + LVITEMW_lParam],      0

    lea     r9, lv_item
    xor     r8d, r8d
    test    edi, edi
    jz      @lii_insert
    mov     edx, LVM_SETITEMW
    jmp     @lii_send
@lii_insert:
    mov     edx, LVM_INSERTITEMW
@lii_send:
    mov     rcx, rbx
    call    SendMessageW

    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_LvInsertItem endp

; ==============================================================================
; _LvGetSelIdx  rcx=hwndLv  →  rax = selected index or -1
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_LvGetSelIdx proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     r9d, LVNI_SELECTED
    mov     r8, -1
    mov     edx, LVM_GETNEXTITEM
    call    SendMessageW

    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_LvGetSelIdx endp

; ==============================================================================
; _LvGetItemText  rcx=hwndLv  rdx=row  r8=col  r9=buf  →  void
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_LvGetItemText proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx
    mov     rsi, rdx
    mov     rdi, r8
    mov     r12, r9

    lea     r10, lv_item
    mov     dword ptr [r10 + LVITEMW_mask],      LVIF_TEXT
    mov     dword ptr [r10 + LVITEMW_iItem],     esi
    mov     dword ptr [r10 + LVITEMW_iSubItem],  edi
    mov     qword ptr [r10 + LVITEMW_pszText],   r12
    mov     dword ptr [r10 + LVITEMW_cchTextMax],260

    lea     r8, lv_item
    mov     r9, r8
    mov     r8d, esi
    mov     edx, LVM_GETITEMTEXTW
    mov     rcx, rbx
    call    SendMessageW

    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_LvGetItemText endp

; ==============================================================================
; _LvFreeze  rcx=hwndLv  rdx=enable(0=freeze,1=thaw)  →  void
; WM_SETREDRAW wrapper. On thaw also invalidates the window.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_LvFreeze proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rbx, rcx                        ; hwnd
    mov     rsi, rdx                        ; enable

    xor     r9d, r9d
    mov     r8, rsi                             ; wParam = enable (0=freeze, 1=thaw)
    mov     edx, WM_SETREDRAW
    mov     rcx, rbx
    call    SendMessageW

    test    rsi, rsi                            ; only invalidate on thaw
    jz      @lf_ret
    xor     r8d, r8d                        ; bErase = FALSE
    xor     edx, edx                        ; lpRect = NULL (entire client)
    mov     rcx, rbx
    call    InvalidateRect                      ; force repaint after batch update

@lf_ret:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_LvFreeze endp

; ==============================================================================
; _LvSelectByText  rcx=hwndLv  rdx=targetText(WCHAR*)  →  void
; Walks rows, finds first whose col 0 text matches target (case-insensitive),
; selects + focuses it and ensures it is visible. Silent if no match.
; Stack: entry rsp%16=8; push rbx,rsi,r12,r13 (+32)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_LvSelectByText proc
    push    rbx
    push    rsi
    push    r12
    push    r13
    sub     rsp, 28h

    mov     rbx, rcx                        ; hwnd
    mov     rsi, rdx                        ; target text

    ; r12d = LVM_GETITEMCOUNT(hwnd)
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, LVM_GETITEMCOUNT
    mov     rcx, rbx
    call    SendMessageW
    mov     r12d, eax
    test    r12d, r12d
    jle     @lsb_ret

    xor     r13d, r13d
@lsb_loop:
    cmp     r13d, r12d
    jge     @lsb_ret

    ; Fetch col 0 text of row r13d into lv_compare_buf
    lea     r9, lv_compare_buf
    xor     r8d, r8d
    mov     rdx, r13
    mov     rcx, rbx
    call    _LvGetItemText

    ; wcscmp_ci(rsi, lv_compare_buf) → 0 if match
    lea     rdx, lv_compare_buf
    mov     rcx, rsi
    call    wcscmp_ci
    test    eax, eax
    jnz     @lsb_next

    ; Match → set state SELECTED|FOCUSED
    lea     r10, lv_item
    mov     dword ptr [r10 + LVITEMW_state],     (LVIS_SELECTED + LVIS_FOCUSED)
    mov     dword ptr [r10 + LVITEMW_stateMask], (LVIS_SELECTED + LVIS_FOCUSED)

    lea     r9, lv_item
    mov     r8, r13
    mov     edx, LVM_SETITEMSTATE
    mov     rcx, rbx
    call    SendMessageW

    ; Ensure visible
    xor     r9d, r9d
    mov     r8, r13
    mov     edx, LVM_ENSUREVISIBLE
    mov     rcx, rbx
    call    SendMessageW
    jmp     @lsb_ret

@lsb_next:
    inc     r13d
    jmp     @lsb_loop

@lsb_ret:
    add     rsp, 28h
    pop     r13
    pop     r12
    pop     rsi
    pop     rbx
    ret
_LvSelectByText endp

; ==============================================================================
; RefreshLists  →  void
;
; Both ListViews repopulated with redraw frozen to eliminate flicker.
; Paths: scan g_ioBuf for {DWORD flags, WCHAR \path, null} records.
; Trusted: enumerate HKCU\Software\kvc\lock\Trusted via RegEnumValueW.
;
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12,r13,r14 (+48)→8; sub 48h (+72)→0 ✓
; RegEnumValueW 8 args: 4 stack slots at [+20h]..[+38h] (within 0x48 alloc).
; ==============================================================================
RefreshLists proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 48h

    ; Snapshot current selections (col 0 path text) to restore after repopulation
    mov     word ptr [lv_saved_path_buf], 0     ; sentinel: empty = nothing selected
    mov     rcx, g_hwndLvPaths
    call    _LvGetSelIdx                        ; -1 if no selection
    cmp     rax, -1
    je      @rl_no_path_sel
    lea     r9, lv_saved_path_buf
    xor     r8d, r8d                            ; col 0 = path
    mov     rdx, rax
    mov     rcx, g_hwndLvPaths
    call    _LvGetItemText                      ; save selected path text
@rl_no_path_sel:

    mov     word ptr [lv_saved_trust_buf], 0
    mov     rcx, g_hwndLvTrusted
    call    _LvGetSelIdx
    cmp     rax, -1
    je      @rl_no_trust_sel
    lea     r9, lv_saved_trust_buf
    xor     r8d, r8d
    mov     rdx, rax
    mov     rcx, g_hwndLvTrusted
    call    _LvGetItemText                      ; save selected trusted process text
@rl_no_trust_sel:

    ; ── Freeze both ListViews ────────────────────────────────────────────────
    mov     edx, 0                              ; 0 = freeze (disable redraw)
    mov     rcx, g_hwndLvPaths
    call    _LvFreeze
    mov     edx, 0
    mov     rcx, g_hwndLvTrusted
    call    _LvFreeze

    ; ── Clear paths ──────────────────────────────────────────────────────────
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, LVM_DELETEALLITEMS
    mov     rcx, g_hwndLvPaths
    call    SendMessageW

    ; ── Registry enum paths (authoritative GUI state) ────────────────────────
    lea     rax, lv_path_hkey
    mov     qword ptr [rsp + 20h], rax          ; phkResult
    mov     r9d, KEY_READ
    xor     r8d, r8d                            ; ulOptions = 0
    lea     rdx, lv_str_paths_key               ; "Software\VG\Paths"
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @rl_no_reg_paths

    xor     r13d, r13d              ; registry value index
    xor     r14d, r14d              ; row index

@rl_paths_loop:
    mov     dword ptr [lv_path_namelen], 520
    mov     dword ptr [lv_path_datalen], 4

    lea     rax, lv_path_datalen
    mov     qword ptr [rsp + 38h], rax
    lea     rax, lv_path_flags
    mov     qword ptr [rsp + 30h], rax
    lea     rax, lv_path_type
    mov     qword ptr [rsp + 28h], rax
    mov     qword ptr [rsp + 20h], 0
    lea     r9, lv_path_namelen
    lea     r8, lv_path_name_buf
    mov     edx, r13d
    mov     rcx, qword ptr [lv_path_hkey]
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @rl_paths_close
    test    eax, eax
    jnz     @rl_paths_next

    mov     edi, dword ptr [lv_path_flags]
    and     edi, 0Fh

    lea     r9, lv_path_name_buf

    ; If registry now contains the pending path, clear the pending marker (avoid duplicate row)
    mov     qword ptr [rsp + 40h], r9           ; save r9 across call
    cmp     word ptr [g_pendingPath], 0
    je      @rl_pending_checked                 ; no pending path
    mov     rdx, r9                             ; current registry path
    lea     rcx, g_pendingPath
    call    wcscmp_ci                           ; case-insensitive compare
    test    eax, eax
    jnz     @rl_pending_checked
    mov     word ptr [g_pendingPath], 0         ; matched: clear pending
@rl_pending_checked:
    mov     r9, qword ptr [rsp + 40h]          ; restore r9

    mov     r8d, LVITEM_COL_PATH
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    ; Store protection flags in LVITEM.lParam for fast checkbox toggle (no registry read)
    mov     r8d, edi                            ; flags bitmask
    mov     rdx, r14                            ; row index
    mov     rcx, g_hwndLvPaths
    call    _LvSetRowParam

    ; Col 1: Hidden
    test    dil, VG_FLAG_HIDDEN
    lea     r9, str_check
    jnz     @rl_h1
    lea     r9, str_empty
@rl_h1:
    mov     r8d, LVITEM_COL_H
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    ; Col 2: Locked
    test    dil, VG_FLAG_LOCKED
    lea     r9, str_check
    jnz     @rl_l1
    lea     r9, str_empty
@rl_l1:
    mov     r8d, LVITEM_COL_L
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    ; Col 3: Read-only
    test    dil, VG_FLAG_READONLY
    lea     r9, str_check
    jnz     @rl_r1
    lea     r9, str_empty
@rl_r1:
    mov     r8d, LVITEM_COL_R
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    ; Col 4: No-exec
    test    dil, VG_FLAG_NOEXEC
    lea     r9, str_check
    jnz     @rl_x1
    lea     r9, str_empty
@rl_x1:
    mov     r8d, LVITEM_COL_X
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    inc     r14d

@rl_paths_next:
    inc     r13d
    jmp     @rl_paths_loop

@rl_paths_close:
    mov     rcx, qword ptr [lv_path_hkey]
    call    RegCloseKey
    jmp     @rl_after_paths

@rl_no_reg_paths:
    xor     r14d, r14d

@rl_after_paths:

    ; ── Pending path (selected but not yet in driver) ────────────────────────
    cmp     word ptr [g_pendingPath], 0
    je      @rl_no_pending

    lea     r9, g_pendingPath
    mov     r8d, LVITEM_COL_PATH
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    xor     r8d, r8d            ; lParam=0 (no flags yet)
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvSetRowParam

    lea     r9, str_empty
    mov     r8d, LVITEM_COL_H
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    lea     r9, str_empty
    mov     r8d, LVITEM_COL_L
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    lea     r9, str_empty
    mov     r8d, LVITEM_COL_R
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    lea     r9, str_empty
    mov     r8d, LVITEM_COL_X
    mov     rdx, r14
    mov     rcx, g_hwndLvPaths
    call    _LvInsertItem

    inc     r14d
@rl_no_pending:

    ; ── Clear trusted list ───────────────────────────────────────────────────
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, LVM_DELETEALLITEMS
    mov     rcx, g_hwndLvTrusted
    call    SendMessageW

    ; ── Open HKCU\Software\kvc\lock\Trusted ─────────────────────────────────
    ; RegOpenKeyExW(HKCU, subkey, 0, KEY_READ, &lv_trust_hkey)  ; 5 args
    lea     rax, lv_trust_hkey
    mov     qword ptr [rsp + 20h], rax
    mov     r9d, KEY_READ
    xor     r8d, r8d
    lea     rdx, lv_str_trust_key
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @rl_after_trusted

    xor     r14d, r14d              ; row index / enum index

@rl_trust_loop:
    mov     dword ptr [lv_trust_namelen], 520
    ; RegEnumValueW: value name = process name; data not used (presence = allow)
    mov     qword ptr [rsp + 38h], 0            ; lpcbData = NULL
    mov     qword ptr [rsp + 30h], 0            ; lpData = NULL
    mov     qword ptr [rsp + 28h], 0            ; lpType = NULL
    mov     qword ptr [rsp + 20h], 0            ; lpReserved = NULL
    lea     r9, lv_trust_namelen
    lea     r8, lv_trust_name_buf               ; value name = process name
    mov     edx, r14d                           ; dwIndex
    mov     rcx, qword ptr [lv_trust_hkey]
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @rl_trust_close
    test    eax, eax
    jnz     @rl_trust_next                      ; skip damaged entries

    lea     r9, lv_trust_name_buf               ; process name string
    xor     r8d, r8d                            ; col 0
    mov     rdx, r14
    mov     rcx, g_hwndLvTrusted
    call    _LvInsertItem

@rl_trust_next:
    inc     r14d
    jmp     @rl_trust_loop

@rl_trust_close:
    mov     rcx, qword ptr [lv_trust_hkey]
    call    RegCloseKey

@rl_after_trusted:

    ; ── Restore selections by text ───────────────────────────────────────────
    cmp     word ptr [lv_saved_path_buf], 0
    je      @rl_skip_path_restore
    lea     rdx, lv_saved_path_buf
    mov     rcx, g_hwndLvPaths
    call    _LvSelectByText
@rl_skip_path_restore:

    cmp     word ptr [lv_saved_trust_buf], 0
    je      @rl_skip_trust_restore
    lea     rdx, lv_saved_trust_buf
    mov     rcx, g_hwndLvTrusted
    call    _LvSelectByText
@rl_skip_trust_restore:

    ; ── Thaw both ListViews + invalidate ─────────────────────────────────────
    mov     edx, 1
    mov     rcx, g_hwndLvPaths
    call    _LvFreeze
    mov     edx, 1
    mov     rcx, g_hwndLvTrusted
    call    _LvFreeze

    add     rsp, 48h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
RefreshLists endp

end
