; ==============================================================================
; Vault Guard - Global External Declarations
; Defined in main.asm; referenced by all other modules.
; ==============================================================================

    EXTRN   g_hInstance         :QWORD
    EXTRN   g_hwndMain          :QWORD
    EXTRN   g_hwndLvPaths       :QWORD
    EXTRN   g_hwndLvTrusted     :QWORD
    EXTRN   g_hwndBtnToggle     :QWORD
    EXTRN   g_hwndDrvStatus     :QWORD
    EXTRN   g_hwndProtStatus    :QWORD
    EXTRN   g_hDevice           :QWORD
    EXTRN   g_hFontMain         :QWORD
    EXTRN   g_hFontSmall        :QWORD
    EXTRN   g_hBrushBg          :QWORD
    EXTRN   g_isDarkMode        :DWORD
    EXTRN   g_driverInstalled   :DWORD
    EXTRN   g_driverRunning     :DWORD
    EXTRN   g_protActive        :DWORD
    EXTRN   g_cliMode           :DWORD
    EXTRN   g_startMinimized    :DWORD
    EXTRN   g_ioBuf             :BYTE
    EXTRN   g_pathBuf           :WORD
    EXTRN   g_tempBuf           :WORD
    EXTRN   g_statusBuf         :WORD
    EXTRN   g_prevDrvOk         :BYTE
    EXTRN   g_prevProtActive    :BYTE
