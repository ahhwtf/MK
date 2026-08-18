@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync-kvc-vps.ps1"
if errorlevel 1 (
    echo.
    echo SYNC FAILED. Review the error above.
) else (
    echo.
    echo SYNC COMPLETE.
)
pause
