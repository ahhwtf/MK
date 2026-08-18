@echo off
setlocal

set "ROOT=%~dp0"
set "SCRIPT=%ROOT%sign.ps1"

if not exist "%SCRIPT%" (
    echo Sign script not found: "%SCRIPT%"
    exit /b 1
)

where pwsh >nul 2>&1
if errorlevel 1 (
    set "PSHOST=powershell"
) else (
    set "PSHOST=pwsh"
)

"%PSHOST%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
exit /b %ERRORLEVEL%
