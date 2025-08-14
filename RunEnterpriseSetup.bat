@echo off
REM ==================================================
REM  Enterprise Device Setup Script Launcher
REM ==================================================
REM 
REM This batch file sets the PowerShell execution policy
REM and launches the Enterprise Device Setup PowerShell script.
REM 
REM Created: 2025-06-25
REM Author: System Administrator
REM ==================================================

echo.
echo ==================================================
echo     Enterprise Device Setup Script Launcher
echo ==================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo This script requires administrator privileges.
    echo Please right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo Setting PowerShell execution policy to allow script execution...

REM Temporarily set execution policy to allow the script to run
powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force"

if %errorLevel% neq 0 (
    echo Failed to set execution policy.
    pause
    exit /b 1
)

echo Execution policy set successfully.
echo.
echo IMPORTANT: Before running, ensure you have configured the script variables:
echo - CLIENT_NAME (3 characters max)
echo - CLIENT_LOCATION (3 characters max) 
echo - WIFI_SSID (your WiFi network name)
echo - WIFI_PASSWORD (your WiFi password)
echo - SOFTWARE_PACKAGES (modify as needed)
echo.
echo Launching Enterprise Device Setup PowerShell script...
echo.

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

REM Check if the PowerShell script exists in the same directory as this batch file
if not exist "%SCRIPT_DIR%EnterpriseDeviceSetup.ps1" (
    echo ERROR: EnterpriseDeviceSetup.ps1 not found in the same directory as this batch file.
    echo Batch file location: %SCRIPT_DIR%
    echo Please ensure both files are in the same folder.
    echo.
    pause
    exit /b 1
)

REM Launch the PowerShell script with execution policy bypass using full path
powershell.exe -ExecutionPolicy Bypass -File "%SCRIPT_DIR%EnterpriseDeviceSetup.ps1"

REM Capture the exit code from PowerShell
set PS_EXIT_CODE=%errorLevel%

echo.
echo ==================================================
if %PS_EXIT_CODE% == 0 (
    echo Enterprise Device Setup completed successfully.
) else (
    echo Enterprise Device Setup completed with errors.
    echo Exit code: %PS_EXIT_CODE%
)
echo ==================================================
echo.

REM Reset execution policy back to restricted (optional security measure)
echo Resetting PowerShell execution policy to Restricted...
powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force" 2>nul

echo.
echo Press any key to exit...
pause >nul

exit /b %PS_EXIT_CODE%