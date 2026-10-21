@echo off
setlocal enabledelayedexpansion

title VoidOsint Platform Launcher
cd /d "%~dp0"

echo ===============================================================
echo  VoidOsint - Unified Multi-Engine OSINT Intelligence Cockpit
echo ===============================================================
echo [*] Target URL: http://127.0.0.1:5002
echo.

:: Check for Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not found in PATH.
    echo Please install Python 3.10+ and add it to your PATH environment variable.
    pause
    exit /b 1
)

:: Activate virtual environment if present
if exist "venv\Scripts\activate.bat" (
    echo [*] Activating local virtual environment...
    call venv\Scripts\activate.bat
) else if exist "..\venv\Scripts\activate.bat" (
    echo [*] Activating workspace virtual environment...
    call ..\venv\Scripts\activate.bat
)

:: Run VoidOsint CLI Launcher
python run_osint.py %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Server exited with status code %ERRORLEVEL%.
    pause
)
