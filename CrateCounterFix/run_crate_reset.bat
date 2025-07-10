@echo off
echo ========================================
echo Drive Zone Online - Crate Counter Reset
echo ========================================
echo.
echo This script will help you reset your crate counter
echo when it reaches 160 to maintain 4-car rewards.
echo.
echo Make sure Drive Zone Online is running before continuing.
echo.
pause

echo [*] Starting crate counter reset system...
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Please install Python first.
    pause
    exit /b 1
)

REM Check if Frida is installed
python -c "import frida" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Frida not found. Installing Frida...
    pip install frida-tools
    if %errorlevel% neq 0 (
        echo [!] Failed to install Frida. Please install manually.
        pause
        exit /b 1
    )
)

echo [*] Running crate counter controller...
echo.

REM Run the controller
python crate_counter_controller.py

echo.
echo [*] Script finished.
pause
