@echo off
echo.
echo ==========================================
echo Drive Zone Online - Android Tools
echo ==========================================
echo.
echo Android Crate Counter Fix
echo FIXED: 300/100 = 3 cars, not 1 car!
echo.
echo Make sure your Android device is connected via USB
echo with debugging enabled before continuing.
echo.
pause
echo.
echo Checking device connection...
adb devices
echo.
echo If your device is not listed above, check:
echo - USB debugging is enabled
echo - Device is connected via USB
echo - USB drivers are installed
echo.
pause
echo.
echo Starting Android Crate Counter Fix...
cd CrateCounterFix
python crate_counter_controller.py
pause
