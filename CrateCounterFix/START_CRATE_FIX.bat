@echo off
echo.
echo ========================================
echo Drive Zone Online - Crate Counter Fix
echo ========================================
echo.
echo FIXED: 300/100 = 3 cars, not 1 car!
echo.
echo This will start the crate counter fix for Android devices.
echo Make sure your Android device is connected via USB with debugging enabled.
echo.
pause
echo.
echo Starting crate counter controller...
python crate_counter_controller.py
pause
