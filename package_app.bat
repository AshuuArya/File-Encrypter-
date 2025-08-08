@echo off
cls
echo.
echo  ==========================================================
echo   FileEncrypter Application Packager
echo  ==========================================================
echo.
echo  This script will bundle the Python application into a single
echo  Windows executable (.exe) file using PyInstaller.
echo.

REM Check if pyinstaller is installed, install if it's not
echo  [1/3] Checking for PyInstaller...
pip show pyinstaller > nul 2>&1
if %errorlevel% neq 0 (
    echo      -> PyInstaller not found. Attempting to install now...
    pip install pyinstaller
    if %errorlevel% neq 0 (
        echo.
        echo  ERROR: Failed to install PyInstaller.
        echo  Please install it manually by running: pip install pyinstaller
        pause
        exit /b 1
    )
    echo      -> PyInstaller installed successfully.
) else (
    echo      -> PyInstaller is already installed.
)

REM Set variables
set APP_NAME=FileEncrypter
set SCRIPT_NAME=main.py

echo.
echo  [2/3] Running PyInstaller...
echo  This may take a few minutes. Please be patient.
echo.

pyinstaller --noconfirm --onefile --windowed --name %APP_NAME% %SCRIPT_NAME%

echo.

if %errorlevel% equ 0 (
    echo  [3/3] Packaging complete!
    echo.
    echo  ==========================================================
    echo   SUCCESS!
    echo.
    echo   Your application executable can be found in the 'dist'
    echo   folder that has been created in this directory.
    echo.
    echo   Path: %cd%\dist\%APP_NAME%.exe
    echo  ==========================================================
) else (
    echo  ==========================================================
    echo   PACKAGING FAILED.
    echo.
    echo   An error occurred during the PyInstaller process.
    echo   Please check the output above for specific error messages.
    echo  ==========================================================
)

echo.
pause
