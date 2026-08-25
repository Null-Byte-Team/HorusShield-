@echo off
chcp 65001 >nul 2>&1
title HorusShield 2.0 — Build EXE
color 0A
echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   HORUSSHIELD 2.0 — Build EXE           ║
echo  ║   Team NullByte · WE School · Alex       ║
echo  ╚══════════════════════════════════════════╝
echo.

:: ── Detect Compatible Python (Python 3.10 - 3.12) ──
set "PYTHON_EXE="

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :found_python
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto :found_python
)
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    goto :found_python
)
if exist "C:\Python311\python.exe" (
    set "PYTHON_EXE=C:\Python311\python.exe"
    goto :found_python
)
if exist "C:\Python312\python.exe" (
    set "PYTHON_EXE=C:\Python312\python.exe"
    goto :found_python
)

py -3.11 -V >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=py -3.11"
    goto :found_python
)

py -3.12 -V >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=py -3.12"
    goto :found_python
)

py -3.10 -V >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=py -3.10"
    goto :found_python
)

for /f "tokens=*" %%i in ('where python 2^>nul') do (
    "%%i" -c "import sys; sys.exit(0 if (3,9) <= sys.version_info < (3,14) else 1)" >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=%%i"
        goto :found_python
    )
)

set "PYTHON_EXE=python"

:found_python
echo [INFO] Using Python: %PYTHON_EXE%
echo.

:: Step 1 — Install deps
echo [1/4] Installing dependencies...
"%PYTHON_EXE%" -m pip install --prefer-binary -r backend\requirements.txt --quiet
"%PYTHON_EXE%" -m pip install --prefer-binary pyinstaller pillow --quiet
echo Done.

:: Step 2 — Clean old build
echo [2/4] Cleaning old build...
if exist dist\HorusShield.exe del /f /q dist\HorusShield.exe
if exist build rmdir /s /q build
echo Done.

:: Step 3 — Build EXE
echo [3/4] Building EXE with PyInstaller...
"%PYTHON_EXE%" -m PyInstaller HorusShield.spec --clean --noconfirm
echo Done.

:: Step 4 — Check result
echo [4/4] Checking...
if exist dist\HorusShield.exe (
    echo.
    echo  ✅ BUILD SUCCESSFUL!
    echo  📁 File: dist\HorusShield.exe
    echo.
    echo  To create installer: install NSIS then run:
    echo     makensis installer\HorusShield_Installer.nsi
) else (
    echo.
    echo  ❌ BUILD FAILED — check error messages above
)
echo.
pause
