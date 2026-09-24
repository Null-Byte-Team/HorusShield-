@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"
title HorusShield 2.0 -- Build EXE
color 0A

echo.
echo  ============================================
echo     HORUSSHIELD 2.0 -- Build EXE
echo     Team NullByte * WE School * Alex
echo  ============================================
echo.

REM -- Detect Compatible Python (Python 3.10 - 3.12) --
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
if exist "C:\Python310\python.exe" (
    set "PYTHON_EXE=C:\Python310\python.exe"
    goto :found_python
)

REM Check Python Launcher (py -3.11, py -3.12, py -3.10)
for /f "usebackq delims=" %%p in (`py -3.11 -c "import sys; print(sys.executable)" 2^>nul`) do (
    set "PYTHON_EXE=%%p"
    goto :found_python
)
for /f "usebackq delims=" %%p in (`py -3.12 -c "import sys; print(sys.executable)" 2^>nul`) do (
    set "PYTHON_EXE=%%p"
    goto :found_python
)
for /f "usebackq delims=" %%p in (`py -3.10 -c "import sys; print(sys.executable)" 2^>nul`) do (
    set "PYTHON_EXE=%%p"
    goto :found_python
)

REM Check PATH python instances
for /f "tokens=*" %%i in ('where python 2^>nul') do (
    "%%i" -c "import sys; sys.exit(0 if (3,9) <= sys.version_info < (3,14) else 1)" >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=%%i"
        goto :found_python
    )
)

where python >nul 2>&1
if not errorlevel 1 (
    python -c "import sys; sys.exit(0 if (3,9) <= sys.version_info < (3,14) else 1)" >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=python"
        goto :found_python
    )
)

echo [ERROR] No compatible Python version (3.10 - 3.12) found.
echo PyInstaller and machine-learning dependencies require Python 3.10, 3.11, or 3.12.
echo Please install Python 3.11 from https://www.python.org/downloads/
echo.
pause
exit /b 1

:found_python
echo [INFO] Using Python: %PYTHON_EXE%
"%PYTHON_EXE%" -V
echo.

REM Step 1 -- Install deps
echo [1/4] Installing dependencies...
"%PYTHON_EXE%" -m pip install --prefer-binary -r backend\requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install backend dependencies.
    pause
    exit /b 1
)
"%PYTHON_EXE%" -m pip install --prefer-binary pyinstaller pillow --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install PyInstaller and Pillow.
    pause
    exit /b 1
)
echo Done.
echo.

REM Step 2 -- Clean old build
echo [2/4] Cleaning old build...
if exist dist\HorusShield.exe del /f /q dist\HorusShield.exe
if exist build rmdir /s /q build
echo Done.
echo.

REM Step 3 -- Build EXE
echo [3/4] Building EXE with PyInstaller...
"%PYTHON_EXE%" -m PyInstaller HorusShield.spec --clean --noconfirm
if errorlevel 1 (
    echo [ERROR] PyInstaller build failed. Check output above.
    pause
    exit /b 1
)
echo Done.
echo.

REM Step 4 -- Check result
echo [4/4] Checking...
if exist dist\HorusShield.exe (
    echo.
    echo  ============================================
    echo   BUILD SUCCESSFUL!
    echo   File: dist\HorusShield.exe
    echo.
    echo   To create installer: install NSIS then run:
    echo      makensis installer\HorusShield_Installer.nsi
    echo  ============================================
) else (
    echo.
    echo  ============================================
    echo   BUILD FAILED -- dist\HorusShield.exe not found
    echo  ============================================
)
echo.
pause
