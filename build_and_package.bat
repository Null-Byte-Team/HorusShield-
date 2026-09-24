@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"
title HorusShield 2.0 -- Build + Package
color 0B

echo.
echo  ============================================
echo     HorusShield 2.0 -- Full Build
echo     Team NullByte * WE School
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

REM -- STEP 1: Install dependencies --
echo [1/4] Installing Python dependencies...
"%PYTHON_EXE%" -m pip install --prefer-binary -r backend\requirements.txt
if errorlevel 1 (
    echo  [ERROR] pip install failed.
    pause & exit /b 1
)
"%PYTHON_EXE%" -m pip install --prefer-binary pyinstaller pillow
if errorlevel 1 (
    echo  [ERROR] pip install failed.
    pause & exit /b 1
)

REM -- STEP 2: Clean old build --
echo [2/4] Cleaning previous build...
if exist build  rmdir /s /q build
if exist dist   rmdir /s /q dist

REM -- STEP 3: Build EXE --
echo [3/4] Building EXE...
"%PYTHON_EXE%" -m PyInstaller HorusShield.spec --clean --noconfirm
if errorlevel 1 (
    echo  [ERROR] PyInstaller failed.
    pause & exit /b 1
)

if not exist dist\HorusShield.exe (
    echo  [ERROR] EXE not found after build.
    pause & exit /b 1
)
echo  [OK] EXE ready: dist\HorusShield.exe

REM -- STEP 4: NSIS Installer (optional) --
echo [4/4] Building installer...
where makensis >nul 2>&1
if errorlevel 1 (
    echo  [SKIP] NSIS not found -- get it from https://nsis.sourceforge.io
    echo.
    echo  ========================================
    echo  DONE!  EXE is at: dist\HorusShield.exe
    echo  Double-click it to run HorusShield.
    echo  ========================================
    echo.
    pause & exit /b 0
)

makensis installer\HorusShield_Installer.nsi
if errorlevel 1 (
    echo  [ERROR] NSIS failed.
    pause & exit /b 1
)

echo.
echo  ============================================
echo  BUILD COMPLETE!
echo.
echo  EXE only:  dist\HorusShield.exe
echo  Installer: installer\HorusShield_Setup.exe
echo.
echo  Share HorusShield_Setup.exe with anyone!
echo  ============================================
echo.
pause
