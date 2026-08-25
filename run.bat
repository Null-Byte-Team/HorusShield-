@echo off
chcp 65001 >nul 2>&1
title HorusShield 2.0
color 0A
echo.
echo  ╔═══════════════════════════════════════════╗
echo  ║  HORUSSHIELD 2.0 — Team NullByte         ║
echo  ║  WE School · Alexandria 🇪🇬               ║
echo  ╚═══════════════════════════════════════════╝
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
cd /d "%~dp0backend"
echo [INFO] Starting HorusShield with %PYTHON_EXE%...
echo.
"%PYTHON_EXE%" app.py
pause

