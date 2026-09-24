@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"
title HorusShield 2.0
color 0A

echo.
echo  =============================================
echo   HORUSSHIELD 2.0 -- Team NullByte
echo   WE School * Alexandria
echo  =============================================
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
echo Please install Python 3.11 from https://www.python.org/downloads/
echo.
pause
exit /b 1

:found_python
cd /d "%~dp0backend"
echo [INFO] Starting HorusShield with %PYTHON_EXE%...
echo.
"%PYTHON_EXE%" app.py
pause
