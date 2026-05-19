@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set APP_PORT=8010
set APP_HOST=127.0.0.1
set VENV_DIR=.venv
set PYTHON_CMD=

REM Prefer stable Python versions with reliable prebuilt wheels.
for %%V in (3.12 3.11 3.10 3.13) do (
    py -%%V -c "import sys; raise SystemExit(0 if sys.version_info < (3,14) else 1)" >nul 2>nul
    if not errorlevel 1 (
        set PYTHON_CMD=py -%%V
        goto :found_python
    )
)

REM Fall back to default py only if it is not Python 3.14+.
py -3 -c "import sys; raise SystemExit(0 if sys.version_info < (3,14) else 1)" >nul 2>nul
if not errorlevel 1 (
    set PYTHON_CMD=py -3
    goto :found_python
)

echo.
echo ERROR: A compatible Python version was not found.
echo.
echo This bundle needs Python 3.10, 3.11, 3.12, or 3.13.
echo Python 3.14 is too new for some FastAPI dependencies on Windows and may try to compile Rust packages.
echo.
echo Recommended fix: install Python 3.12 for Windows, then run this start.bat again.
echo.
pause
exit /b 1

:found_python
echo Using Python launcher: %PYTHON_CMD%

REM Free the platform port before starting.
REM This handles orphaned uvicorn/python processes left behind after closing the browser or command window.
echo Checking for existing process on %APP_HOST%:%APP_PORT%...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":%APP_PORT%" ^| findstr "LISTENING"') do (
    if not "%%P"=="0" (
        echo Stopping existing process using port %APP_PORT% ^(PID %%P^)...
        taskkill /F /PID %%P >nul 2>nul
    )
)
timeout /t 1 /nobreak >nul

if exist "%VENV_DIR%\Scripts\python.exe" (
    "%VENV_DIR%\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info < (3,14) else 1)" >nul 2>nul
    if errorlevel 1 (
        echo Existing virtual environment uses Python 3.14 or newer. Rebuilding it...
        rmdir /s /q "%VENV_DIR%"
    )
)

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Creating local Python virtual environment...
    %PYTHON_CMD% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo Failed to create virtual environment.
        pause
        exit /b 1
    )
)

call "%VENV_DIR%\Scripts\activate.bat"
set NO_COLOR=1
set PY_COLORS=0
python -m pip install --upgrade pip
if errorlevel 1 goto :install_failed

python -m pip install --upgrade --upgrade-strategy eager -r requirements.txt --only-binary=:all:
if errorlevel 1 (
    echo.
    echo Binary wheel install failed. Retrying without the binary-only flag...
    python -m pip install --upgrade --upgrade-strategy eager -r requirements.txt
    if errorlevel 1 goto :install_failed
)

echo.
echo Starting Single Digits Engineering Platform on http://%APP_HOST%:%APP_PORT%
echo Press CTRL+C to stop.
echo.
start "" "http://%APP_HOST%:%APP_PORT%"
python -m uvicorn app.main:app --host %APP_HOST% --port %APP_PORT%
pause
exit /b 0

:install_failed
echo.
echo Dependency installation failed.
echo Make sure you are using Python 3.10 through 3.13, preferably Python 3.12.
echo If a broken virtual environment exists, delete the .venv folder and run start.bat again.
echo.
pause
exit /b 1
