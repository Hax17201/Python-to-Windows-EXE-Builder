@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 py_to_exe_gui.py
    goto :end
)

where python >nul 2>nul
if %errorlevel%==0 (
    python py_to_exe_gui.py
    goto :end
)

echo.
echo ERROR: Python 3 was not found in PATH.
echo Install Python from https://www.python.org/downloads/windows/
echo and enable "Add python.exe to PATH" during installation.
echo.
pause

:end
endlocal
