@echo off
chcp 65001 >nul
setlocal
title ProxyDeck - Disable and Reset
cd /d "%~dp0"
echo.
echo ProxyDeck - Disable and Reset
echo ----------------------------
echo This will:
echo   - Cancel active discovery or testing
echo   - Restore the previous Windows system-proxy settings
echo   - Stop the local ProxyDeck UI service
echo.
echo Your proxy catalogue and source preferences will be preserved.
echo.
choice /C YN /N /M "Continue? [Y/N] "
if errorlevel 2 exit /b 0
set "PY=C:\msys64\ucrt64\bin\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" "%~dp0core.py" --disable-reset
echo.
pause
