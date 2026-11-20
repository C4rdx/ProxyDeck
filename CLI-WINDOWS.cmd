@echo off
setlocal
cd /d "%~dp0"
set "PY=C:\msys64\ucrt64\bin\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" "%~dp0core.py"
pause
