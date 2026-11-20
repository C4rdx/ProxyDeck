@echo off
setlocal
cd /d "%~dp0"
wscript.exe //nologo "%~dp0RUN-WINDOWS.vbs"
exit /b 0
