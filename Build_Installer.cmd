@echo off
setlocal

cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\build_installer.ps1"
pause
