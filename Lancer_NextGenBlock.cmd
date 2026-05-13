@echo off
setlocal

cd /d "%~dp0"

set "NGB_AUTO_START=1"
set "NGB_AUTO_HIDE_SECONDS=5"

set "PYTHONW=%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe"
if not exist "%PYTHONW%" set "PYTHONW=pythonw.exe"

start "" "%PYTHONW%" "%~dp0NextGenBlock.pyw"
exit /b 0
