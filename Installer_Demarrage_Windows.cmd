@echo off
setlocal

cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$startup=[Environment]::GetFolderPath('Startup');" ^
  "$shell=New-Object -ComObject WScript.Shell;" ^
  "$lnk=$shell.CreateShortcut((Join-Path $startup 'NextGenBlock.lnk'));" ^
  "$lnk.TargetPath=(Join-Path (Get-Location) 'Lancer_NextGenBlock.cmd');" ^
  "$lnk.WorkingDirectory=(Get-Location).Path;" ^
  "$lnk.IconLocation=(Join-Path (Get-Location) 'assets\nextgenblock.ico');" ^
  "$lnk.Description='NextGenBlock - demarrage automatique';" ^
  "$lnk.Save();"

echo NextGenBlock demarrera avec Windows.
pause
