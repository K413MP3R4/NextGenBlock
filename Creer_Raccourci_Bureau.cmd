@echo off
setlocal

cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$desktop=[Environment]::GetFolderPath('Desktop');" ^
  "$shell=New-Object -ComObject WScript.Shell;" ^
  "$lnk=$shell.CreateShortcut((Join-Path $desktop 'NextGenBlock.lnk'));" ^
  "$lnk.TargetPath=(Join-Path (Get-Location) 'Lancer_NextGenBlock.cmd');" ^
  "$lnk.WorkingDirectory=(Get-Location).Path;" ^
  "$lnk.IconLocation=(Join-Path (Get-Location) 'assets\nextgenblock.ico');" ^
  "$lnk.Description='NextGenBlock - protection reseau sans incidence';" ^
  "$lnk.Save();"

echo Raccourci cree sur le Bureau : NextGenBlock
pause
