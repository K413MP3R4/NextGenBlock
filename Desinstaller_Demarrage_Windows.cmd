@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$shortcut=Join-Path ([Environment]::GetFolderPath('Startup')) 'NextGenBlock.lnk';" ^
  "if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }"

echo NextGenBlock ne demarrera plus automatiquement avec Windows.
pause
