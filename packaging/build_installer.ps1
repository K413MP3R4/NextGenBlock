param(
    [string]$Python = "python",
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Spec = Join-Path $Root "packaging\NextGenBlock.spec"
$Iss = Join-Path $Root "packaging\NextGenBlock.iss"
$Release = Join-Path $Root "release"

Set-Location $Root

try {
    & $Python -m PyInstaller --version | Out-Null
} catch {
    throw "PyInstaller est introuvable. Installe-le avec : $Python -m pip install pyinstaller"
}

Remove-Item -LiteralPath (Join-Path $Root "build") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Root "dist") -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Release | Out-Null

& $Python -m PyInstaller $Spec --noconfirm --clean

$isccCandidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $iscc) {
    throw "Inno Setup 6 est introuvable. Installe-le puis relance ce script : https://jrsoftware.org/isdl.php"
}

& $iscc "/DMyAppVersion=$Version" $Iss

Write-Host ""
Write-Host "Installateur cree dans : $Release" -ForegroundColor Green
