# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_submodules
from pathlib import Path


block_cipher = None
root = Path(SPECPATH).resolve().parent

hiddenimports = []
hiddenimports += collect_submodules("pydivert")

a = Analysis(
    [str(root / "NextGenBlock.pyw")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "assets" / "nextgenblock.ico"), "assets"),
        (str(root / "assets" / "nextgenblock.png"), "assets"),
        (str(root / "LICENSE"), "."),
        (str(root / "README.md"), "."),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NextGenBlock",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(root / "assets" / "nextgenblock.ico"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="NextGenBlock",
)
