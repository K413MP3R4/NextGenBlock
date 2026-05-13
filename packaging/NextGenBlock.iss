#define MyAppName "NextGenBlock"
#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#define MyAppPublisher "NextGenBlock"
#define MyAppExeName "NextGenBlock.exe"

[Setup]
AppId={{D4B93C64-8E9D-43D9-B548-A9A8F67B68B4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\release
OutputBaseFilename=NextGenBlock-Setup-{#MyAppVersion}
SetupIconFile=..\assets\nextgenblock.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Creer un raccourci sur le Bureau"; GroupDescription: "Raccourcis :"; Flags: checkedonce
Name: "startup"; Description: "Demarrer NextGenBlock avec Windows"; GroupDescription: "Options :"; Flags: unchecked

[Files]
Source: "..\dist\NextGenBlock\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NextGenBlock"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\assets\nextgenblock.ico"
Name: "{commondesktop}\NextGenBlock"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\assets\nextgenblock.ico"; Tasks: desktopicon
Name: "{group}\Desinstaller NextGenBlock"; Filename: "{uninstallexe}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NextGenBlock"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Lancer NextGenBlock"; Flags: nowait postinstall skipifsilent
