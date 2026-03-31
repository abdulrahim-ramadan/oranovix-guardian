; Inno Setup Script — Oranovix Guardian v1.0.0
; ────────────────────────────────────────────────────────────────────────────
; To compile:
;   1. Download Inno Setup (free) from: https://jrsoftware.org/isinfo.php
;   2. Open this file in Inno Setup Compiler
;   3. Press F9 (or Build → Compile)
;   4. Result: dist\Oranovix_Guardian_Setup_v1.0.exe
; ────────────────────────────────────────────────────────────────────────────

[Setup]
AppName=Oranovix Guardian
AppVersion=1.0.0
AppPublisher=Oranovix
AppPublisherURL=https://oranovix.com
AppSupportURL=https://oranovix.com/support
AppUpdatesURL=https://oranovix.com/updates
DefaultDirName={autopf}\Oranovix Guardian
DefaultGroupName=Oranovix Guardian
AllowNoIcons=yes
OutputDir=dist
OutputBaseFilename=Oranovix_Guardian_Setup_v1.0
SetupIconFile=assets\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Require Windows 10 or later
MinVersion=10.0
; 64-bit only
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main executable (PyInstaller one-file build)
Source: "dist\Oranovix Guardian.exe"; DestDir: "{app}"; Flags: ignoreversion

; Assets (icon, etc.)
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs

; Translations
Source: "translations\*"; DestDir: "{app}\translations"; Flags: ignoreversion recursesubdirs

; Default settings
Source: "settings.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist

[Icons]
; Start Menu shortcut
Name: "{group}\Oranovix Guardian";     Filename: "{app}\Oranovix Guardian.exe"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\{cm:UninstallProgram,Oranovix Guardian}"; Filename: "{uninstallexe}"

; Desktop shortcut (optional, from task above)
Name: "{autodesktop}\Oranovix Guardian"; Filename: "{app}\Oranovix Guardian.exe"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\Oranovix Guardian.exe"; Description: "{cm:LaunchProgram,Oranovix Guardian}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove settings generated at runtime
Type: files; Name: "{app}\settings.json"
Type: files; Name: "{app}\reports\output\*"
