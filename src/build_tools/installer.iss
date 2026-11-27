; Inno Setup Script — Oranovix Guardian v1.1.0
; ────────────────────────────────────────────────────────────────────────────
; To compile:
;   1. Download Inno Setup (free) from: https://jrsoftware.org/isinfo.php
;   2. Open this file in Inno Setup Compiler
;   3. Press F9 (or Build → Compile)
;   4. Result: dist\Oranovix_Guardian_Setup_v1.1.0.exe
;
; The app is installed to Program Files, which a normal user cannot write
; to. Nothing is written into {app} at runtime: settings, databases,
; custom rules and reports live in %LOCALAPPDATA%\Oranovix Guardian
; (core/app_paths.py). Default settings come from the code.
; ────────────────────────────────────────────────────────────────────────────

[Setup]
AppName=Oranovix Guardian
; Paths below are relative to the project root, not to src/build_tools.
SourceDir=..\..
AppVersion=1.1.0
AppPublisher=Oranovix
AppPublisherURL=https://oranovix.com
AppSupportURL=https://oranovix.com/support
AppUpdatesURL=https://oranovix.com/updates
DefaultDirName={autopf}\Oranovix Guardian
DefaultGroupName=Oranovix Guardian
AllowNoIcons=yes
OutputDir=dist
OutputBaseFilename=Oranovix_Guardian_Setup_v1.1.0
SetupIconFile=assets\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Require Windows 10 or later
MinVersion=10.0
; 64-bit only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

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
Source: "src\oranovix_guardian\translations\*"; DestDir: "{app}\translations"; Flags: ignoreversion recursesubdirs

[Icons]
; Start Menu shortcut
Name: "{group}\Oranovix Guardian";     Filename: "{app}\Oranovix Guardian.exe"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\{cm:UninstallProgram,Oranovix Guardian}"; Filename: "{uninstallexe}"

; Desktop shortcut (optional, from task above)
Name: "{autodesktop}\Oranovix Guardian"; Filename: "{app}\Oranovix Guardian.exe"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\Oranovix Guardian.exe"; Description: "{cm:LaunchProgram,Oranovix Guardian}"; Flags: nowait postinstall skipifsilent

; No [UninstallDelete]: the app writes nothing into {app}. The user's data
; folder (%LOCALAPPDATA%\Oranovix Guardian) is kept on uninstall.
