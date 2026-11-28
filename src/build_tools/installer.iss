; Inno Setup Script — Oranovix Guardian v1.2.0
; ────────────────────────────────────────────────────────────────────────────
; To compile:
;   1. Download Inno Setup (free) from: https://jrsoftware.org/isinfo.php
;   2. Build the app first: src\build_tools\build.ps1 -NoInstaller
;      (or run build.ps1 without switches, which also compiles this file)
;   3. Open this file in Inno Setup Compiler and press F9
;   4. Result: dist\Oranovix_Guardian_Setup_v1.2.0.exe
;
; The installer ships the one-folder build (dist\Oranovix Guardian\). A
; one-file exe runs as a windowless bootloader plus the app; Restart
; Manager cannot close the bootloader, so an update failed with
; "DeleteFile failed; code 5".
;
; The app is installed to Program Files, which a normal user cannot write
; to. Nothing is written into {app} at runtime: settings, databases,
; custom rules and reports live in %LOCALAPPDATA%\Oranovix Guardian
; (core/app_paths.py) and are kept by an update. Default settings come
; from the code.
; ────────────────────────────────────────────────────────────────────────────

[Setup]
AppName=Oranovix Guardian
; Paths below are relative to the project root, not to src/build_tools.
SourceDir=..\..
AppVersion=1.2.0
AppPublisher=Oranovix
AppPublisherURL=https://oranovix.com
AppSupportURL=https://oranovix.com/support
AppUpdatesURL=https://oranovix.com/updates
DefaultDirName={autopf}\Oranovix Guardian
DefaultGroupName=Oranovix Guardian
AllowNoIcons=yes
OutputDir=dist
OutputBaseFilename=Oranovix_Guardian_Setup_v1.2.0
SetupIconFile=assets\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Require Windows 10 or later
MinVersion=10.0
; 64-bit only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; The running app holds these mutexes (core/single_instance.py, RunningMarker).
; Setup and the uninstaller check them before anything is copied or removed
; and ask to close the app (messages below).
AppMutex=OranovixGuardianRunning,Global\OranovixGuardianRunning
; Restart Manager closes what still holds a file that is replaced; the app
; answers with its own clean close. It is not started again by Setup.
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
SetupAppRunningError=Oranovix Guardian is running, please close it.%n%nClose Oranovix Guardian, then click OK to continue, or Cancel to exit.
UninstallAppRunningError=Oranovix Guardian is running, please close it.%n%nClose Oranovix Guardian, then click OK to continue, or Cancel to exit.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; An update starts from a clean program folder: the bundle of the previous
; version (_internal) and the loose folders older versions installed next to their
; one-file exe. The user's data folder is not touched.
Type: filesandordirs; Name: "{app}\_internal"
Type: filesandordirs; Name: "{app}\assets"
Type: filesandordirs; Name: "{app}\translations"

[Files]
; The whole one-folder build: Oranovix Guardian.exe and _internal\ (Python,
; libraries, assets, translations, default rules).
Source: "dist\Oranovix Guardian\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu shortcut (the icon is the exe's own)
Name: "{group}\Oranovix Guardian";     Filename: "{app}\Oranovix Guardian.exe"
Name: "{group}\{cm:UninstallProgram,Oranovix Guardian}"; Filename: "{uninstallexe}"

; Desktop shortcut (optional, from task above)
Name: "{autodesktop}\Oranovix Guardian"; Filename: "{app}\Oranovix Guardian.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Oranovix Guardian.exe"; Description: "{cm:LaunchProgram,Oranovix Guardian}"; Flags: nowait postinstall skipifsilent

; No [UninstallDelete]: the app writes nothing into {app}. The user's data
; folder (%LOCALAPPDATA%\Oranovix Guardian) is kept on uninstall.
