; Inno Setup script for Watchtower AV  (https://jrsoftware.org/isinfo.php)
; Built by build_installer.bat or the GitHub Actions workflow.

#define AppName "Watchtower AV"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define AppPublisher "Watchtower AV contributors"
#define AppExe "WatchtowerAV.exe"

[Setup]
AppId={{3B8E5D71-2C4A-4F9B-A6D3-7E1F0C92B548}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Watchtower AV
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=WatchtowerAV-Setup-{#AppVersion}
SetupIconFile=..\assets\watchtower.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
CloseApplications=force

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "autostart"; Description: "Start real-time protection when I sign in (recommended)"; GroupDescription: "Protection:"

[Dirs]
; Shared data folder; users can read, only admins can change signatures/rules
Name: "{commonappdata}\WatchtowerAV"
Name: "{commonappdata}\WatchtowerAV\rules"
Name: "{commonappdata}\WatchtowerAV\quarantine"; Permissions: admins-full system-full
Name: "{commonappdata}\WatchtowerAV\logs"; Permissions: users-modify

[Files]
Source: "..\dist\WatchtowerAV.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\watchtower.exe";   DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";         DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\LICENSE";           DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";           Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";     Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Add CLI folder to the system PATH so `watchtower quick` works in any terminal
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}'))
; Right-click "Scan with Watchtower AV" on files and folders
Root: HKCR; Subkey: "*\shell\WatchtowerScan"; ValueType: string; ValueData: "Scan with Watchtower AV"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\WatchtowerScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe}"
Root: HKCR; Subkey: "*\shell\WatchtowerScan\command"; ValueType: string; ValueData: """{app}\watchtower.exe"" scan ""%1"" --pause"
Root: HKCR; Subkey: "Directory\shell\WatchtowerScan"; ValueType: string; ValueData: "Scan with Watchtower AV"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\WatchtowerScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe}"
Root: HKCR; Subkey: "Directory\shell\WatchtowerScan\command"; ValueType: string; ValueData: """{app}\watchtower.exe"" scan ""%1"" --pause"

[Run]
; Autostart elevated at sign-in via Task Scheduler (a Run key can't elevate silently)
Filename: "schtasks.exe"; \
    Parameters: "/Create /F /TN ""Watchtower AV"" /SC ONLOGON /RL HIGHEST /TR ""\""{app}\{#AppExe}\"" --minimized"""; \
    Flags: runhidden; Tasks: autostart
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN ""Watchtower AV"""; Flags: runhidden; RunOnceId: "DelTask"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\WatchtowerAV\logs"

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if MsgBox('Also delete quarantined files and custom signatures/rules?',
              mbConfirmation, MB_YESNO) = IDYES then
      DelTree(ExpandConstant('{commonappdata}\WatchtowerAV'), True, True, True);
end;
