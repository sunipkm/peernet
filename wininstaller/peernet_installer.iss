; -- peernet_installer.iss --
; Installer script to generate the peernet installer

[Setup]
AppName=PeerNet
AppVersion=3.0.0
DefaultDirName={autopf}\PeerNet
DefaultGroupName=PeerNet
UninstallDisplayIcon={app}\unins000.exe
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
ChangesEnvironment=true
OutputDir=userdocs:Inno Setup Examples Output
OutputBaseFilename=peernet_setup
SetupIconFile=p2p_icon.ico
; "ArchitecturesInstallIn64BitMode=x64" requests that the install be
; done in "64-bit mode" on x64, meaning it should use the native
; 64-bit Program Files directory and the 64-bit view of the registry.
; On all other architectures it will install in "32-bit mode".
ArchitecturesInstallIn64BitMode=x64
; Note: We don't set ProcessorsAllowed because we want this
; installation to run on all architectures (including Itanium,
; since it's capable of running 32-bit code too).

[Files]
; Install MyProg-x64.exe if running in 64-bit mode (x64; see above),
; MyProg.exe otherwise.
; Place all x64 files here
Source: "x64\*"; DestDir: "{app}"; Check: Is64BitInstallMode; Flags: ignoreversion recursesubdirs
; Place all x86 files here, first one should be marked 'solidbreak'
Source: "x86\*"; DestDir: "{app}"; Check: not Is64BitInstallMode; Flags: solidbreak ignoreversion recursesubdirs
; Place all common files here, first one should be marked 'solidbreak'
Source: "license.rtf"; DestDir: "{app}"; Flags: solidbreak
Source: "README.MD"; DestDir: "{app}"; Flags: isreadme
Source: "p2p_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Uninstall PeerNet"; Filename: "{uninstallexe}"; IconFilename: "{app}\p2p_icon.ico"

[Code]
const EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

procedure EnvAddPath(Path: string);
var
    Paths: string;
begin
    { Retrieve current path (use empty string if entry not exists) }
    if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', Paths)
    then Paths := '';

    { Skip if string already found in path }
    if Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';') > 0 then exit;

    { App string to the end of the path variable }
    Paths := Paths + ';'+ Path +';'

    { Overwrite (or create if missing) path environment variable }
    if RegWriteStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', Paths)
    then Log(Format('The [%s] added to PATH: [%s]', [Path, Paths]))
    else Log(Format('Error while adding the [%s] to PATH: [%s]', [Path, Paths]));
end;

procedure EnvRemovePath(Path: string);
var
    Paths: string;
    P: Integer;
begin
    { Skip if registry entry not exists }
    if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', Paths) then
        exit;

    { Skip if string not found in path }
    P := Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';');
    if P = 0 then exit;

    { Update path variable }
    Delete(Paths, P - 1, Length(Path) + 1);

    { Overwrite path environment variable }
    if RegWriteStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', Paths)
    then Log(Format('The [%s] removed from PATH: [%s]', [Path, Paths]))
    else Log(Format('Error while removing the [%s] from PATH: [%s]', [Path, Paths]));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
    if CurStep = ssPostInstall 
     then EnvAddPath(ExpandConstant('{app}') +'\bin');
end;

function InitializeUninstall(): Boolean;
begin
  Result := MsgBox(#13#13 'Uninstall is initializing. Do you really want to start Uninstall?', mbConfirmation, MB_YESNO) = idYes;
  if Result = False then
    MsgBox(#13#13 'Uninstall cancelled.', mbInformation, MB_OK);
end;

procedure DeinitializeUninstall();
begin
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  case CurUninstallStep of
    usUninstall:
      begin
        // ...insert code to perform pre-uninstall tasks here...
      end;
    usPostUninstall:
      begin
        EnvRemovePath(ExpandConstant('{app}') +'\bin');
        // ...insert code to perform post-uninstall tasks here...
      end;
  end;
end;
