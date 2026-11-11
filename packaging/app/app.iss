; DriverCrate App. Author: Shunji Ogawa.
; Copyright (c) 2026 EnterSystem CO.,LTD.
; SPDX-License-Identifier: Apache-2.0
; Inno manages only the five App files and its own shortcuts/uninstaller.
#ifndef BundleDir
  #error BundleDir is required
#endif
#ifndef DestinationDir
  #error DestinationDir is required
#endif
#ifndef ProductVersion
  #error ProductVersion is required
#endif
#define AppImage AddBackslash(BundleDir) + "DriverCrate.exe"
#if GetStringFileInfo(AppImage, "ProductName") != "DriverCrate"
  #error The payload must be the DriverCrate App
#endif
#if GetVersionNumbersString(AppImage) != ProductVersion + ".0"
  #error App payload and Setup versions must agree
#endif
#define AppMS 0
#define AppLS 0
#expr GetVersionNumbers(AppImage, AppMS, AppLS)

[Setup]
#ifdef AppSetupTestMode
AppId={{C3F4109D-57CB-4811-909E-59CE00F2F9E6}
AppName=DriverCrate App Setup Test
DefaultDirName={localappdata}\Programs\DriverCrateAppSetupTest
#else
AppId={{3158ED66-084C-491D-BE82-42B8E49D4679}
AppName=DriverCrate
DefaultDirName={localappdata}\Programs\DriverCrate
#endif
AppVersion={#ProductVersion}
AppPublisher=Shunji Ogawa
AppCopyright=Copyright (c) 2026 EnterSystem CO.,LTD.
AppPublisherURL=https://github.com/EnterOgawa/drivercrate
AppSupportURL=https://github.com/EnterOgawa/drivercrate/issues
PrivilegesRequired=lowest
UseSetupLdr=x64
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0
DefaultGroupName=DriverCrate
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
AllowRootDirectory=no
AllowUNCPath=no
AllowNetworkDrive=no
OutputDir={#DestinationDir}
OutputBaseFilename=DriverCrateSetup-windows-x64
VersionInfoVersion={#ProductVersion}
VersionInfoProductVersion={#ProductVersion}
VersionInfoProductName=DriverCrate
VersionInfoDescription=DriverCrate Setup
SetupIconFile=..\..\src\app\assets\drivercrate.ico
LicenseFile={#BundleDir}\LICENSE
UninstallDisplayIcon={app}\DriverCrate.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupMutex=Local\DriverCrate.App.Setup
CloseApplications=no
RestartApplications=no
SetupLogging=no
#ifdef SignAppSetup
SignTool=DriverCrateAppEV
SignedUninstaller=yes
SignedUninstallerDir={#SigningWorkspace}
SignToolRetryCount=0
#endif

[Languages]
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"

[CustomMessages]
japanese.CloseApp=DriverCrateを終了してから、もう一度実行してください。ドライバー処理を強制終了しないでください。
japanese.BusyFile=アプリのファイルが使用中、または確認できない状態です。DriverCrateを終了し、保存先を確認してください。
japanese.UserArea=インストール先には、このユーザーのAppData\Local内のフォルダーを指定してください。
japanese.InvalidApp=同名のEXEをDriverCrateとして確認できません。別のフォルダーを選ぶか、ファイルを確認してください。
japanese.NewerApp=新しいバージョンがあるため、この古いインストーラーでは上書きできません。
japanese.LaunchApp=DriverCrateを起動する
japanese.DesktopIcon=デスクトップにショートカットを作成する

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked

[Files]
Source: "{#BundleDir}\DriverCrate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BundleDir}\DriverCrate.exe.index-profile.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BundleDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BundleDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BundleDir}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

#ifndef AppSetupTestMode
[Icons]
Name: "{userprograms}\DriverCrate"; Filename: "{app}\DriverCrate.exe"; WorkingDir: "{app}"
Name: "{userdesktop}\DriverCrate"; Filename: "{app}\DriverCrate.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\DriverCrate.exe"; Description: "{cm:LaunchApp}"; Flags: postinstall shellexec nowait skipifsilent
#endif

[Messages]
japanese.ConfirmUninstall=DriverCrateのプログラムを削除しますか？%n%n設定、ログ、収集管理と収集データは保持します。

[Code]
function FileAttributes(const Name: String): Cardinal;
  external 'GetFileAttributesW@kernel32.dll stdcall';
function ExclusiveRead(const Name: String; Access, Share, Security, Disposition, Flags: Cardinal; Template: THandle): THandle;
  external 'CreateFileW@kernel32.dll stdcall';
function CloseOwnedHandle(Value: THandle): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';
function VersionInfoSize(const Name: String; var Ignored: Cardinal): Cardinal;
  external 'GetFileVersionInfoSizeW@version.dll stdcall';
function ReadVersionInfo(const Name: String; Ignored, Size: Cardinal; Buffer: String): Boolean;
  external 'GetFileVersionInfoW@version.dll stdcall';
function QueryVersion(const Buffer, Query: String; var Value: THandle; var Size: Cardinal): Boolean;
  external 'VerQueryValueW@version.dll stdcall';
procedure CopyVersionNumber(var Destination: Cardinal; Source: THandle; Size: Cardinal);
  external 'RtlMoveMemory@kernel32.dll stdcall';
procedure CopyVersionText(Destination: String; Source: THandle; Size: Cardinal);
  external 'RtlMoveMemory@kernel32.dll stdcall';

function ProductName(const Name: String): String;
var
  Size, Ignored, Bytes, Translation: Cardinal;
  Buffer, Query, Text: String;
  Value: THandle;
begin
  Result := '';
  Ignored := 0;
  Size := VersionInfoSize(Name, Ignored);
  if (Size = 0) or (Size > 65536) then Exit;
  SetLength(Buffer, (Size + 1) div 2);
  if not ReadVersionInfo(Name, 0, Size, Buffer) then Exit;
  if not QueryVersion(Buffer, '\VarFileInfo\Translation', Value, Bytes) then Exit;
  if (Bytes < 4) or (Bytes > 64) then Exit;
  CopyVersionNumber(Translation, Value, 4);
  Query := Format('\StringFileInfo\%4.4x%4.4x\ProductName', [Translation and $FFFF, Translation shr 16]);
  if not QueryVersion(Buffer, Query, Value, Bytes) then Exit;
  if (Bytes < 2) or (Bytes > 256) then Exit;
  SetLength(Text, Bytes);
  CopyVersionText(Text, Value, Bytes * 2);
  SetLength(Text, Bytes - 1);
  Result := Text;
end;

function UserDirectory(const Directory: String): Boolean;
var
  Root, Target, Current: String;
  Position: Integer;
  Attributes: Cardinal;
begin
  Root := AddBackslash(ExpandFileName(ExpandConstant('{localappdata}')));
  Target := RemoveBackslashUnlessRoot(ExpandFileName(Directory));
  Result := (Length(Target) > Length(Root)) and
    (CompareText(Copy(Target, 1, Length(Root)), Root) = 0);
  if not Result then Exit;
  { Existing parent components must not redirect the fixed user scope. }
  Current := RemoveBackslashUnlessRoot(Root);
  Position := Length(Root);
  while Position <= Length(Target) do
  begin
    if (Position = Length(Target)) or (Target[Position + 1] = '\') then
    begin
      Current := Copy(Target, 1, Position);
      Attributes := FileAttributes(Current);
      if (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0) then
      begin
        Result := False;
        Exit;
      end;
    end;
    Position := Position + 1;
  end;
end;

function AppBusy(): String;
var
  Index: Integer;
  Name: String;
  Image: THandle;
begin
  Result := '';
  if CheckForMutexes('Local\DriverCrate.App') or
     (FindWindowByClassName('DriverCrate.MainWindow') <> 0) then
  begin
    Result := CustomMessage('CloseApp');
    Exit;
  end;
  { Only the two App files are checked. Collector/data/log are never traversed. }
  for Index := 0 to 1 do
  begin
    if Index = 0 then Name := 'DriverCrate.exe'
    else Name := 'DriverCrate.exe.index-profile.json';
    Name := AddBackslash(ExpandConstant('{app}')) + Name;
    if FileExists(Name) then
    begin
      if (FileAttributes(Name) and $400) <> 0 then
      begin
        Result := CustomMessage('BusyFile');
        Exit;
      end;
      Image := ExclusiveRead(Name, $80000000, 0, 0, 3, $200000, 0);
      if Image = THandle($FFFFFFFF) then
      begin
        Result := CustomMessage('BusyFile');
        Exit;
      end;
      CloseOwnedHandle(Image);
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Name: String;
  MajorMinor, PatchBuild: Cardinal;
begin
  Result := '';
  if not UserDirectory(ExpandConstant('{app}')) then
  begin
    Result := CustomMessage('UserArea');
    Exit;
  end;
  Result := AppBusy();
  if Result <> '' then Exit;
  Name := AddBackslash(ExpandConstant('{app}')) + 'DriverCrate.exe';
  if FileExists(Name) then
  begin
    if (ProductName(Name) <> 'DriverCrate') or
       not GetVersionNumbers(Name, MajorMinor, PatchBuild) then
    begin
      Result := CustomMessage('InvalidApp');
      Exit;
    end;
    if (MajorMinor > {#AppMS}) or
       ((MajorMinor = {#AppMS}) and (PatchBuild > {#AppLS})) then
      Result := CustomMessage('NewerApp');
  end;
end;

function InitializeUninstall(): Boolean;
var
  Reason: String;
begin
  Reason := AppBusy();
  Result := Reason = '';
  if not Result then
    MsgBox(Reason, mbInformation, MB_OK);
end;
