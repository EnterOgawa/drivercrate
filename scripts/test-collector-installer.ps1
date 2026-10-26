#requires -Version 7.0
<#
.SYNOPSIS
実生成単体EXEの閉包・改変拒否・新規fixture配置・固定runtime・保持解除を非通信で検査する。
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
入力EXEを変更せず、outの新規fixture内のcopyだけを改変する。全fixtureとstagingを保持する。
defaultはcheck-onlyで、現行v7正常install/解除はNOT_RUNとする。実Taskの有限試験は
-AllowTaskRegistrationで専用integrationへ委譲する。旧Task、鍵、署名、HTTP、GitHub、driverは扱わない。
defaultはstagingを作成・探索しない。旧三staging全byte比較は別の実EXE受入へ残す。
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string] $InstallerExecutable,
    [Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][string] $FixtureRoot,
    [string] $BuildDirectory = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../build'))),
    [switch] $AllowTaskRegistration)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
$context = Resolve-IndexPackageBuild -BuildDirectory $BuildDirectory -RequireCollector
Import-Module (Join-Path $repo 'packaging/collector/collector-setup.psm1') -Force -DisableNameChecking
$installer = Assert-IndexPackagePath -Path $InstallerExecutable
$bundle = Read-CollectorBundle $PackageDirectory
$root = Assert-IndexPackageOutput -Context $context -Path $FixtureRoot -Fresh
Assert-IndexPackageDistinctPaths -Paths @($bundle.Root, $root, $installer)
[void][IO.Directory]::CreateDirectory($root)
if ($AllowTaskRegistration) {
    & (Join-Path $PSScriptRoot 'test-collector-user-task-integration.ps1') -PackageDirectory $bundle.Root `
        -InstallerExecutable $installer -FixtureRoot (Join-Path $root 'user-task-integration') -AllowTaskRegistration
    return
}
$utf8 = [Text.UTF8Encoding]::new($false)
$script:checks = 0
$script:calls = 0
$script:cases = [ordered]@{}
function Check([bool] $Condition, [string] $Reason) {
    ++$script:checks
    if (-not $Condition) { throw ('INSTALLER_TEST_' + $Reason) }
}
function Native([string] $Executable, [string[]] $Arguments, [int] $Expected, [string] $Case) {
    $start = [Diagnostics.ProcessStartInfo]::new($Executable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $began = [DateTimeOffset]::UtcNow
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timeout = -not $process.WaitForExit(180000)
        if ($timeout) { $process.Kill($true); [void]$process.WaitForExit(5000) }
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        $code = $process.ExitCode
        $prefix = Join-Path $root ('process-' + $script:calls++)
        [IO.File]::WriteAllText(($prefix + '.stdout'), $out, $utf8)
        [IO.File]::WriteAllText(($prefix + '.stderr'), $err, $utf8)
        [IO.File]::WriteAllText(($prefix + '.json'), ([ordered]@{ case = $Case; executable = $Executable
            arguments = $Arguments; expectedExit = $Expected; exitCode = $code; timedOut = $timeout
            startedUtc = $began.ToString('o'); finishedUtc = [DateTimeOffset]::UtcNow.ToString('o') } | ConvertTo-Json), $utf8)
        Check (-not $timeout -and $code -eq $Expected -and $out.Length -lt 65536 -and $err.Length -lt 65536) ($Case + '_EXIT')
        return $out
    } finally { $process.Dispose() }
}

# datafileだけとしてPEを読み、test copyのresourceまたはcompile時tableを変更する。
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
public static class CollectorResourceFixture {
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
    [DllImport("kernel32", SetLastError=true)] static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr FindResourceExW(IntPtr module, IntPtr type, IntPtr name, ushort language);
    [DllImport("kernel32", SetLastError=true)] static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32", SetLastError=true)] static extern IntPtr LockResource(IntPtr loaded);
    [DllImport("kernel32", SetLastError=true)] static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr BeginUpdateResourceW(string path, bool delete);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool UpdateResourceW(IntPtr update, IntPtr type, IntPtr name, ushort language, byte[] data, uint bytes);
    [DllImport("kernel32", SetLastError=true)] static extern bool EndUpdateResourceW(IntPtr update, bool discard);
    [DllImport("advapi32", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetNamedSecurityInfoW(string path, uint type, uint information, out IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("kernel32")] static extern IntPtr LocalFree(IntPtr memory);
    [StructLayout(LayoutKind.Sequential)] struct Attributes { public int length; public IntPtr descriptor; public int inherit; }
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectoryW(string path, ref Attributes attributes);
    public static void ProtectedDirectory(string path, string template) {
        IntPtr owner, dacl, descriptor;
        uint error=GetNamedSecurityInfoW(template,1,5,out owner,IntPtr.Zero,out dacl,IntPtr.Zero,out descriptor);
        if(error!=0) throw new Win32Exception(checked((int)error));
        try {
            Attributes attributes=new Attributes { length=Marshal.SizeOf<Attributes>(), descriptor=descriptor, inherit=0 };
            if(!CreateDirectoryW(path,ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { LocalFree(descriptor); }
    }
    public static byte[] Read(string path, int id) {
        IntPtr module=LoadLibraryExW(path, IntPtr.Zero, 0x22);
        if(module==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr resource=FindResourceExW(module, new IntPtr(10), new IntPtr(id), 0);
            uint length=SizeofResource(module, resource);
            if(resource==IntPtr.Zero || length==0 || length>67108864) throw new InvalidDataException("FIXTURE_RESOURCE");
            byte[] bytes=new byte[length];
            Marshal.Copy(LockResource(LoadResource(module, resource)), bytes, 0, checked((int)length));
            return bytes;
        } finally { FreeLibrary(module); }
    }
    public static void Write(string path, int id, ushort language, byte[] data) {
        IntPtr update=BeginUpdateResourceW(path, false);
        if(update==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        if(!UpdateResourceW(update, new IntPtr(10), new IntPtr(id), language, data, data==null ? 0u : checked((uint)data.Length))) {
            int error=Marshal.GetLastWin32Error(); EndUpdateResourceW(update,true); throw new Win32Exception(error);
        }
        if(!EndUpdateResourceW(update,false)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    static int ResourceOffset(byte[] bytes) {
        int pe=BitConverter.ToInt32(bytes,0x3c);
        int count=BitConverter.ToUInt16(bytes,pe+6);
        int section=pe+24+BitConverter.ToUInt16(bytes,pe+20);
        for(int i=0;i<count;i++,section+=40) {
            if(Encoding.ASCII.GetString(bytes,section,8).TrimEnd('\0')==".rsrc") return checked((int)BitConverter.ToUInt32(bytes,section+20));
        }
        throw new InvalidDataException("FIXTURE_RSRC_SECTION");
    }
    static int Find(byte[] bytes, byte[] pattern) {
        int stop=ResourceOffset(bytes)-pattern.Length;
        int found=-1;
        for(int i=0;i<=stop;i++) {
            bool same=true;
            for(int j=0;j<pattern.Length;j++) { if(bytes[i+j]!=pattern[j]) {same=false;break;} }
            if(same) { if(found!=-1) throw new InvalidDataException("FIXTURE_AMBIGUOUS_PATTERN"); found=i; }
        }
        if(found<0) throw new InvalidDataException("FIXTURE_PATTERN_MISSING");
        return found;
    }
    public static void Path(string path, string from, string to) {
        byte[] bytes=File.ReadAllBytes(path);
        byte[] original=Encoding.Unicode.GetBytes(from+"\0"), replacement=Encoding.Unicode.GetBytes(to+"\0");
        if(original.Length!=replacement.Length) throw new InvalidDataException("FIXTURE_PATH_LENGTH");
        replacement.CopyTo(bytes,Find(bytes,original)); File.WriteAllBytes(path,bytes);
    }
    public static void Size(string path, ushort id, ulong originalSize, ulong newSize) {
        byte[] bytes=File.ReadAllBytes(path), pattern=new byte[16];
        BitConverter.GetBytes(id).CopyTo(pattern,0); BitConverter.GetBytes(originalSize).CopyTo(pattern,8);
        BitConverter.GetBytes(newSize).CopyTo(bytes,Find(bytes,pattern)+8); File.WriteAllBytes(path,bytes);
    }
}
'@
function Mutant([string] $Name) {
    $path = Join-Path $root ($Name + '.exe')
    [IO.File]::Copy($installer, $path, $false)
    return $path
}
$originalHash = Get-CollectorSetupHash $installer
$result = Native $installer @('--check-embedded') 0 'B01'
Check ($result.Contains('files=' + (@($bundle.Manifest.files).Count + 1)) -and $result.Contains('child_started=0') -and $result.Contains('network=0')) 'B01_CLOSED'
$script:cases.B01 = 'PASS'
# payloadとmanifestを別々に一byte変更し、子起動前のhash拒否を実EXEで検証する。
foreach ($id in @(4000, (4000 + @($bundle.Manifest.files).Count))) {
    $path = Mutant ('byte-' + $id)
    $bytes = [CollectorResourceFixture]::Read($path, $id)
    $bytes[0] = $bytes[0] -bxor 1
    [CollectorResourceFixture]::Write($path, $id, 0, $bytes)
    $result = Native $path @('--check-embedded') 2 'B02'
    Check ($result.Contains('EMBEDDED_RESOURCE_HASH') -and -not $result.Contains('SETUP_STAGING')) 'B02_NO_STAGING'
}
$script:cases.B02 = 'PASS'
foreach ($kind in @('missing', 'unknown', 'language', 'duplicate-path')) {
    $path = Mutant $kind
    switch ($kind) {
        'missing' { [CollectorResourceFixture]::Write($path, 4000, 0, $null) }
        'unknown' { [CollectorResourceFixture]::Write($path, 5000, 0, [byte[]]@(1,2,3)) }
        'language' { [CollectorResourceFixture]::Write($path, 4000, 1033, [CollectorResourceFixture]::Read($path, 4000)) }
        'duplicate-path' { [CollectorResourceFixture]::Path($path, 'Collect.cmd', 'Install.cmd') }
    }
    $result = Native $path @('--check-embedded') 2 'B03'
    Check (-not $result.Contains('SETUP_STAGING')) 'B03_NO_STAGING'
}
$script:cases.B03 = 'PASS'
# compile時table自体の不正を含め、hash検査より先のpath/size境界を実EXEで確認する。
foreach ($name in @('../badx.cmd', 'C:/badx.cmd', '//badxx.cmd', 'ad:badx.cmd')) {
    $path = Mutant ('path-' + $script:calls)
    [CollectorResourceFixture]::Path($path, 'Collect.cmd', $name)
    $result = Native $path @('--check-embedded') 2 'B04'
    Check (-not $result.Contains('SETUP_STAGING')) 'B04_NO_STAGING'
}
foreach ($kind in @('file-limit', 'total-limit', 'size-mismatch', 'overflow')) {
    $path = Mutant $kind
    [ushort]$id = 4000
    [ulong]$old = [CollectorResourceFixture]::Read($path, 4000).Length
    [ulong]$size = 67108865
    if ($kind -eq 'total-limit') { $id = 4077; $old = [CollectorResourceFixture]::Read($path, 4077).Length; $size = 67108864 }
    if ($kind -eq 'size-mismatch') { $size = $old + 1 }
    if ($kind -eq 'overflow') { $size = [ulong]::MaxValue }
    [CollectorResourceFixture]::Size($path, $id, $old, $size)
    $result = Native $path @('--check-embedded') 2 'B04'
    Check (-not $result.Contains('SETUP_STAGING')) 'B04_SIZE_NO_STAGING'
}
$script:cases.B04 = 'PASS_WITH_HELPER_COUNT_BOUNDARY'
# 誤CLIは内部setupへ委譲せず、現行v7通常installの成功経路を実行しない。
foreach ($arguments in @(@('--unknown'), @('--check-embedded', 'extra'), @('--install', 'relative'),
    @('--install', (Join-Path $root 'not-created'), '--bad-consent'))) {
    $result = Native $installer $arguments 2 'B08_CLI'
    Check (-not $result.Contains('SETUP_STAGING')) 'B08_CLI_NO_STAGING'
}
$script:cases.B08 = 'PASS_INVALID_CLI_ONLY_VALID_INSTALL_NOT_RUN'
# 最新現行v7の正常installは実Taskを作る。defaultをTask0の正常配置試験へ読み替えない。
foreach ($case in @('B05','B06','B07','B09','B10','V01','V02','V03','V04','V05','V06','V07','L01','L12_BUNDLED_IMPORT')) {
    $script:cases[$case] = 'NOT_RUN_LIVE_CASE_OR_SEPARATE_REGRESSION_REQUIRED'
}
$summary = [ordered]@{ schema = 'dc-collector-installer-fixture-v2'; result = 'PASS_CHECK_ONLY_INTEGRATION_NOT_RUN'
    checks = $script:checks; processCalls = $script:calls; cases = $script:cases; fixture = $root
    installerSha256 = $originalHash; network = 0; tasks = 0; realInstall = 'NOT_RUN'; realUninstall = 'NOT_RUN'
    integration = 'scripts/test-collector-user-task-integration.ps1 -AllowTaskRegistration' }
[IO.File]::WriteAllText((Join-Path $root 'result.json'), ($summary | ConvertTo-Json -Depth 8), $utf8)
$summary | ConvertTo-Json -Depth 8
return
