#requires -Version 5.1
<#
.SYNOPSIS
Runs finite non-network installer fixtures inside work/tmp only.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Uses a synthetic PE; never executes it or registers tasks. Retains fixtures for inspection.
#>
param([string] $SetupExecutable)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$source = Join-Path $repo 'packaging\collector'
Import-Module (Join-Path $source 'collector-setup.psm1') -Force -DisableNameChecking
$script:Checks = 0
function Check([bool] $Condition) {
    if (-not $Condition) { throw ('FIXTURE_CHECK_' + $script:Checks) }
    ++$script:Checks
}
function Reject([scriptblock] $Action, [string] $Reason) {
    $observed = ''
    try { & $Action | Out-Null } catch { $observed = $_.Exception.Message }
    Check ($observed -ceq $Reason)
}
$temporary = Join-Path $repo ('work\tmp\collector-setup-' + [Guid]::NewGuid().ToString('N'))
$package = Join-Path $temporary 'package'
[void][IO.Directory]::CreateDirectory($package)
$utf8 = New-Object Text.UTF8Encoding($false)
function Save-Json([string] $Path, $Body) {
    [IO.File]::WriteAllText($Path, ($Body | ConvertTo-Json -Depth 8), $utf8)
}
$rows = @()
# 固定managed file全件から合成packageとhash行を作る。明示setupは実file、未指定setupとcollectorは非実行synthetic x64 PE、configは固定正本、残りは合成textへ分ける。
foreach ($relative in @(Get-CollectorPayloadFiles)) {
    $target = Join-Path $package $relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    if ($relative -ceq 'DriverCrateCollectorSetup.exe' -and $SetupExecutable) {
        [IO.File]::Copy($SetupExecutable, $target)
    }
    elseif ($relative -ceq 'bin/DriverCrateCollector.exe' -or $relative -ceq 'DriverCrateCollectorSetup.exe') {
        $bytes = New-Object byte[] 128
        $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[0x3c] = 0x40
        $bytes[0x40] = 0x50; $bytes[0x41] = 0x45; $bytes[0x44] = 0x64; $bytes[0x45] = 0x86
        $bytes[0x58] = 0x0b; $bytes[0x59] = 0x02
        [IO.File]::WriteAllBytes($target, $bytes)
    }
    elseif ($relative -ceq 'config/targets.json') { [IO.File]::Copy((Join-Path $source 'targets.json'), $target) }
    else { [IO.File]::WriteAllText($target, 'synthetic managed file', $utf8) }
    $rows += [ordered]@{ path = $relative; sha256 = Get-CollectorSetupHash $target
        bytes = (Get-Item -LiteralPath $target).Length }
}
$manifestPath = Join-Path $package 'package-manifest.json'
$manifest = [ordered]@{ schema = 'dc-collector-package-v1'; version = '0.1.0'
    architecture = 'x64'; mode = 'MANUAL_METADATA_ONLY'; files = $rows }
Save-Json $manifestPath $manifest
Check ((Read-CollectorBundle $package).Manifest.files.Count -eq 11)
Reject { Assert-CollectorSetupPath 'relative' } 'SETUP_PATH_REJECTED'
Reject { Assert-CollectorSetupPath '\\localhost\share\collector' } 'SETUP_PATH_REJECTED'
Reject { Assert-CollectorSetupPath ($temporary + '\..\escape') } 'SETUP_PATH_REJECTED'
Reject { Assert-CollectorSetupPath ($temporary + ':stream') } 'SETUP_PATH_REJECTED'
Reject { Assert-CollectorSetupPath 'C:\' } 'SETUP_FIXED_DRIVE_REQUIRED'

$extra = Join-Path $package 'extra.txt'
[IO.File]::WriteAllText($extra, 'keep', $utf8)
Reject { Read-CollectorBundle $package } 'SETUP_FILE_INVENTORY_REJECTED'
Remove-Item -LiteralPath $extra
$manifest.architecture = 'ARM64'; Save-Json $manifestPath $manifest
Reject { Read-CollectorBundle $package } 'SETUP_MANIFEST_REJECTED'
$manifest.architecture = 'x64'
$manifest.files[0].path = '../escape'; Save-Json $manifestPath $manifest
Reject { Read-CollectorBundle $package } 'SETUP_FILE_RECORD_REJECTED'
$manifest.files[0].path = 'bin/DriverCrateCollector.exe'
$originalHash = $manifest.files[0].sha256
$manifest.files[0].sha256 = '0' * 64; Save-Json $manifestPath $manifest
Reject { Read-CollectorBundle $package } 'SETUP_PAYLOAD_HASH_REJECTED'
$manifest.files[0].sha256 = $originalHash; Save-Json $manifestPath $manifest
$exe = Join-Path $package 'bin/DriverCrateCollector.exe'
$original = [IO.File]::ReadAllBytes($exe)
$changed = $original.Clone(); $changed[0x44] = 0x4c; $changed[0x45] = 0x01
[IO.File]::WriteAllBytes($exe, $changed)
Reject { Assert-CollectorX64Executable $exe } 'SETUP_X64_REQUIRED'
[IO.File]::WriteAllBytes($exe, $original)

$destination = Join-Path $temporary 'installed workspace'
Install-CollectorWorkspace $package $destination -WhatIf | Out-Null
Check (-not (Test-Path -LiteralPath $destination))
Install-CollectorWorkspace $package $destination -Confirm:$false | Out-Null
Check ((Read-CollectorBundle $destination -Installed).ManifestHash -ceq (Get-CollectorSetupHash $manifestPath))
Check (Test-Path -LiteralPath (Join-Path $destination 'work\state') -PathType Container)
Check (-not (Test-Path -LiteralPath (Join-Path $destination 'work\state\collector')))
Reject { Install-CollectorWorkspace $package $destination -Confirm:$false } 'SETUP_EXISTING_DIRECTORY_REJECTED'
$empty = Join-Path $temporary 'existing-empty'; [void][IO.Directory]::CreateDirectory($empty)
Reject { Install-CollectorWorkspace $package $empty -Confirm:$false } 'SETUP_EXISTING_DIRECTORY_REJECTED'

$config = Join-Path $destination 'config\targets.json'
Save-Json $config @{ schema = 'dc-collector-targets-v1'; targets = @() }
Check ((Read-CollectorBundle $destination -Installed).Manifest.mode -ceq 'MANUAL_METADATA_ONLY')
$state = Join-Path $destination 'work\state\retained-data.json'
$unknown = Join-Path $destination 'user-notes.txt'
[IO.File]::WriteAllText($state, 'retained data', $utf8)
[IO.File]::WriteAllText($unknown, 'retained notes', $utf8)
Check ((Read-CollectorBundle $destination -Installed).Manifest.files.Count -eq 11)
$protected = Join-Path $destination 'LICENSE'
$saved = [IO.File]::ReadAllBytes($protected)
[IO.File]::WriteAllText($protected, 'modified', $utf8)
Reject { Uninstall-CollectorWorkspace $destination -Confirm:$false } 'SETUP_PAYLOAD_HASH_REJECTED'
Check (Test-Path -LiteralPath (Join-Path $destination 'bin\DriverCrateCollector.exe'))
[IO.File]::WriteAllBytes($protected, $saved)
Uninstall-CollectorWorkspace $destination -WhatIf | Out-Null
Check (Test-Path -LiteralPath (Join-Path $destination 'bin\DriverCrateCollector.exe'))
Uninstall-CollectorWorkspace $destination -Confirm:$false | Out-Null
Check (-not (Test-Path -LiteralPath (Join-Path $destination 'bin\DriverCrateCollector.exe')))
Check ([IO.File]::ReadAllText($state) -ceq 'retained data')
Check ([IO.File]::ReadAllText($unknown) -ceq 'retained notes')
Check (Test-Path -LiteralPath $config)
Check (Test-Path -LiteralPath $destination -PathType Container)

$linked = Join-Path $temporary 'junction'
New-Item -ItemType Junction -Path $linked -Target $package | Out-Null
Reject { Read-CollectorBundle $linked } 'SETUP_REPARSE_OR_FILE_REJECTED'
Reject { Install-CollectorWorkspace $package (Join-Path $linked 'new') -Confirm:$false } 'SETUP_REPARSE_OR_FILE_REJECTED'
Check (-not (Test-Path -LiteralPath (Join-Path $package 'new')))

# The native installer is independently exercised; the synthetic collector is never executed.
if ($SetupExecutable) {
    $setup = Join-Path $package 'DriverCrateCollectorSetup.exe'
    function Native([string[]] $Arguments, [int] $Expected, [string] $Stage = '') {
        $output = & $setup @Arguments 2>&1
        $code = $LASTEXITCODE
        Check ($code -eq $Expected)
        Check (($output -join "`n") -match 'network=0 tasks=0')
        if ($Stage) { Check (($output -join "`n") -match ('stage=' + $Stage)) }
    }
    $nativeRoot = Join-Path $temporary 'native installed workspace'
    Native @('--check-package', $package) 0
    Native @('--check-package', $linked) 2
    Native @('--check-installed', $package) 2
    Native @('--install', $nativeRoot, '--yes') 0
    Native @('--install', $nativeRoot, '--yes') 2
    Native @('--check-installed', $nativeRoot) 0
    $nativeData = Join-Path $nativeRoot 'work\state\saved.json'
    $nativeNotes = Join-Path $nativeRoot 'notes.txt'
    [IO.File]::WriteAllText($nativeData, 'native retained', $utf8)
    [IO.File]::WriteAllText($nativeNotes, 'notes retained', $utf8)
    # Large private work is intentionally not enumerated by the setup or uninstaller.
    for ($i = 0; $i -lt 150; ++$i) {
        [IO.File]::WriteAllText((Join-Path $nativeRoot ('work\state\fixture-' + $i)), 'retained', $utf8)
    }
    $nativeConfig = Join-Path $nativeRoot 'config\targets.json'
    Save-Json $nativeConfig @{ schema = 'dc-collector-targets-v1'; targets = @() }
    Native @('--check-installed', $nativeRoot) 0
    $license = Join-Path $nativeRoot 'LICENSE'
    $savedLicense = [IO.File]::ReadAllBytes($license)
    [IO.File]::WriteAllText($license, 'tampered', $utf8)
    Native @('--uninstall', $nativeRoot, '--yes') 2
    Check (Test-Path -LiteralPath (Join-Path $nativeRoot 'bin\DriverCrateCollector.exe'))
    [IO.File]::WriteAllBytes($license, $savedLicense)
    $nativeReceiptPath = Join-Path $nativeRoot 'install-receipt.json'
    $savedReceipt = [IO.File]::ReadAllBytes($nativeReceiptPath)
    $receipt = [IO.File]::ReadAllText($nativeReceiptPath) | ConvertFrom-Json
    $receipt.packageManifestSha256 = '0' * 64
    Save-Json $nativeReceiptPath $receipt
    Native @('--uninstall', $nativeRoot, '--yes') 2
    Check (Test-Path -LiteralPath (Join-Path $nativeRoot 'bin\DriverCrateCollector.exe'))
    [IO.File]::WriteAllBytes($nativeReceiptPath, $savedReceipt)
    Native @('--uninstall', $nativeRoot, '--yes') 0
    Check (-not (Test-Path -LiteralPath (Join-Path $nativeRoot 'bin\DriverCrateCollector.exe')))
    Check (Test-Path -LiteralPath (Join-Path $nativeRoot 'DriverCrateCollectorSetup.exe'))
    Check (Test-Path -LiteralPath (Join-Path $nativeRoot 'Uninstall.cmd'))
    Check ([IO.File]::ReadAllText($nativeData) -ceq 'native retained')
    Check ([IO.File]::ReadAllText($nativeNotes) -ceq 'notes retained')
    Check (Test-Path -LiteralPath $nativeConfig)
    Check (@(Get-ChildItem -LiteralPath (Join-Path $nativeRoot 'work\state') -File).Count -eq 151)
    Native @('--install', (Join-Path $linked 'new'), '--yes') 2
    Native @('--install', $empty, '--yes') 2
    Native @('--check-package', 'relative') 2
    Native @('--check-package', '\\localhost\share\collector') 2
    Native @('--check-package', ($package + ':stream')) 2
    Native @('--check-package', ($temporary + '\..\escape')) 2
    $aliasPackage = Join-Path $temporary 'alias-package'
    [void][IO.Directory]::CreateDirectory($aliasPackage)
    # 固定管理一覧をalias fixtureへcopyし、binだけをjunctionに置換するためcollector fileを先にcopyしない。
    foreach ($relative in @((Get-CollectorPayloadFiles)) + @('package-manifest.json')) {
        if ($relative -ceq 'bin/DriverCrateCollector.exe') { continue }
        $target = Join-Path $aliasPackage $relative
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        [IO.File]::Copy((Join-Path $package $relative), $target)
    }
    $emptyOutside = Join-Path $temporary 'outside-empty'
    [void][IO.Directory]::CreateDirectory($emptyOutside)
    New-Item -ItemType Junction -Path (Join-Path $aliasPackage 'bin') -Target $emptyOutside | Out-Null
    # No missing payload may be read through the junction before its attributes are rejected.
    Native @('--check-package', $aliasPackage) 2 'INVENTORY_REPARSE'
}

Write-Output ('COLLECTOR_SETUP_TESTS checks={0} failures=0 network=0 tasks=0 collector_executions=0 native_setup={1}' -f
    $script:Checks, [bool]$SetupExecutable)
