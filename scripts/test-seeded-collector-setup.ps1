#requires -Version 5.1
<#
.SYNOPSIS
Tests seeded collector setup with an actual research snapshot and synthetic collector PE.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
The rebuilt native setup and fixed Python seed verifier run. No network, tasks, collector or driver execution.
Fixtures default to work/tmp; explicit FixtureRoot uses a new child of a validated fixed-drive root.
Fixtures are retained for inspection; no recursive cleanup.
#>
param([Parameter(Mandatory)][string] $SetupExecutable,
    [Parameter(Mandatory)][string] $SeedSnapshot, [string] $FixtureRoot,
    [string] $PythonExecutable)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $repo 'packaging\collector\collector-setup.psm1') -Force -DisableNameChecking
$script:Checks = 0
$script:NativeCalls = 0
function Check([bool] $Condition) {
    if (-not $Condition) { throw ('SEED_FIXTURE_CHECK_' + $script:Checks) }
    ++$script:Checks
}
function Reject([scriptblock] $Action, [string] $Reason) {
    $observed = ''
    try { & $Action | Out-Null } catch { $observed = $_.Exception.Message }
    Check ($observed -ceq $Reason)
}
$temporary = Join-Path $repo ('work\tmp\collector-seeded-setup-' + [Guid]::NewGuid().ToString('N'))
if ($FixtureRoot) { $temporary = Join-Path (Assert-CollectorSetupPath $FixtureRoot) ('seeded-setup-' + [Guid]::NewGuid().ToString('N')) }
$package = Join-Path $temporary 'package'
[void][IO.Directory]::CreateDirectory($package)
$utf8 = New-Object Text.UTF8Encoding($false)
function Save-Json([string] $Path, $Body) {
    [IO.File]::WriteAllText($Path, ($Body | ConvertTo-Json -Depth 80), $utf8)
}
$rows = @()
# 固定seeded payload全件からpackageと外側hash行を作る。setupは実file、collectorは非実行synthetic x64 PE、seedはsnapshot、configは固定正本、残りは合成textへ分ける。
foreach ($relative in @(Get-CollectorPayloadFiles -Seeded)) {
    $target = Join-Path $package $relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    if ($relative -ceq 'DriverCrateCollectorSetup.exe') { [IO.File]::Copy($SetupExecutable, $target) }
    elseif ($relative -ceq 'bin/DriverCrateCollector.exe') {
        $bytes = New-Object byte[] 128
        $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[0x3c] = 0x40
        $bytes[0x40] = 0x50; $bytes[0x41] = 0x45; $bytes[0x44] = 0x64; $bytes[0x45] = 0x86
        $bytes[0x58] = 0x0b; $bytes[0x59] = 0x02
        [IO.File]::WriteAllBytes($target, $bytes)
    }
    elseif ($relative.StartsWith('seed/collector-data/', [StringComparison]::Ordinal)) {
        [IO.File]::Copy((Join-Path $SeedSnapshot $relative.Substring('seed/collector-data/'.Length)), $target)
    }
    elseif ($relative -ceq 'config/targets.json') {
        [IO.File]::Copy((Join-Path $repo 'packaging\collector\targets.json'), $target)
    }
    else { [IO.File]::WriteAllText($target, 'synthetic managed file', $utf8) }
    $rows += [ordered]@{ path = $relative; bytes = (Get-Item -LiteralPath $target).Length
        sha256 = Get-CollectorSetupHash $target }
}
$manifestPath = Join-Path $package 'package-manifest.json'
$manifest = [ordered]@{ schema = 'dc-collector-package-v2'; version = '0.1.0'
    architecture = 'x64'; mode = 'MANUAL_METADATA_WITH_RESEARCH_SEED'; files = $rows }
Save-Json $manifestPath $manifest
$originalManifest = [IO.File]::ReadAllBytes($manifestPath)
$setup = Join-Path $package 'DriverCrateCollectorSetup.exe'
# 固定setupを非shellで一回起動し、180秒の終了待機に失敗するとKillを試みて例外へ進む。追加の終了待機はしない。
# stdout/stderrの非同期CopyTo完了後に各64KiB以下を検査するため、保持memoryのhard capではない。
# 出力検査を通るとraw出力とreceiptを先に保存し、その後に期待exitとnetwork=0/tasks=0を照合する。
# Stageが空でない場合だけ出力stageも検査する。途中fixtureやnativeの部分作用は保持する。
# finallyのprocess/stream Disposeはrollbackや確実なreapを保証しない。
function Native([string[]] $Arguments, [int] $Expected, [string] $Stage = '') {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $setup
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Arguments = (@($Arguments | ForEach-Object {
        '"' + ([regex]::Replace(([regex]::Replace($_, '(\\*)"', '$1$1\"')), '(\\+)$', '$1$1')) + '"'
    }) -join ' ')
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    $stderr = [IO.MemoryStream]::new()
    try {
        [void]$process.Start()
        $outTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $errTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if (-not $process.WaitForExit(180000)) { $process.Kill(); throw 'SEED_NATIVE_TIMEOUT' }
        $outTask.GetAwaiter().GetResult()
        $errTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 65536 -or $stderr.Length -gt 65536) { throw 'SEED_NATIVE_OUTPUT_LIMIT' }
        $code = $process.ExitCode
        $prefix = Join-Path $temporary ('native-' + $script:NativeCalls)
        [IO.File]::WriteAllBytes($prefix + '.stdout.bin', $stdout.ToArray())
        [IO.File]::WriteAllBytes($prefix + '.stderr.bin', $stderr.ToArray())
        [IO.File]::WriteAllText($prefix + '.receipt.json',
            ([ordered]@{ argv = @($setup) + $Arguments; expectedExit = $Expected; exitCode = $code; stage = $Stage } | ConvertTo-Json), $utf8)
        $output = [Text.Encoding]::UTF8.GetString($stdout.ToArray())
        Check ($code -eq $Expected)
        Check ($output -match 'network=0 tasks=0')
        if ($Stage) { Check ($output -match ('stage=' + $Stage)) }
        ++$script:NativeCalls
    } finally { $process.Dispose(); $stdout.Dispose(); $stderr.Dispose() }
}
function Rewrite-Outer {
    # 内側seed改変fixtureを外側hashだけで正当化できないことを試すため、外側manifest全行の実size/hashを再計算する。
    foreach ($row in $manifest.files) {
        $path = Join-Path $package $row.path
        $row.bytes = (Get-Item -LiteralPath $path).Length
        $row.sha256 = Get-CollectorSetupHash $path
    }
    Save-Json $manifestPath $manifest
}
$seed = Join-Path $package 'seed\collector-data'
$seedManifestPath = Join-Path $seed 'manifest.json'
$originalSeedManifest = [IO.File]::ReadAllBytes($seedManifestPath)
function Rewrite-Inner {
    $inner = [IO.File]::ReadAllText($seedManifestPath) | ConvertFrom-Json
    # 研究flag等の改変をhash不足でなく意味検査へ届かせるため、内側全fileのsize/hashを再計算して外側も更新する。
    foreach ($row in $inner.files) {
        $path = Join-Path $seed $row.path
        $row.bytes = (Get-Item -LiteralPath $path).Length
        $row.sha256 = Get-CollectorSetupHash $path
    }
    Save-Json $seedManifestPath $inner
    Rewrite-Outer
}
Check ((Read-CollectorBundle $package).Manifest.files.Count -eq 18)
Native @('--check-package', $package) 0
$psDestination = Join-Path $temporary 'PowerShell seeded installed workspace'
Install-CollectorWorkspace $package $psDestination -WhatIf | Out-Null
Check (-not (Test-Path -LiteralPath $psDestination))
Install-CollectorWorkspace $package $psDestination -Confirm:$false | Out-Null
Check ((Read-CollectorBundle $psDestination -Installed).Seeded)
Uninstall-CollectorWorkspace $psDestination -Confirm:$false | Out-Null
Check (-not (Test-Path -LiteralPath (Join-Path $psDestination 'bin\DriverCrateCollector.exe')))
# PowerShell配置/uninstall後の全seed fileを元package hashへ照合し、seed保持を具体的に検査する。
foreach ($relative in @(Get-CollectorPayloadFiles -Seeded | Where-Object { $_.StartsWith('seed/') })) {
    Check ((Get-CollectorSetupHash (Join-Path $package $relative)) -ceq
        (Get-CollectorSetupHash (Join-Path $psDestination $relative)))
}
$destination = Join-Path $temporary 'native seeded installed workspace'
Native @('--install', $destination, '--yes') 0
Native @('--check-installed', $destination) 0
Check ((Read-CollectorBundle $destination -Installed).Seeded)
Check (-not (Test-Path -LiteralPath (Join-Path $destination 'work\state\collector')))
# native配置後の全seed fileを元package hashへ照合し、copy結果を検査する。
foreach ($relative in @(Get-CollectorPayloadFiles -Seeded | Where-Object { $_.StartsWith('seed/') })) {
    Check ((Get-CollectorSetupHash (Join-Path $package $relative)) -ceq
        (Get-CollectorSetupHash (Join-Path $destination $relative)))
}
function Verify-InstalledSeed {
    if ($PythonExecutable) {
        & $PythonExecutable -X utf8 -B (Join-Path $repo 'scripts\collector_payload_evidence.py') verify (Join-Path $destination 'seed\collector-data')
    }
    else { & py -3.13 -X utf8 -B (Join-Path $repo 'scripts\collector_payload_evidence.py') verify (Join-Path $destination 'seed\collector-data') }
    Check ($LASTEXITCODE -eq 0)
}
Verify-InstalledSeed
Native @('--install', $destination, '--yes') 2 'EXISTING_DIRECTORY'

# Extra seed files are rejected even after installation, and never become deletion targets.
$extra = Join-Path $destination 'seed\collector-data\extra.json'
[IO.File]::WriteAllText($extra, '{}', $utf8)
Reject { Read-CollectorBundle $destination -Installed } 'SETUP_FILE_INVENTORY_REJECTED'
Native @('--check-installed', $destination) 2 'INVENTORY_EXTRA'
Remove-Item -LiteralPath $extra
$installedIndex = Join-Path $destination 'seed\collector-data\index\drivers.json'
$installedBytes = [IO.File]::ReadAllBytes($installedIndex)
[IO.File]::WriteAllText($installedIndex, '{}', $utf8)
Native @('--uninstall', $destination, '--yes') 2 'PAYLOAD_HASH'
Check (Test-Path -LiteralPath (Join-Path $destination 'bin\DriverCrateCollector.exe'))
[IO.File]::WriteAllBytes($installedIndex, $installedBytes)

# Rehashing the outer package cannot bypass an inconsistent inner manifest.
$indexPath = Join-Path $seed 'index\drivers.json'
$indexBytes = [IO.File]::ReadAllBytes($indexPath)
[IO.File]::WriteAllText($indexPath, '{}', $utf8)
Rewrite-Outer
Reject { Read-CollectorBundle $package } 'SETUP_SEED_HASH_REJECTED'
Native @('--check-package', $package) 2 'SEED_HASH'
[IO.File]::WriteAllBytes($indexPath, $indexBytes)
[IO.File]::WriteAllBytes($seedManifestPath, $originalSeedManifest)
[IO.File]::WriteAllBytes($manifestPath, $originalManifest)

# Even rehashed claims must stay research-only and never authorize installation.
$index = [IO.File]::ReadAllText($indexPath) | ConvertFrom-Json
$index.installAuthorized = $true
Save-Json $indexPath $index
Rewrite-Inner
Reject { Read-CollectorBundle $package } 'SETUP_SEED_RESEARCH_BOUNDARY_REJECTED'
Native @('--check-package', $package) 2 'SEED_RESEARCH_BOUNDARY'
$index.installAuthorized = $false
$index.researchOnly = 'true'
Save-Json $indexPath $index
Rewrite-Inner
Reject { Read-CollectorBundle $package } 'SETUP_SEED_RESEARCH_BOUNDARY_REJECTED'
Native @('--check-package', $package) 2
$index.researchOnly = $true
$index.counts.targetProducts++
Save-Json $indexPath $index
Rewrite-Inner
Reject { Read-CollectorBundle $package } 'SETUP_SEED_INDEX_BINDING_REJECTED'
Native @('--check-package', $package) 2 'SEED_INDEX_BINDING'
[IO.File]::WriteAllBytes($indexPath, $indexBytes)
[IO.File]::WriteAllBytes($seedManifestPath, $originalSeedManifest)
[IO.File]::WriteAllBytes($manifestPath, $originalManifest)

$inner = [IO.File]::ReadAllText($seedManifestPath) | ConvertFrom-Json
$inner.schema = 'dc-portable-research-snapshot-v999'
Save-Json $seedManifestPath $inner
Rewrite-Outer
Reject { Read-CollectorBundle $package } 'SETUP_SEED_SCHEMA_REJECTED'
Native @('--check-package', $package) 2 'SEED_SCHEMA'
[IO.File]::WriteAllBytes($seedManifestPath, $originalSeedManifest)
[IO.File]::WriteAllBytes($manifestPath, $originalManifest)
$inner.files[0].path = '../outside.json'
$inner.schema = 'dc-portable-research-snapshot-v2'
Save-Json $seedManifestPath $inner
Rewrite-Outer
Reject { Read-CollectorBundle $package } 'SETUP_SEED_HASH_REJECTED'
Native @('--check-package', $package) 2 'SEED_HASH'
[IO.File]::WriteAllBytes($seedManifestPath, $originalSeedManifest)
[IO.File]::WriteAllBytes($manifestPath, $originalManifest)
$inner = [IO.File]::ReadAllText($seedManifestPath) | ConvertFrom-Json
$inner.registrySha256 += [char]0
Save-Json $seedManifestPath $inner
Rewrite-Outer
Reject { Read-CollectorBundle $package } 'SETUP_SEED_SCHEMA_REJECTED'
Native @('--check-package', $package) 2 'SEED_SCHEMA'
[IO.File]::WriteAllBytes($seedManifestPath, $originalSeedManifest)
[IO.File]::WriteAllBytes($manifestPath, $originalManifest)

$unknownDirectory = Join-Path $package 'seed\collector-data\unknown'
[void][IO.Directory]::CreateDirectory($unknownDirectory)
Reject { Read-CollectorBundle $package } 'SETUP_EXTRA_DIRECTORY'
Native @('--check-package', $package) 2
Remove-Item -LiteralPath $unknownDirectory
$missingPath = Join-Path $seed 'observations.json'
$missingBytes = [IO.File]::ReadAllBytes($missingPath)
Remove-Item -LiteralPath $missingPath
Reject { Read-CollectorBundle $package } 'SETUP_FILE_INVENTORY_REJECTED'
Native @('--check-package', $package) 2
[IO.File]::WriteAllBytes($missingPath, $missingBytes)
$manifest.schema = 'dc-collector-package-v1'
$manifest.mode = 'MANUAL_METADATA_ONLY'
Save-Json $manifestPath $manifest
Reject { Read-CollectorBundle $package } 'SETUP_FILE_COUNT_REJECTED'
Native @('--check-package', $package) 2 'MANIFEST_COUNT'
$manifest.schema = 'dc-collector-package-v2'
$manifest.mode = 'MANUAL_METADATA_WITH_RESEARCH_SEED'
[IO.File]::WriteAllBytes($manifestPath, $originalManifest)

# A seed subtree junction must be refused before reading even one child.
$alias = Join-Path $temporary 'alias package'
[void][IO.Directory]::CreateDirectory($alias)
foreach ($relative in @((Get-CollectorPayloadFiles)) + @('package-manifest.json')) {
    $target = Join-Path $alias $relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    [IO.File]::Copy((Join-Path $package $relative), $target)
}
New-Item -ItemType Junction -Path (Join-Path $alias 'seed') -Target (Join-Path $package 'seed') | Out-Null
Reject { Read-CollectorBundle $alias } 'SETUP_INVENTORY_REJECTED'
Native @('--check-package', $alias) 2 'INVENTORY_REPARSE'
$aliasSeed = [IO.Path]::GetFullPath((Join-Path $alias 'seed'))
Check ($aliasSeed.StartsWith([IO.Path]::GetFullPath($temporary) + '\', [StringComparison]::OrdinalIgnoreCase))
Check ([bool]((Get-Item -LiteralPath $aliasSeed -Force).Attributes -band [IO.FileAttributes]::ReparsePoint))
# Remove this exact artificial junction without traversing or deleting the retained seed target.
[IO.Directory]::Delete($aliasSeed)

$retained = Join-Path $destination 'work\state\retained.json'
[IO.File]::WriteAllText($retained, '{}', $utf8)
Native @('--uninstall', $destination, '--yes') 0
Check (-not (Test-Path -LiteralPath (Join-Path $destination 'bin\DriverCrateCollector.exe')))
Check (Test-Path -LiteralPath (Join-Path $destination 'DriverCrateCollectorSetup.exe'))
Check (Test-Path -LiteralPath $retained)
# native uninstall後も全seed fileのhashと共通verifierで保持を確認し、dataだけ残ったことをseed合格へ代用しない。
foreach ($relative in @(Get-CollectorPayloadFiles -Seeded | Where-Object { $_.StartsWith('seed/') })) {
    Check ((Get-CollectorSetupHash (Join-Path $package $relative)) -ceq
        (Get-CollectorSetupHash (Join-Path $destination $relative)))
}
Verify-InstalledSeed
Write-Output ('SEEDED_SETUP_TESTS checks={0} failures=0 network=0 tasks=0 collector_executions=0 native_setup_calls={1}' -f
    $script:Checks, $script:NativeCalls)
