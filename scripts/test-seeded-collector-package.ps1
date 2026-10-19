#requires -Version 5.1
<#
.SYNOPSIS
Verifies a real seeded ZIP, new native placement, read-only collector validation and seed retention.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Finite fixtures default to work/tmp; explicit FixtureRoot uses a new child of a validated fixed-drive root.
Fixtures are retained. No network, tasks, driver install or recursive deletion.
#>
param([Parameter(Mandatory)][string] $Archive, [string] $FixtureRoot,
    [switch] $SkipCollectorValidation)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $repo 'packaging\collector\collector-setup.psm1') -Force -DisableNameChecking
$script:Checks = 0
$script:NativeCalls = 0
function Check([bool] $Condition) {
    if (-not $Condition) { throw ('SEED_PACKAGE_CHECK_' + $script:Checks) }
    ++$script:Checks
}
$Archive = [IO.Path]::GetFullPath($Archive)
$checksum = [IO.File]::ReadAllText($Archive + '.sha256').Split(' ')[0].Trim()
Check ((Get-CollectorSetupHash $Archive) -ceq $checksum)
$name = [IO.Path]::GetFileNameWithoutExtension($Archive)
Check ($name -cmatch '^DriverCrateCollector-[0-9]+\.[0-9]+\.[0-9]+-windows-x64-preview-[0-9a-f]{32}$')
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($Archive)
try {
    $entries = @($zip.Entries)
    $manifestEntry = @($entries | Where-Object { $_.FullName -ceq ($name + '/package-manifest.json') })
    Check ($manifestEntry.Count -eq 1 -and $manifestEntry[0].Length -le 262144)
    $reader = [IO.StreamReader]::new($manifestEntry[0].Open(), [Text.UTF8Encoding]::new($false, $true))
    try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    $protectedWorkspace = $manifest.schema -cin @('dc-collector-package-v4', 'dc-collector-package-v5')
    $registryRuntime = $protectedWorkspace -or $manifest.schema -ceq 'dc-collector-package-v3'
    $expected = @((Get-CollectorPayloadFiles -Seeded -RegistryRuntime:$registryRuntime -ProtectedWorkspace:$protectedWorkspace)) + @('package-manifest.json')
    $directories = @('', 'bin/', 'config/', 'docs/', 'docs/adr/', 'seed/',
        'seed/collector-data/', 'seed/collector-data/index/')
    if ($registryRuntime) { $directories += @('runtime/', 'scripts/') }
    Check ($entries.Count -le $expected.Count + $directories.Count)
    Check (@($entries | Where-Object { -not $_.FullName.EndsWith('/') }).Count -eq $expected.Count)
    $found = @()
    # ZIP全entryを一回ずつ検査し、package prefix・固定directory/file集合・重複なし・有限sizeを確認してから展開する。
    foreach ($entry in $entries) {
        Check ($entry.FullName.StartsWith($name + '/', [StringComparison]::Ordinal))
        $relative = $entry.FullName.Substring($name.Length + 1)
        if ($entry.FullName.EndsWith('/')) {
            Check ($relative -cin $directories -and $relative -cnotin $found -and $entry.Length -eq 0)
        }
        else { Check ($relative -cin $expected -and $relative -cnotin $found) }
        Check ($entry.Length -ge 0 -and $entry.Length -le 67108864)
        $found += $relative
    }
}
finally { $zip.Dispose() }
$temporary = Join-Path $repo ('work\tmp\seeded-package-' + [Guid]::NewGuid().ToString('N'))
if ($FixtureRoot) { $temporary = Join-Path (Assert-CollectorSetupPath $FixtureRoot) ('package-test-' + [Guid]::NewGuid().ToString('N')) }
[void](Assert-CollectorSetupPath $temporary)
Check (-not (Test-Path -LiteralPath $temporary))
$expanded = Join-Path $temporary 'expanded'
[void][IO.Directory]::CreateDirectory($expanded)
Expand-Archive -LiteralPath $Archive -DestinationPath $expanded
$package = Join-Path $expanded $name
$bundle = Read-CollectorBundle $package
$payloadCount = 18
# registry/runtime modeのpayload数期待を64へ切り替え、seedのみ18件と区別する。
if ($registryRuntime) { $payloadCount = 64 }
# protected workspaceではpayload数期待を69へ切り替え、保護入口fileの欠落を見逃さない。
if ($protectedWorkspace) { $payloadCount = 69 }
Check ($bundle.Seeded -and $bundle.RegistryRuntime -eq $registryRuntime -and $bundle.Manifest.files.Count -eq $payloadCount)
# The standalone guide may only link to files that are inside this package.
$readme = [IO.File]::ReadAllText((Join-Path $package 'README-collector.md'))
$guideLinks = @([regex]::Matches($readme, '\[[^\]]+\]\(([^)]+)\)') |
    ForEach-Object { $_.Groups[1].Value })
Check ($guideLinks.Count -eq 2)
foreach ($link in $guideLinks) {
    Check ($link -cin @('LICENSE', 'THIRD_PARTY_NOTICES.md') -and
        (Test-Path -LiteralPath (Join-Path $package $link) -PathType Leaf))
}
Check ($readme.Contains('Seedから日次通信を開始する機能') -and $readme.Contains('未完成'))
$setup = Join-Path $package 'DriverCrateCollectorSetup.exe'
# 固定setupを非shellで一回起動し、180秒の終了待機に失敗するとKillを試みて例外へ進む。追加の終了待機はしない。
# stdout/stderrの非同期CopyTo完了後に各64KiB以下を検査するため、保持memoryのhard capではない。
# 出力検査を通るとraw出力とreceiptを先に保存し、その後に期待exitとnetwork=0/tasks=0を照合する。
# 途中fixtureやnativeの部分作用は保持する。finallyのprocess/stream Disposeはrollbackや確実なreapを保証しない。
function Native([string[]] $Arguments, [int] $Expected) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $setup
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Quote the Windows argv directly; no command shell is involved.
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
            ([ordered]@{ argv = @($setup) + $Arguments; expectedExit = $Expected; exitCode = $code } | ConvertTo-Json), $utf8)
        $output = [Text.Encoding]::UTF8.GetString($stdout.ToArray())
        Check ($code -eq $Expected)
        Check ($output -match 'network=0 tasks=0')
        ++$script:NativeCalls
    } finally { $process.Dispose(); $stdout.Dispose(); $stderr.Dispose() }
}
$destination = Join-Path $temporary '収集 host & data'
Native @('--check-package', $package) 0
Native @('--install', $destination, '--yes') 0
Native @('--check-installed', $destination) 0
$installed = Read-CollectorBundle $destination -Installed
Check ($installed.ManifestHash -ceq $bundle.ManifestHash)
# 全seed fileのhashを元packageと配置先で一致確認し、新規native配置で研究seedが変わらないことを検査する。
foreach ($relative in @(Get-CollectorPayloadFiles -Seeded -RegistryRuntime:$registryRuntime | Where-Object { $_.StartsWith('seed/') })) {
    Check ((Get-CollectorSetupHash (Join-Path $package $relative)) -ceq
        (Get-CollectorSetupHash (Join-Path $destination $relative)))
}
# v3 placement does not assert daily readiness or execute the bundled runtime/collector.
$collectorValidation = 'NOT_RUN'
if (-not $registryRuntime -and -not $SkipCollectorValidation) {
    Push-Location -LiteralPath $destination
    try {
    $validationArguments = @('--validate', (Join-Path $destination 'config\targets.json'),
        (Join-Path $destination 'work\state\collector'))
    $output = @(& (Join-Path $destination 'bin\DriverCrateCollector.exe') @validationArguments 2>&1)
    Check ($LASTEXITCODE -eq 0)
    Check (($output -join "`n") -match 'acquired=0 installed=0')
    $collectorValidation = 'PASS'
    }
    finally { Pop-Location }
}
Native @('--uninstall', $destination, '--yes') 0
Check (-not (Test-Path -LiteralPath (Join-Path $destination 'bin\DriverCrateCollector.exe')))
Check (Test-Path -LiteralPath (Join-Path $destination 'config\targets.json'))
Check (Test-Path -LiteralPath (Join-Path $destination 'DriverCrateCollectorSetup.exe'))
# uninstall後も全seed fileのhashが元packageと一致することを検査し、seed保持を集計だけで推測しない。
foreach ($relative in @(Get-CollectorPayloadFiles -Seeded -RegistryRuntime:$registryRuntime | Where-Object { $_.StartsWith('seed/') })) {
    Check ((Get-CollectorSetupHash (Join-Path $package $relative)) -ceq
        (Get-CollectorSetupHash (Join-Path $destination $relative)))
}
[pscustomobject]@{ result = 'OK'; checks = $script:Checks; payloadFiles = $payloadCount; archiveFiles = $payloadCount + 1
    networkRequests = 0; tasksRegistered = 0; driverInstallations = 0; seedRetained = $true
    collectorValidation = $collectorValidation; runtimeExecuted = $false; fixture = $temporary } |
    ConvertTo-Json -Compress
