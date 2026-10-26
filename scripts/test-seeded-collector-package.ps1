#requires -Version 5.1
<#
.SYNOPSIS
Verifies a real seeded ZIP, new native placement, read-only collector validation and seed retention.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Finite fixtures default to work/tmp; explicit FixtureRoot uses a new child of a validated fixed-drive root.
Fixtures are retained. Current v7 is check-only by default; install/uninstall requires explicit integration.
Obsolete package schemas are rejected. No network, driver install or recursive deletion.
#>
param([Parameter(Mandatory)][string] $Archive, [string] $FixtureRoot,
    [switch] $SkipCollectorValidation, [switch] $AllowTaskRegistration)
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
    Check ($manifest.schema -ceq 'dc-collector-package-v7' -and $manifest.mode -ceq 'EXPLICIT_DISTRIBUTION_DATA_DAILY')
    $includesReference = @($manifest.files | Where-Object { $_.path -ceq 'seed/distribution-data/reference.json' }).Count -eq 1
    $expected = @(Get-CollectorPayloadFiles -IncludeReference:$includesReference) + @('package-manifest.json')
    $directories = @('', 'bin/', 'config/', 'docs/', 'docs/adr/', 'seed/',
        'seed/collector-data/', 'seed/collector-data/index/')
    $directories += @('runtime/', 'scripts/', 'seed/distribution-data/', 'seed/distribution-data/references/')
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
$payloadCount = @(Get-CollectorPayloadFiles -IncludeReference:$includesReference).Count
Check ($bundle.Manifest.files.Count -eq $payloadCount)
# 共通guideの固定相対link又は公式canonical linkだけを受理し、対応する権利fileの同梱を必須にする。
$readme = [IO.File]::ReadAllText((Join-Path $package 'README-collector.md'))
$guideLinks = @([regex]::Matches($readme, '\[[^\]]+\]\(([^)]+)\)') |
    ForEach-Object { $_.Groups[1].Value })
Check ($guideLinks.Count -eq 2)
foreach ($link in $guideLinks) {
    $localFile = switch -CaseSensitive -Exact ($link) {
        'LICENSE' { 'LICENSE' }
        'THIRD_PARTY_NOTICES.md' { 'THIRD_PARTY_NOTICES.md' }
        'https://github.com/EnterOgawa/drivercrate/blob/main/LICENSE' { 'LICENSE' }
        'https://github.com/EnterOgawa/drivercrate/blob/main/THIRD_PARTY_NOTICES.md' { 'THIRD_PARTY_NOTICES.md' }
        default { '' }
    }
    Check ($localFile -cin @('LICENSE', 'THIRD_PARTY_NOTICES.md') -and
        (Test-Path -LiteralPath (Join-Path $package $localFile) -PathType Leaf))
}
Check ($readme.Contains('--enable-distribution-daily') -and $readme.Contains('copy/import/validate') -and $readme.Contains('未確認'))
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
        Check ($output -match 'network=0 (tasks=0|task_cleanup=not_confirmed)')
        ++$script:NativeCalls
    } finally { $process.Dispose(); $stdout.Dispose(); $stderr.Dispose() }
}
$destination = Join-Path $temporary '収集 host & data'
Native @('--check-package', $package) 0
# 現行通常installはTaskを作るので、既定は実byte検査だけを行う。
if ($AllowTaskRegistration) {
    & (Join-Path $PSScriptRoot 'test-collector-user-task-integration.ps1') -PackageDirectory $package `
        -FixtureRoot (Join-Path $temporary 'user-task-integration') -AllowTaskRegistration
}
[pscustomobject]@{ result = 'PASS_CHECK_ONLY'; checks = $script:Checks; payloadFiles = $payloadCount
    archiveFiles = $payloadCount + 1; networkRequests = 0; tasksRegistered = 0
    install = 'NOT_RUN'; uninstall = 'NOT_RUN'; fixture = $temporary } | ConvertTo-Json -Compress
