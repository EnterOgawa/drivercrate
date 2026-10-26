#requires -Version 7.0
<#
.SYNOPSIS
Creates a local Windows x64 manual collector preview ZIP, optionally signing its own two PEs.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Uses an explicitly rebuilt Release collector. Does not build, download dependencies, publish, or overwrite.
Optional CodeSigning follows ADR0406; third-party Python runtime bytes/signatures are never changed.
#>
[CmdletBinding()]
param([ValidatePattern('^\d+\.\d+\.\d+$')][string] $Version = '0.1.1',
    [Parameter(Mandatory)][string] $RegistrySnapshot,
    [Parameter(Mandatory)][string] $PythonRuntimeArchive,
    [Parameter(Mandatory)][string] $PythonExecutable,
    [Parameter(Mandatory)][string] $DistributionDataBundle,
    [string] $OutputDirectory,
    [string] $BuildDirectory = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../build'))),
    [hashtable] $CodeSigning)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
$context = Resolve-IndexPackageBuild -BuildDirectory $BuildDirectory -RequireCollector
Assert-IndexPackageExecutable -Executable (Join-Path $context.Build 'Release/DriverCrateCollector.exe')
Assert-IndexPackageExecutable -Executable (Join-Path $context.Build 'Release/DriverCrateCollectorSetup.exe')
$source = Join-Path $repo 'packaging\collector'
Import-Module (Join-Path $source 'collector-setup.psm1') -Force -DisableNameChecking
& $PythonExecutable -I -B -X utf8 -c 'import runpy,sys;sys.path[:0]=[sys.argv[1]];sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")' (Join-Path $repo 'scripts') (Join-Path $repo 'scripts/collector_distribution_data.py') verify $DistributionDataBundle
if ($LASTEXITCODE -ne 0) { throw 'PACKAGE_DISTRIBUTION_DATA_REJECTED' }
$distributionManifestPath = Join-Path $DistributionDataBundle 'manifest.json'
# 先行codec検証後も通常file/容量を再確認し、非exportのmodule内部helperへ依存しない。
[void](Get-CollectorSetupHash $distributionManifestPath)
if ((Get-Item -LiteralPath $distributionManifestPath).Length -gt 262144) { throw 'PACKAGE_DATA_MANIFEST_LIMIT' }
$distributionManifest = [Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($distributionManifestPath)) | ConvertFrom-Json
function Verify-Seed([string] $Path) {
    & $PythonExecutable -I -B -X utf8 -c 'import runpy,sys;sys.path[:0]=[sys.argv[1]];sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")' (Join-Path $repo 'scripts') (Join-Path $repo 'scripts/collector_locator_snapshot.py') verify $Path
    if ($LASTEXITCODE -ne 0) { throw 'PACKAGE_SEED_REJECTED' }
}
$RegistrySnapshot = Assert-CollectorSetupPath $RegistrySnapshot -Existing
Verify-Seed $RegistrySnapshot
$project = [IO.File]::ReadAllText((Join-Path $repo 'CMakeLists.txt'))
# 要求VersionをCMake project版へ一致させ、異なる製品版名でpackageしない。
if ($project -notmatch '(?s)project\(\s*DriverCrate\s+VERSION\s+([0-9.]+)' -or $Matches[1] -cne $Version) {
    throw 'PACKAGE_VERSION_REJECTED'
}
$name = 'DriverCrateCollector-' + $Version + '-windows-x64-preview-' + [Guid]::NewGuid().ToString('N')
$output = if ($PSBoundParameters.ContainsKey('OutputDirectory')) {
    Assert-IndexPackageOutput -Context $context -Path $OutputDirectory -Fresh
} else {
    Assert-IndexPackageOutput -Context $context -Path (Join-Path $repo 'out') -AllowRoot
}
$directory = Join-Path $output $name
Assert-IndexPackageDistinctPaths -Paths @($RegistrySnapshot, $DistributionDataBundle, $directory)
$archive = $directory + '.zip'
$checksum = $archive + '.sha256'
[void](Assert-CollectorSetupPath $directory)
# package directory・ZIP・checksumの三出力を作成前に全て確認し、一つでも既存なら拒否して上書きしない。
foreach ($path in @($directory, $archive, $checksum)) {
    if (Test-Path -LiteralPath $path) { throw 'PACKAGE_OUTPUT_ALREADY_EXISTS' }
}
# runtime stagingとpackage/ZIP/checksumには新規名を要求するが、途中成果物の自動rollbackは行わない。
# runtime展開・copy・検証や後続I/Oで失敗しても、既に作ったdirectory/fileは保持する。
$runtimeDirectory = $null
$metadataPath = Join-Path $source 'python-runtime-manifest.json'
# runtime manifest自身の固定hashを先に確認し、変更したmetadataでarchiveを正当化させない。
if ((Get-CollectorSetupHash $metadataPath) -cne '00691561b72690d21156e5777ddc9fec9226353fd3b816e614894f9c6503942e') {
    throw 'PACKAGE_RUNTIME_METADATA_REJECTED'
}
$metadata = [IO.File]::ReadAllText($metadataPath) | ConvertFrom-Json
$runtimeItem = Get-Item -LiteralPath $PythonRuntimeArchive -Force
# runtime archiveを通常非reparse file・固定size/hashへ限定し、異なるarchiveを展開しない。
if ($runtimeItem.PSIsContainer -or ($runtimeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $runtimeItem.Length -ne $metadata.archiveBytes -or
    (Get-CollectorSetupHash $PythonRuntimeArchive) -cne $metadata.archiveSha256) {
    throw 'PACKAGE_RUNTIME_ARCHIVE_REJECTED'
}
[void](Assert-CollectorSetupPath $runtimeItem.DirectoryName -Existing)
$runtimeDirectory = Join-Path $output ($name + '-runtime-input')
[void](Assert-CollectorSetupPath $runtimeDirectory)
if (Test-Path -LiteralPath $runtimeDirectory) { throw 'PACKAGE_OUTPUT_ALREADY_EXISTS' }
[void][IO.Directory]::CreateDirectory($runtimeDirectory)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($PythonRuntimeArchive)
try {
    $expectedRuntime = @(Get-CollectorRuntimeFiles)
    $entries = @($zip.Entries)
    # ZIP entry数を固定runtime一覧と一致させ、余分・欠落entryがあるarchiveを拒否する。
    if ($entries.Count -ne $expectedRuntime.Count) { throw 'PACKAGE_RUNTIME_ENTRY_COUNT_REJECTED' }
    $found = @()
    # 固定runtime全entryを一回ずつ処理して名前・重複・size・実hash・x64を検査し、一件の不一致で展開を中止する。
    foreach ($entry in $entries) {
        $relative = $entry.FullName
        # 固定名以外・重複・separator/colon入り名・16MiB超entryを拒否し、任意pathへの展開を避ける。
        if ($relative -cnotin $expectedRuntime -or $relative -in $found -or
            $relative -match '[\\/:]' -or $entry.Length -gt 16777216) { throw 'PACKAGE_RUNTIME_ENTRY_REJECTED' }
        $found += $relative
        $row = @($metadata.files | Where-Object { $_.path -ceq $relative })
        # entryがmanifestに一意に結合でき、宣言sizeが一致するときだけstreamを開く。
        if ($row.Count -ne 1 -or $entry.Length -ne $row[0].bytes) { throw 'PACKAGE_RUNTIME_ENTRY_SIZE_REJECTED' }
        $stream = $entry.Open()
        try {
            $buffer = [byte[]]::new([int]$entry.Length + 1)
            $count = 0
            # 宣言size+1のbufferへ容量まで読み、EOFかbuffer満了で停止して実byte数が宣言sizeと一致することを確認する。
            while ($count -lt $buffer.Length) {
                $read = $stream.Read($buffer, $count, $buffer.Length - $count)
                if ($read -eq 0) { break }
                $count += $read
            }
            # 実読取数がZIP宣言長と違うentryは保存せず拒否し、短いreadや余分byteを採用しない。
            if ($count -ne $entry.Length) { throw 'PACKAGE_RUNTIME_ENTRY_READ_REJECTED' }
            $bytes = [byte[]]$buffer[0..($count - 1)]
            $target = Join-Path $runtimeDirectory $relative
            [IO.File]::WriteAllBytes($target, $bytes)
            # stagingへ書いたfileの実hashを固定manifestへ一致させ、不正byteのpackage化を拒否する。
            if ((Get-CollectorSetupHash $target) -cne $row[0].sha256) { throw 'PACKAGE_RUNTIME_ENTRY_HASH_REJECTED' }
            if ($relative -cmatch '\.(exe|dll|pyd)$') { Assert-CollectorX64Executable $target }
        } finally { $stream.Dispose() }
    }
} finally { $zip.Dispose() }

$signing = @()
if ($null -ne $CodeSigning) {
    . (Join-Path $PSScriptRoot 'release_signing.ps1')
    $signing += Invoke-ReleaseBuildSigning -Context $context -Role Collector -CodeSigning $CodeSigning
    $signing += Invoke-ReleaseBuildSigning -Context $context -Role CollectorSetup -CodeSigning $CodeSigning
}
$mapping = [ordered]@{}
# 固定payload一覧全件を実sourceへ対応付けて通常file hash検査を行い、package相対名のmappingを作る。
foreach ($relative in @(Get-CollectorPayloadFiles -IncludeReference:$distributionManifest.includesReference)) {
    $inputPath = Join-Path $source $relative
    # 固定relativeごとにcollector/setupはRelease、configは正本data、ADR/license/noticeはrepo rootへ割り当てる。非一致は既定packaging sourceを保ちfallthroughしない。
    switch ($relative) {
        'bin/DriverCrateCollector.exe' { $inputPath = Join-Path $context.Build 'Release/DriverCrateCollector.exe' }
        'DriverCrateCollectorSetup.exe' { $inputPath = Join-Path $context.Build 'Release/DriverCrateCollectorSetup.exe' }
        'config/targets.json' { $inputPath = Join-Path $source 'targets.json' }
        'config/monitor-policy.json' { $inputPath = Join-Path $repo 'data/collector-registry/monitor-policy.json' }
        'docs/adr/0209-local-first-recurring-driver-collector.md' { $inputPath = Join-Path $repo $relative }
        'LICENSE' { $inputPath = Join-Path $repo 'LICENSE' }
        'THIRD_PARTY_NOTICES.md' { $inputPath = Join-Path $repo 'THIRD_PARTY_NOTICES.md' }
    }
    if ($relative.StartsWith('seed/collector-data/', [StringComparison]::Ordinal)) {
        $inputPath = Join-Path $RegistrySnapshot $relative.Substring('seed/collector-data/'.Length)
    }
    if ($relative.StartsWith('seed/distribution-data/', [StringComparison]::Ordinal)) {
        $inputPath = Join-Path $DistributionDataBundle $relative.Substring('seed/distribution-data/'.Length)
    }
    if ($relative.StartsWith('scripts/', [StringComparison]::Ordinal)) { $inputPath = Join-Path $repo $relative }
    if ($relative.StartsWith('runtime/', [StringComparison]::Ordinal)) {
        $inputPath = Join-Path $runtimeDirectory $relative.Substring('runtime/'.Length)
        if ($relative -ceq 'runtime/python-runtime-manifest.json') { $inputPath = Join-Path $source 'python-runtime-manifest.json' }
    }
    [void](Get-CollectorSetupHash $inputPath)
    $mapping[$relative] = $inputPath
}
Assert-CollectorX64Executable $mapping['bin/DriverCrateCollector.exe']
[void][IO.Directory]::CreateDirectory($directory)
$rows = @()
foreach ($relative in $mapping.Keys) {
    $target = Join-Path $directory $relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    [IO.File]::Copy($mapping[$relative], $target, $false)
    $rows += [ordered]@{ path = $relative; sha256 = Get-CollectorSetupHash $target
        bytes = (Get-Item -LiteralPath $target).Length }
}
Verify-Seed (Join-Path $directory 'seed/collector-data')
$schema = 'dc-collector-package-v7'
$mode = 'EXPLICIT_DISTRIBUTION_DATA_DAILY'
$manifest = [ordered]@{ schema = $schema; version = $Version
    architecture = 'x64'; mode = $mode; files = $rows }
$utf8 = New-Object Text.UTF8Encoding($false)
# manifest保存、package検査、ZIP、checksumは順次処理する。--check-package不合格も配置内容を削除しない。
# 後段失敗では保存済みpackageや途中ZIP/checksumを保持し、完成成果物とは扱わない。
[IO.File]::WriteAllText((Join-Path $directory 'package-manifest.json'),
    ($manifest | ConvertTo-Json -Depth 8), $utf8)
[void](Read-CollectorBundle $directory)
# Require the rebuilt native setup to accept the actual artifact before packaging it.
& (Join-Path $directory 'DriverCrateCollectorSetup.exe') --check-package $directory
if ($LASTEXITCODE -ne 0) { throw 'PACKAGE_NATIVE_CHECK_REJECTED' }
Compress-Archive -LiteralPath $directory -DestinationPath $archive
$hash = Get-CollectorSetupHash $archive
[IO.File]::WriteAllText($checksum, $hash + '  ' + [IO.Path]::GetFileName($archive) + "`n", $utf8)
[pscustomobject]@{ Package = $archive; Directory = $directory; Sha256 = $hash; Mode = $mode
    PayloadFiles = $rows.Count; TasksRegistered = 0; NetworkRequests = 0
    Signing = $signing; SigningNetworkMayHaveOccurred = ($null -ne $CodeSigning) }
