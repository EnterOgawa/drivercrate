#requires -Version 5.1
<#
.SYNOPSIS
Creates a local unsigned Windows x64 manual collector preview ZIP.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Uses an explicitly rebuilt Release collector. Does not build, download, publish, or overwrite.
#>
[CmdletBinding()]
param([ValidatePattern('^\d+\.\d+\.\d+$')][string] $Version = '0.1.0',
    [string] $SeedSnapshot, [string] $RegistrySnapshot, [string] $PythonRuntimeArchive,
    [string] $PythonExecutable, [string] $OutputDirectory, [switch] $ProtectedWorkspace,
    [switch] $ExplicitMonitor)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
Assert-DistributableIndexBuild -Executable (Join-Path $repo 'build\Release\DriverCrateCollector.exe')
Assert-DistributableIndexBuild -Executable (Join-Path $repo 'build\Release\DriverCrateCollectorSetup.exe')
$source = Join-Path $repo 'packaging\collector'
Import-Module (Join-Path $source 'collector-setup.psm1') -Force -DisableNameChecking
$registryRuntime = -not [string]::IsNullOrEmpty($RegistrySnapshot)
# ExplicitMonitorは保護workspaceと組み合わせた場合だけ受け付け、旧modeとの混用を拒否する。
if ($ExplicitMonitor -and -not $ProtectedWorkspace) { throw 'PACKAGE_EXPLICIT_REQUIRES_PROTECTED' }
# ProtectedWorkspaceはregistry/runtime入力を必須にして、保護入口の不足したpackageを作らない。
if ($ProtectedWorkspace -and -not $registryRuntime) { throw 'PACKAGE_WORKSPACE_REQUIRES_RUNTIME' }
# RegistrySnapshotと旧SeedSnapshotの同時指定や、registryとruntime archiveの片方だけの指定を拒否する。
if (($registryRuntime -and $SeedSnapshot) -or ($registryRuntime -ne (-not [string]::IsNullOrEmpty($PythonRuntimeArchive)))) {
    throw 'PACKAGE_MODE_REJECTED'
}
$seeded = $registryRuntime -or -not [string]::IsNullOrEmpty($SeedSnapshot)
function Verify-Seed([string] $Path) {
    $validator = 'collector_payload_evidence.py'
    if ($registryRuntime) { $validator = 'collector_locator_snapshot.py' }
    if ($PythonExecutable) {
        # An explicit build tool is used only for this fixed verifier, never a manifest command.
        & $PythonExecutable -X utf8 -B (Join-Path $repo ('scripts\' + $validator)) verify $Path
    }
    else { & py -3.13 -X utf8 -B (Join-Path $repo ('scripts\' + $validator)) verify $Path }
    if ($LASTEXITCODE -ne 0) { throw 'PACKAGE_SEED_REJECTED' }
}
if ($registryRuntime) { $SeedSnapshot = $RegistrySnapshot }
if ($seeded) {
    $SeedSnapshot = Assert-CollectorSetupPath $SeedSnapshot -Existing
    # Reuse the complete canonical-byte validator before and after copy.
    Verify-Seed $SeedSnapshot
}
$project = [IO.File]::ReadAllText((Join-Path $repo 'CMakeLists.txt'))
# 要求VersionをCMake project版へ一致させ、異なる製品版名でpackageしない。
if ($project -notmatch '(?s)project\(\s*DriverCrate\s+VERSION\s+([0-9.]+)' -or $Matches[1] -cne $Version) {
    throw 'PACKAGE_VERSION_REJECTED'
}
$name = 'DriverCrateCollector-' + $Version + '-windows-x64-preview-' + [Guid]::NewGuid().ToString('N')
$output = Join-Path $repo 'out'
if ($OutputDirectory) { $output = Assert-CollectorSetupPath $OutputDirectory }
$directory = Join-Path $output $name
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
if ($registryRuntime) {
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
    # v5 uses the native shared cached-only verifier at --check-package below; never start online trust here.
    if (-not $ExplicitMonitor) {
        foreach ($native in @('python.exe', 'pythonw.exe', 'python313.dll', 'python3.dll')) {
            $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $runtimeDirectory $native)
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
                throw 'PACKAGE_RUNTIME_SIGNATURE_REJECTED'
            }
        }
    }
}
$mapping = [ordered]@{}
# 固定payload一覧全件を実sourceへ対応付けて通常file hash検査を行い、package相対名のmappingを作る。
foreach ($relative in @(Get-CollectorPayloadFiles -Seeded:$seeded -RegistryRuntime:$registryRuntime -ProtectedWorkspace:$ProtectedWorkspace)) {
    $inputPath = Join-Path $source $relative
    # 固定relativeごとにcollector/setupはRelease、configは正本data、ADR/license/noticeはrepo rootへ割り当てる。非一致は既定packaging sourceを保ちfallthroughしない。
    switch ($relative) {
        'bin/DriverCrateCollector.exe' { $inputPath = Join-Path $repo 'build\Release\DriverCrateCollector.exe' }
        'DriverCrateCollectorSetup.exe' { $inputPath = Join-Path $repo 'build\Release\DriverCrateCollectorSetup.exe' }
        'config/targets.json' { $inputPath = Join-Path $source 'targets.json' }
        'config/monitor-policy.json' { $inputPath = Join-Path $repo 'data/collector-registry/monitor-policy.json' }
        'docs/adr/0209-local-first-recurring-driver-collector.md' { $inputPath = Join-Path $repo $relative }
        'LICENSE' { $inputPath = Join-Path $repo 'LICENSE' }
        'THIRD_PARTY_NOTICES.md' { $inputPath = Join-Path $repo 'THIRD_PARTY_NOTICES.md' }
    }
    if ($relative.StartsWith('seed/collector-data/', [StringComparison]::Ordinal)) {
        $inputPath = Join-Path $SeedSnapshot $relative.Substring('seed/collector-data/'.Length)
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
$schema = 'dc-collector-package-v1'
$mode = 'MANUAL_METADATA_ONLY'
if ($seeded) {
    $schema = 'dc-collector-package-v2'
    $mode = 'MANUAL_METADATA_WITH_RESEARCH_SEED'
    Verify-Seed (Join-Path $directory 'seed\collector-data')
}
# registry/runtime bundleはv3 modeへ上書きし、seedのみv2と区別する。
if ($registryRuntime) {
    $schema = 'dc-collector-package-v3'
    $mode = 'MANUAL_REGISTRY_WITH_RUNTIME'
}
# 保護workspaceはv4 modeへ切り替えてnative保護配置入口を示す。
if ($ProtectedWorkspace) {
    $schema = 'dc-collector-package-v4'
    $mode = 'OFFLINE_PROTECTED_REGISTRY_WORKSPACE'
}
# ExplicitMonitorはv5 modeを最終選択し、明示一回monitor入口と旧offline保護modeを区別する。
if ($ExplicitMonitor) {
    $schema = 'dc-collector-package-v5'
    $mode = 'EXPLICIT_ONCE_REGISTRY_MONITOR'
}
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
[pscustomobject]@{ Package = $archive; Sha256 = $hash; Mode = $mode
    PayloadFiles = $rows.Count; TasksRegistered = 0; NetworkRequests = 0 }
