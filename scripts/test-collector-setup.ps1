#requires -Version 7.0
<#
.SYNOPSIS
現行v7 package/receiptと未知形式拒否を新規copyで有限検査する。
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実Task・通信・install/uninstallを開始しない。原packageと全fixtureを保持する。
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][string] $FixtureRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $repo 'packaging/collector/collector-setup.psm1') -Force -DisableNameChecking
$bundle = Read-CollectorBundle $PackageDirectory
$base = Assert-CollectorSetupPath $FixtureRoot
if (Test-Path -LiteralPath $base) { throw 'FIXTURE_FRESH_REQUIRED' }
if ($base.StartsWith($bundle.Root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'FIXTURE_PACKAGE_OVERLAP' }
[void][IO.Directory]::CreateDirectory($base)
$package = Join-Path $base 'package'
Copy-Item -LiteralPath $bundle.Root -Destination $package -Recurse
$script:checks = 0
$utf8 = [Text.UTF8Encoding]::new($false)
function Check([bool] $Value) {
    ++$script:checks
    if (-not $Value) { throw ('CURRENT_SETUP_CHECK_' + $script:checks) }
}
function Reject([scriptblock] $Operation, [string] $Reason) {
    $observed = ''
    try { & $Operation | Out-Null } catch { $observed = $_.Exception.Message }
    Check ($observed -ceq $Reason)
}
function Save-Json([string] $Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), $utf8)
}
$manifestPath = Join-Path $package 'package-manifest.json'
$raw = [IO.File]::ReadAllBytes($manifestPath)
$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
$includesReference = @($manifest.files | Where-Object { $_.path -ceq 'seed/distribution-data/reference.json' }).Count -eq 1
$payloadCount = @(Get-CollectorPayloadFiles -IncludeReference:$includesReference).Count
Check ($manifest.files.Count -eq $payloadCount)
Check ((Read-CollectorBundle $package).ManifestHash -ceq $bundle.ManifestHash)
# 参考つきの通常packageをnativeにも渡し、取得やTaskを開始せず完全集合の正例を確認する。
if ($includesReference) {
    $setup = Join-Path $package 'DriverCrateCollectorSetup.exe'
    $out = @(& $setup --check-package $package)
    Check ($LASTEXITCODE -eq 0 -and ($out -join '') -match 'SETUP_CHECK_COMPLETE')
    $referencePath = Join-Path $package 'seed/distribution-data/reference.json'
    $referenceRaw = [IO.File]::ReadAllBytes($referencePath)
    $reference = [Text.Encoding]::UTF8.GetString($referenceRaw) | ConvertFrom-Json
    Check (-not $reference.privateEvidence -and -not $reference.communicationAuthorized)
    $indexPath = Join-Path $package 'seed/distribution-data/references/index.json'
    $indexRaw = [IO.File]::ReadAllBytes($indexPath)
    [IO.File]::WriteAllText($indexPath, '{}', $utf8)
    Reject { Read-CollectorBundle $package } 'SETUP_PAYLOAD_HASH_REJECTED'
    $out = @(& $setup --check-package $package)
    Check ($LASTEXITCODE -eq 2 -and ($out -join '') -match 'PAYLOAD_HASH')
    [IO.File]::WriteAllBytes($indexPath, $indexRaw)
    Move-Item -LiteralPath $indexPath -Destination ($indexPath + '.held')
    Reject { Read-CollectorBundle $package } 'SETUP_FILE_INVENTORY_REJECTED'
    $out = @(& $setup --check-package $package)
    Check ($LASTEXITCODE -eq 2 -and ($out -join '') -match 'INVENTORY_EXTRA')
    Move-Item -LiteralPath ($indexPath + '.held') -Destination $indexPath
    $unknownPath = Join-Path $package 'seed/distribution-data/references/unknown.json'
    [IO.File]::WriteAllText($unknownPath, '{}', $utf8)
    Reject { Read-CollectorBundle $package } 'SETUP_FILE_INVENTORY_REJECTED'
    $out = @(& $setup --check-package $package)
    Check ($LASTEXITCODE -eq 2 -and ($out -join '') -match 'INVENTORY_EXTRA')
    Remove-Item -LiteralPath $unknownPath
    # 全hashを再結合した偽通信許可でも、参考dataからauthorityを発行させない。
    $dataManifestPath = Join-Path $package 'seed/distribution-data/manifest.json'
    $dataManifestRaw = [IO.File]::ReadAllBytes($dataManifestPath)
    $dataManifest = [Text.Encoding]::UTF8.GetString($dataManifestRaw) | ConvertFrom-Json
    $reference.communicationAuthorized = $true
    Save-Json $referencePath $reference
    $refRow = @($dataManifest.files | Where-Object { $_.path -ceq 'reference.json' })[0]
    $refRow.sha256 = Get-CollectorSetupHash $referencePath
    $refRow.bytes = (Get-Item -LiteralPath $referencePath).Length
    Save-Json $dataManifestPath $dataManifest
    foreach ($relative in @('seed/distribution-data/reference.json', 'seed/distribution-data/manifest.json')) {
        $row = @($manifest.files | Where-Object { $_.path -ceq $relative })[0]
        $row.sha256 = Get-CollectorSetupHash (Join-Path $package $relative)
        $row.bytes = (Get-Item -LiteralPath (Join-Path $package $relative)).Length
    }
    Save-Json $manifestPath $manifest
    Reject { Read-CollectorBundle $package } 'SETUP_REFERENCE_BOUNDARY_REJECTED'
    $out = @(& $setup --check-package $package)
    Check ($LASTEXITCODE -eq 2 -and ($out -join '') -match 'DISTRIBUTION_REFERENCE_BOUNDARY')
    [IO.File]::WriteAllBytes($referencePath, $referenceRaw)
    [IO.File]::WriteAllBytes($dataManifestPath, $dataManifestRaw)
    [IO.File]::WriteAllBytes($manifestPath, $raw)
    $manifest = [Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
    Check ((Read-CollectorBundle $package).ManifestHash -ceq $bundle.ManifestHash)
}
# 廃止版はfileを調べる前のschemaで拒否し、自動変換しない。
foreach ($schema in @('dc-collector-package-v1', 'dc-collector-package-v2', 'dc-collector-package-v3',
    'dc-collector-package-v4', 'dc-collector-package-v5', 'dc-collector-package-v6', 'unknown-package')) {
    $manifest.schema = $schema
    Save-Json $manifestPath $manifest
    Reject { Read-CollectorBundle $package } 'SETUP_MANIFEST_REJECTED'
    $out = @(& (Join-Path $package 'DriverCrateCollectorSetup.exe') --check-package $package)
    Check ($LASTEXITCODE -eq 2 -and ($out -join '') -match 'MANIFEST_SCHEMA')
}
[IO.File]::WriteAllBytes($manifestPath, $raw)
$receiptPath = Join-Path $package 'install-receipt.json'
$receipt = [ordered]@{ schema = 'dc-collector-install-receipt-v3'; packageManifestSha256 = $bundle.ManifestHash
    installedUtc = '2026-10-24T00:00:00Z' }
Save-Json $receiptPath $receipt
Check ((Read-CollectorBundle $package -Installed).ManifestHash -ceq $bundle.ManifestHash)
foreach ($schema in @('dc-collector-install-receipt-v1', 'dc-collector-install-receipt-v2', 'unknown-receipt')) {
    $receipt.schema = $schema
    Save-Json $receiptPath $receipt
    Reject { Read-CollectorBundle $package -Installed } 'SETUP_RECEIPT_REJECTED'
    $out = @(& (Join-Path $package 'DriverCrateCollectorSetup.exe') --check-installed $package)
    Check ($LASTEXITCODE -eq 2 -and ($out -join '') -match 'RECEIPT_BINDING')
}
$receipt.schema = 'dc-collector-install-receipt-v3'
Save-Json $receiptPath $receipt
# ShouldProcessの確認だけでは実Taskや削除を開始しない。
Uninstall-CollectorWorkspace $package -WhatIf | Out-Null
Check (Test-Path -LiteralPath (Join-Path $package 'bin/DriverCrateCollector.exe'))
$saved = [IO.File]::ReadAllBytes((Join-Path $package 'LICENSE'))
[IO.File]::WriteAllText((Join-Path $package 'LICENSE'), 'changed', $utf8)
Reject { Read-CollectorBundle $package -Installed } 'SETUP_PAYLOAD_HASH_REJECTED'
[IO.File]::WriteAllBytes((Join-Path $package 'LICENSE'), $saved)
Reject { Assert-CollectorSetupPath 'relative' } 'SETUP_PATH_REJECTED'
Reject { Assert-CollectorSetupPath ($base + ':stream') } 'SETUP_PATH_REJECTED'
Check ((Get-CollectorSetupHash (Join-Path $bundle.Root 'package-manifest.json')) -ceq $bundle.ManifestHash)
[pscustomobject]@{ result = 'PASS'; checks = $script:checks; packageSchema = 'dc-collector-package-v7'
    receiptSchema = 'dc-collector-install-receipt-v3'; payloadFiles = $payloadCount; reference = $includesReference; fixture = $base
    tasks = 0; network = 0; install = 'NOT_RUN'; uninstall = 'NOT_RUN' } | ConvertTo-Json -Compress
