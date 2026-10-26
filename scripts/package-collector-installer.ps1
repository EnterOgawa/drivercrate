#requires -Version 7.0
<#
.SYNOPSIS
検査済み現行v7閉包から、唯一buildでWindows x64単体setup EXEを生成する。署名は明示任意。
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
MSVC環境とCMakeを開発時だけ使用する。依存download、配置、Task、公開は行わない。
CodeSigning指定時は同証明書の内PEを検証し、resource/build後のouterだけをADR0406に従い署名する。
生成resource入力はbuild/generatedに残し、通常profileのpayload optionはfinallyで空へ戻す。
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][string] $OutputDirectory,
    [string] $BuildDirectory = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../build'))),
    [hashtable] $CodeSigning)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $repo 'packaging/collector/collector-setup.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
$context = Resolve-IndexPackageBuild -BuildDirectory $BuildDirectory -RequireCollector
$build = $context.Build
$output = Assert-IndexPackageOutput -Context $context -Path $OutputDirectory -Fresh
$bundle = Read-CollectorBundle $PackageDirectory
Assert-IndexPackageDistinctPaths -Paths @($bundle.Root, $output)
# 現行v7の固定閉包だけを単体EXEへ結合する。
$includesReference = @($bundle.Manifest.files | Where-Object { $_.path -ceq 'seed/distribution-data/reference.json' }).Count -eq 1
$payloadCount = @(Get-CollectorPayloadFiles -IncludeReference:$includesReference).Count
if ($bundle.Manifest.schema -cne 'dc-collector-package-v7' -or
    @($bundle.Manifest.files).Count -ne $payloadCount) { throw 'INSTALLER_CURRENT_PACKAGE_REQUIRED' }
$inner = Join-Path $bundle.Root 'DriverCrateCollectorSetup.exe'
Assert-IndexPackageExecutable -Executable (Join-Path $build 'Release/DriverCrateCollector.exe')
Assert-IndexPackageExecutable -Executable (Join-Path $build 'Release/DriverCrateCollectorSetup.exe')
$innerSignatures = @()
if ($null -ne $CodeSigning) {
    . (Join-Path $PSScriptRoot 'release_signing.ps1')
    $signingOptions = Get-ReleaseSigningOptions $CodeSigning
    Assert-ReleaseSigningEnvironment $signingOptions
    foreach ($name in @('DriverCrateCollector.exe', 'DriverCrateCollectorSetup.exe')) {
        # 同じ指定signer/timestampの実byteだけをresourceへ渡し、第三者runtimeは署名しない。
        $innerSignatures += Assert-ReleaseSignedExecutable -Executable (Join-Path $build ('Release/' + $name)) -Options $signingOptions
    }
}
# 新しいsourceを同梱したという申告だけを信用せず、全script原byteを現sourceへ結合する。
foreach ($row in @($bundle.Manifest.files)) {
    if ($row.path.StartsWith('scripts/', [StringComparison]::Ordinal) -and
        (Get-CollectorSetupHash (Join-Path $repo $row.path)) -cne $row.sha256) {
        throw 'INSTALLER_SOURCE_PIN_REJECTED'
    }
}
# 原setupとcollectorも今の通常Release実byteへ一致させる。
foreach ($pair in @(@('DriverCrateCollectorSetup.exe', 'DriverCrateCollectorSetup.exe'),
    @('bin/DriverCrateCollector.exe', 'DriverCrateCollector.exe'))) {
    if ((Get-CollectorSetupHash (Join-Path $bundle.Root $pair[0])) -cne
        (Get-CollectorSetupHash (Join-Path $build ('Release/' + $pair[1])))) {
        throw 'INSTALLER_BINARY_PIN_REJECTED'
    }
}
& $inner --check-package $bundle.Root
if ($LASTEXITCODE -ne 0) { throw 'INSTALLER_NATIVE_PACKAGE_REJECTED' }
$project = [IO.File]::ReadAllText((Join-Path $repo 'CMakeLists.txt'))
if ($project -notmatch '(?s)project\(\s*DriverCrate\s+VERSION\s+([0-9.]+)' -or
    $Matches[1] -cne $bundle.Manifest.version) { throw 'INSTALLER_VERSION_REJECTED' }
$version = $bundle.Manifest.version
$generated = Assert-IndexPackagePath -Path (Join-Path $build ('generated/collector-bootstrap-' +
    [Guid]::NewGuid().ToString('N'))) -Directory -AllowMissing
[void][IO.Directory]::CreateDirectory($generated)
$utf8 = [Text.UTF8Encoding]::new($false)
$resourceRows = [Collections.Generic.List[string]]::new()
$tableRows = [Collections.Generic.List[string]]::new()
$pins = @()
[long]$total = 0
$paths = @($bundle.Manifest.files | ForEach-Object { $_.path }) + @('package-manifest.json')
# 固定順の現行payloadとmanifestの原byteを一つずつresourceへ結合する。
for ($i = 0; $i -lt $paths.Count; ++$i) {
    $relative = $paths[$i]
    if ($relative -notmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or
        $relative -match '(^|/)\.{1,2}(/|$)') { throw 'INSTALLER_RESOURCE_PATH' }
    $path = Join-Path $bundle.Root $relative
    $bytes = (Get-Item -LiteralPath $path -Force).Length
    if ($bytes -le 0 -or $bytes -gt 67108864 -or $total -gt 67108864 - $bytes) {
        throw 'INSTALLER_RESOURCE_LIMIT'
    }
    $total += $bytes
    $hash = Get-CollectorSetupHash $path
    $id = 4000 + $i
    $resourceRows.Add(('{0} RCDATA "{1}"' -f $id, $path.Replace('\', '/')))
    $tableRows.Add(('{1}{{L"{0}", {2}U, {3}ULL, L"{4}"}},' -f $relative, "`t", $id, $bytes, $hash))
    $pins += [ordered]@{ path = $relative; resourceId = $id; bytes = $bytes; sha256 = $hash }
}
if ($paths.Count -ne $payloadCount + 1 -or @($paths | Sort-Object -Unique).Count -ne $payloadCount + 1) { throw 'INSTALLER_RESOURCE_COUNT' }
$table = [IO.File]::ReadAllText((Join-Path $repo 'src/app/collector_setup_bootstrap_table.h.in')).
    Replace('@COLLECTOR_RESOURCE_COUNT@', [string]$paths.Count).
    Replace('@COLLECTOR_RESOURCE_ROWS@', ($tableRows -join "`n"))
$resource = [IO.File]::ReadAllText((Join-Path $repo 'src/app/collector_setup_bootstrap.rc.in')).
    Replace('@COLLECTOR_BOOTSTRAP_MANIFEST@', (Join-Path $repo 'src/app/collector_setup.manifest').Replace('\', '/')).
    Replace('@COLLECTOR_VERSION_COMMAS@', $version.Replace('.', ',')).Replace('@COLLECTOR_VERSION@', $version).
    Replace('@COLLECTOR_RESOURCE_RC@', ($resourceRows -join "`n"))
[IO.File]::WriteAllText((Join-Path $generated 'collector_setup_bootstrap_table.h'), $table, $utf8)
[IO.File]::WriteAllText((Join-Path $generated 'collector_setup_bootstrap.rc'), $resource, $utf8)
$cmake = (Get-Command cmake.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
Invoke-IndexPackageBuildAndRestore -Operation {
    [void](Resolve-IndexPackageBuild -BuildDirectory $build -RequireCollector)
    & $cmake -S $repo -B $build ('-DDRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH=' + $generated)
    if ($LASTEXITCODE -ne 0) { throw 'INSTALLER_CONFIGURE_FAILED' }
    [void](Resolve-IndexPackageBuild -BuildDirectory $build -AllowedEmbeddedResources @($generated) -RequireCollector)
    & $cmake --build $build --config Release --target DriverCrateCollectorInstaller --parallel 16
    if ($LASTEXITCODE -ne 0) { throw 'INSTALLER_BUILD_FAILED' }
    $executable = Join-Path $build 'Release/DriverCrateCollectorInstaller.exe'
    & $executable --check-embedded
    if ($LASTEXITCODE -ne 0) { throw 'INSTALLER_EMBEDDED_REJECTED' }
    # 生成中の入力置換も検出し、固定pinと違うpackageを完成としない。
    foreach ($pin in $pins) {
        if ((Get-CollectorSetupHash (Join-Path $bundle.Root $pin.path)) -cne $pin.sha256) {
            throw 'INSTALLER_INPUT_CHANGED'
        }
    }
    [void][IO.Directory]::CreateDirectory($output)
    $asset = Join-Path $output ('DriverCrateCollectorSetup-' + $version + '-windows-x64.exe')
    [IO.File]::Copy($executable, $asset, $false)
    Assert-CollectorX64Executable $asset
    $hash = Get-CollectorSetupHash $asset
    $signing = $null
    if ($null -ne $CodeSigning) {
        $signing = Invoke-ReleaseInstallerAssetSigning -Executable $asset -ExpectedSha256 $hash `
            -BuildDirectory $build -CodeSigning $CodeSigning
        $hash = Get-CollectorSetupHash $asset
        if ($hash -cne $signing.signedSha256) { throw 'INSTALLER_SIGNED_ASSET_CHANGED' }
    }
    [IO.File]::WriteAllText(($asset + '.sha256'), $hash + '  ' + [IO.Path]::GetFileName($asset) + "`n", $utf8)
    $result = [ordered]@{ schema = 'dc-collector-single-exe-build-v1'; executable = $asset
        bytes = (Get-Item -LiteralPath $asset).Length; sha256 = $hash; version = $version
        architecture = 'x64'; signed = ($null -ne $signing -and $signing.signed); payloadFiles = $payloadCount; packageFiles = $payloadCount + 1
        signing = $signing; innerSignatures = $innerSignatures
        packageRoot = $bundle.Root; manifestSha256 = $bundle.ManifestHash; resourcePins = $pins
        generatedResources = $generated; stagingRetained = $true
        network = $(if ($null -eq $CodeSigning) { 0 } else { $null }); tasks = 0
        signingNetworkMayHaveOccurred = ($null -ne $CodeSigning) }
    [IO.File]::WriteAllText((Join-Path $output 'installer-build.json'), ($result | ConvertTo-Json -Depth 8), $utf8)
    [pscustomobject]$result
} -Restore {
    # 元cache又は自身が生成したresource pathだけを認証し、別sourceへconfigureしない。
    [void](Resolve-IndexPackageBuild -BuildDirectory $build -AllowedEmbeddedResources @('', $generated) -RequireCollector)
    & $cmake -S $repo -B $build '-DDRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH='
    if ($LASTEXITCODE -ne 0) { throw 'INSTALLER_NORMAL_PROFILE_RESTORE_FAILED' }
    [void](Resolve-IndexPackageBuild -BuildDirectory $build -RequireCollector)
}
