#requires -Version 7.0
<#
.SYNOPSIS
Builds the per-user App Setup from the verified DriverCrate App/profile pair.
.DESCRIPTION
Consumes exactly five consumer files. Signing is optional for development and uses
the existing certificate/SDK checks plus Inno SignTool for its engine/uninstaller/outer.
No driver, Collector, credential or private key is included.
#>
[CmdletBinding()]
param(
    [string]$BuildDirectory = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../build'))),
    [string]$OutputDirectory = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../output'))),
    [string]$InnoCompiler = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    [hashtable]$CodeSigning,
    [switch]$InstallerTest,
    [string]$TestExecutable
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
. (Join-Path $PSScriptRoot 'app_distribution_documents.ps1')
$context = Resolve-IndexPackageBuild -BuildDirectory $BuildDirectory
$executable = Join-Path $context.Build 'Release/DriverCrate.exe'
if ($TestExecutable) {
    if (-not $InstallerTest -or $CodeSigning) { throw 'APP_SETUP_TEST_INPUT_REJECTED' }
    $executable = Assert-IndexPackagePath -Path $TestExecutable
}
if ($InstallerTest -and $CodeSigning) { throw 'APP_SETUP_TEST_SIGNING_REJECTED' }
Assert-IndexPackageExecutable -Executable $executable
$metadata = [Diagnostics.FileVersionInfo]::GetVersionInfo($executable)
$version = $metadata.ProductVersion
if ($version -cnotmatch '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$' -or
    $metadata.ProductName -cne 'DriverCrate' -or
    @($version.Split('.') | Where-Object { [uint32]$_ -gt 65535 }).Count -ne 0) {
    throw 'APP_SETUP_PRODUCT_REJECTED'
}
$compiler = Assert-IndexPackagePath -Path $InnoCompiler
$destination = Assert-IndexPackagePath -Path $OutputDirectory -Directory -AllowMissing
$flatOutput = Join-Path $repository 'output'
if ($destination.StartsWith($flatOutput + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'APP_SETUP_FLAT_OUTPUT_REQUIRED'
}
if ($InstallerTest -and [string]::Equals($destination, $flatOutput, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'APP_SETUP_TEST_OUTPUT_REJECTED'
}
[void][IO.Directory]::CreateDirectory($destination)
$workspace = Assert-IndexPackagePath -Path (Join-Path $context.Build ('generated/app-setup-' + [Guid]::NewGuid().ToString('N'))) -Directory -AllowMissing
[void][IO.Directory]::CreateDirectory($workspace)
$payload = Join-Path $workspace 'payload'
$compiled = Join-Path $workspace 'compiled'
[void][IO.Directory]::CreateDirectory($payload)
[void][IO.Directory]::CreateDirectory($compiled)
$signing = $null
$options = $null
if ($CodeSigning) {
    . (Join-Path $PSScriptRoot 'release_signing.ps1')
    $options = Get-ReleaseSigningOptions $CodeSigning
    Assert-ReleaseSigningEnvironment $options
    $signature = Get-AuthenticodeSignature -LiteralPath $executable
    if ($signature.Status -eq 'NotSigned') {
        $signing = Invoke-ReleaseBuildSigning -Context $context -Role App -CodeSigning $CodeSigning
    } else {
        $null = Assert-ReleaseSignedExecutable -Executable $executable -Options $options
    }
    Assert-IndexPackageExecutable -Executable $executable
}
$inputs = [ordered]@{
    'DriverCrate.exe' = $executable
    'DriverCrate.exe.index-profile.json' = ($executable + '.index-profile.json')
    'README.md' = (Join-Path $repository 'README.md')
    'LICENSE' = (Join-Path $repository 'LICENSE')
    'THIRD_PARTY_NOTICES.md' = (Join-Path $repository 'THIRD_PARTY_NOTICES.md')
}
$pins = @()
foreach ($name in $inputs.Keys) {
    $source = Assert-IndexPackagePath -Path $inputs[$name]
    $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::Copy($source, (Join-Path $payload $name), $false)
    $pins += [ordered]@{ name = $name; sourceSha256 = $hash }
}
# Resolve same-version distribution links without extra payload files.
$readmePath = Join-Path $payload 'README.md'
$readme = [IO.File]::ReadAllText($readmePath)
$readme = ConvertTo-AppDistributionReadme -Readme $readme -Version $version
[IO.File]::WriteAllText($readmePath, $readme, [Text.UTF8Encoding]::new($false))
$arguments = @('/Qp', "/DBundleDir=$payload", "/DDestinationDir=$compiled", "/DProductVersion=$version")
if ($InstallerTest) { $arguments += '/DAppSetupTestMode' }
if ($CodeSigning) {
    $signedUninstaller = Join-Path $workspace 'inno-signing'
    [void][IO.Directory]::CreateDirectory($signedUninstaller)
    $arguments += '/DSignAppSetup'
    $arguments += "/DSigningWorkspace=$signedUninstaller"
    # Validated public signing metadata only. No PIN/password argument is accepted.
    $store = if ($options.CertificateStore -ceq 'LocalMachine') { ' /sm' } else { '' }
    $command = '$q' + $options.SignToolPath + '$q sign /sha1 ' + $options.CertificateThumbprint +
        ' /s My' + $store + ' /fd SHA256 /tr $q' + $options.TimestampUrl + '$q /td SHA256 $f'
    $arguments += ('/SDriverCrateAppEV=' + $command)
}
$arguments += (Join-Path $repository 'packaging/app/app.iss')
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw 'APP_SETUP_INNO_REJECTED' }
$asset = Assert-IndexPackagePath -Path (Join-Path $compiled 'DriverCrateSetup-windows-x64.exe')
$setup = [Diagnostics.FileVersionInfo]::GetVersionInfo($asset)
if ($setup.ProductName.TrimEnd([char]' ') -cne 'DriverCrate' -or $setup.FileDescription.TrimEnd([char]' ') -cne 'DriverCrate Setup' -or
    $setup.FileMajorPart -ne $metadata.FileMajorPart -or $setup.FileMinorPart -ne $metadata.FileMinorPart -or
    $setup.FileBuildPart -ne $metadata.FileBuildPart -or $setup.FilePrivatePart -ne 0) {
    throw 'APP_SETUP_VERSION_REJECTED'
}
if ($CodeSigning) {
    $null = Assert-ReleaseSignedExecutable -Executable $asset -Options $options
    # Inno's own signed uninstaller can be x86. Do not apply the App AMD64 layout gate.
    $internal = @(Get-ChildItem -LiteralPath $signedUninstaller -File)
    # SignTool signs the uninstaller on-the-fly; a persistent cache may be empty.
    foreach ($item in $internal) {
        $null = Assert-ReleaseSignedExecutable -Executable $item.FullName -Options $options
    }
}
foreach ($pin in $pins) {
    if ((Get-FileHash -LiteralPath $inputs[$pin.name] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.sourceSha256) {
        throw 'APP_SETUP_SOURCE_CHANGED'
    }
}
$sha = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
$target = Join-Path $destination 'DriverCrateSetup-windows-x64.exe'
$checksum = $target + '.sha256'
$previous = Join-Path $workspace 'previous'
[void][IO.Directory]::CreateDirectory($previous)
foreach ($path in @($target, $checksum)) {
    if (Test-Path -LiteralPath $path) {
        $checked = Assert-IndexPackagePath -Path $path
        [IO.File]::Copy($checked, (Join-Path $previous ([IO.Path]::GetFileName($checked))), $false)
    }
}
[IO.File]::Copy($asset, $target, $true)
[IO.File]::WriteAllText($checksum, ($sha + '  DriverCrateSetup-windows-x64.exe' + [char]10), [Text.UTF8Encoding]::new($false))
$result = [ordered]@{
    schema = 'dc-app-inno-build-v1'; version = $version; architecture = 'x64'; scope = 'current-user'
    signed = [bool]$CodeSigning; installerTest = [bool]$InstallerTest
    signedUninstallerCacheFiles = if ($CodeSigning) { $internal.Count } else { 0 }
    setupSha256 = $sha; appSha256 = $pins[0].sourceSha256; profileSha256 = $pins[1].sourceSha256
    inputs = $pins; signing = $signing; output = $target; workspace = $workspace
}
[IO.File]::WriteAllText((Join-Path $workspace 'package-result.json'), ($result | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
[pscustomobject]$result
