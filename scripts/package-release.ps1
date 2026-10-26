#requires -Version 7.0
<#
.SYNOPSIS
Creates the DriverCrate Windows x64 release package and SHA-256 file.

.DESCRIPTION
Copies only the release executable and public distribution documents into an exact package
directory below out, creates a ZIP archive, and writes its SHA-256 checksum. The script does not
download dependencies. Optional CodeSigning verifies and signs the existing build before copying it;
omitting it preserves the certificate-free development path. See docs/adr/0406-verified-authenticode-build-transition.md.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '0.1.1',
    [string]$BuildDirectory = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../build'))),
    [string]$OutputDirectory,
    [hashtable]$CodeSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
$context = Resolve-IndexPackageBuild -BuildDirectory $BuildDirectory
$releaseExecutable = Join-Path $context.Build 'Release/DriverCrate.exe'
Assert-IndexPackageExecutable -Executable $releaseExecutable
$explicitOutput = $PSBoundParameters.ContainsKey('OutputDirectory')
$outputRoot = if ($explicitOutput) {
    Assert-IndexPackageOutput -Context $context -Path $OutputDirectory -Fresh
} else {
    Assert-IndexPackageOutput -Context $context -Path (Join-Path $repositoryRoot 'out') -AllowRoot
}
$packageName = "DriverCrate-$Version-windows-x64"
$packageDirectory = [System.IO.Path]::GetFullPath((Join-Path $outputRoot $packageName))
$archivePath = [System.IO.Path]::GetFullPath((Join-Path $outputRoot "$packageName.zip"))
$checksumPath = [System.IO.Path]::GetFullPath((Join-Path $outputRoot "$packageName.zip.sha256"))

function Assert-OutputPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $expectedPrefix = $outputRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) +
        [System.IO.Path]::DirectorySeparatorChar
    if (!$Path.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Release output escaped the expected directory: $Path"
    }
}

Assert-OutputPath -Path $packageDirectory
Assert-OutputPath -Path $archivePath
Assert-OutputPath -Path $checksumPath

if (!(Test-Path -LiteralPath $releaseExecutable -PathType Leaf)) {
    throw "Release executable was not found: $releaseExecutable"
}

$productVersion = (Get-Item -LiteralPath $releaseExecutable).VersionInfo.ProductVersion
if ($productVersion -ne $Version) {
    throw "Executable version '$productVersion' does not match package version '$Version'."
}

# 元成果物を自動削除せず、同版三出力の一つでも存在した場合は作成前に拒否する。
foreach ($target in @($packageDirectory, $archivePath, $checksumPath)) {
    if (Test-Path -LiteralPath $target) { throw 'INDEX_PACKAGE_NEW_OUTPUT_REQUIRED' }
}
$signing = $null
if ($null -ne $CodeSigning) {
    . (Join-Path $PSScriptRoot 'release_signing.ps1')
    $signing = Invoke-ReleaseBuildSigning -Context $context -Role App -CodeSigning $CodeSigning
}
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $packageDirectory | Out-Null
Copy-Item -LiteralPath $releaseExecutable -Destination $packageDirectory
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'README.md') -Destination $packageDirectory
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'LICENSE') -Destination $packageDirectory
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'THIRD_PARTY_NOTICES.md') `
    -Destination $packageDirectory

$packageFiles = @(Get-ChildItem -LiteralPath $packageDirectory -File | Select-Object -Expand FullName)
Compress-Archive -LiteralPath $packageFiles -DestinationPath $archivePath
$archiveHash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
$checksumLine = "$($archiveHash.Hash.ToLowerInvariant())  $([System.IO.Path]::GetFileName($archivePath))"
Set-Content -LiteralPath $checksumPath -Value $checksumLine -Encoding ascii

[PSCustomObject]@{
    Package = $archivePath
    Checksum = $checksumPath
    Sha256 = $archiveHash.Hash.ToLowerInvariant()
    Signing = $signing
}
