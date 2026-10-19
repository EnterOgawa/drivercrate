<#
.SYNOPSIS
Creates the unsigned DriverCrate Windows x64 release package and SHA-256 file.

.DESCRIPTION
Copies only the release executable and public distribution documents into an exact package
directory below out, creates a ZIP archive, and writes its SHA-256 checksum. The script does not
sign binaries or download dependencies.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '0.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$releaseExecutable = Join-Path $repositoryRoot 'build\Release\DriverCrate.exe'
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
Assert-DistributableIndexBuild -Executable $releaseExecutable
$outputRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'out'))
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

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

# 正規化済みout配下の同版固定directory/ZIP/checksumを先に除去して再生成する。
# 後段のcopy・圧縮・保存が失敗しても旧成果物を復元せず、途中成果物が残る場合がある。
if (Test-Path -LiteralPath $packageDirectory) {
    Remove-Item -LiteralPath $packageDirectory -Recurse -Force
}
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}
if (Test-Path -LiteralPath $checksumPath) {
    Remove-Item -LiteralPath $checksumPath -Force
}

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
}
