#requires -Version 7.0
<#+.SYNOPSIS
隔離人工PEと模擬trustでADR0406の拒否・遷移・package順序を検証する。
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実証明書/store/key/tool/ネットワークを使用しない。人工EXEは実行しない。
新規fixtureだけを作成して保持する。成功は実EV署名の証拠ではない。
#>
[CmdletBinding()]
param([string] $FixtureRoot = (Join-Path ([IO.Path]::GetTempPath()) ('drivercrate-signing-tests-' + [Guid]::NewGuid().ToString('N'))))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
$root = Assert-IndexPackagePath -Path $FixtureRoot -Directory -AllowMissing
if (Test-Path -LiteralPath $root) { throw 'SIGNING_FIXTURE_NEW_ROOT_REQUIRED' }
[void][IO.Directory]::CreateDirectory((Join-Path $root 'scripts'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'src/platform'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'build/Release'))
foreach ($name in @('index_build_profile.ps1', 'release_signing.ps1')) {
    [IO.File]::Copy((Join-Path $repository ('scripts/' + $name)), (Join-Path $root ('scripts/' + $name)), $false)
}
[IO.File]::Copy((Join-Path $repository 'src/platform/index_distribution_trust.h'),
    (Join-Path $root 'src/platform/index_distribution_trust.h'), $false)
. (Join-Path $root 'scripts/index_build_profile.ps1')
. (Join-Path $root 'scripts/release_signing.ps1')
$utf8 = [Text.UTF8Encoding]::new($false)
$tool = Join-Path $root 'signtool.exe'
[IO.File]::WriteAllText($tool, 'ARTIFICIAL TOOL - NEVER EXECUTE', $utf8)
$thumbprint = '1111111111111111111111111111111111111111'
$options = @{ CertificateStore = 'CurrentUser'; CertificateThumbprint = $thumbprint
    SignToolPath = $tool; SignToolSha256 = (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant()
    TimestampUrl = 'https://timestamp.example.invalid/rfc3161' }
$build = Join-Path $root 'build'
$exe = Join-Path $build 'Release/DriverCrate.exe'
$profilePath = $exe + '.index-profile.json'
$cachePath = Join-Path $build 'CMakeCache.txt'
$sourceHeader = [IO.File]::ReadAllText((Join-Path $root 'src/platform/index_distribution_trust.h'))
$fingerprint = [regex]::Match($sourceHeader, 'PUBLIC_FINGERPRINT\s*=\s*"([0-9a-f]{64})"').Groups[1].Value
$caseCount = 0
$signCalls = 0
$verifyCalls = 0
$chainCalls = 0
$mode = 'Good'

function Require([bool] $Condition, [string] $Reason) {
    <# .SYNOPSIS fixtureの条件を省略せず拒否する。 #>
    if (-not $Condition) { throw ('SIGNING_TEST_ASSERT_' + $Reason) }
}
function New-FixtureCertificate([string] $Thumbprint, [string] $Eku) {
    <# .SYNOPSIS 秘密鍵を持たない単純objectで境界からの観測を模擬する。 #>
    return [pscustomobject]@{ Thumbprint = $Thumbprint; Subject = 'CN=Artificial Publisher'; Issuer = 'CN=Artificial CA'
        HasPrivateKey = $true; NotBefore = [DateTime]::UtcNow.AddDays(-1); NotAfter = [DateTime]::UtcNow.AddDays(1)
        Extensions = @([pscustomobject]@{ Oid = [pscustomobject]@{ Value = '2.5.29.37' }
            EnhancedKeyUsages = @([pscustomobject]@{ Value = $Eku }) }) }
}
function Get-Item {
    <# .SYNOPSIS Cert providerの明示一件だけを模擬し、他pathは元のfile cmdletへ渡す。 #>
    [CmdletBinding()]param([string] $LiteralPath, [switch] $Force)
    if ($LiteralPath.StartsWith('Cert:\', [StringComparison]::Ordinal)) {
        Require ($LiteralPath -ceq ('Cert:\CurrentUser\My\' + $thumbprint)) 'CERT_EXACT_SELECTION'
        $cert = New-FixtureCertificate $thumbprint '1.3.6.1.5.5.7.3.3'
        if ($mode -ceq 'Expired') { $cert.NotAfter = [DateTime]::UtcNow.AddDays(-1) }
        if ($mode -ceq 'Future') { $cert.NotBefore = [DateTime]::UtcNow.AddDays(1) }
        if ($mode -ceq 'NoKey') { $cert.HasPrivateKey = $false }
        if ($mode -ceq 'SelfIssued') { $cert.Issuer = $cert.Subject }
        if ($mode -ceq 'CertEku') { $cert.Extensions = @() }
        return $cert
    }
    return Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}
function Assert-ReleaseCodeSigningChain {
    <# .SYNOPSIS 実Windows chain境界を模擬する。実trustへ数えない。 #>
    param($Certificate)
    $script:chainCalls++
    Require ($Certificate.Thumbprint -ceq $thumbprint) 'CHAIN_CERTIFICATE'
    if ($mode -ceq 'ChainFailure') { throw 'RELEASE_SIGNING_CERTIFICATE_CHAIN_REJECTED' }
    if ($mode -ceq 'PreSignOriginalChange') {
        $bytes = [IO.File]::ReadAllBytes($exe)
        $bytes[600] = $bytes[600] -bxor 1
        [IO.File]::WriteAllBytes($exe, $bytes)
    }
}
function Get-AuthenticodeSignature {
    <# .SYNOPSIS Windows signature観測だけを模擬し、実Wintrust/storeへ接続しない。 #>
    param([string] $LiteralPath)
    $signer = New-FixtureCertificate $thumbprint '1.3.6.1.5.5.7.3.3'
    $timestamp = New-FixtureCertificate ('2' * 40) '1.3.6.1.5.5.7.3.8'
    $signature = [pscustomobject]@{ Status = 'Valid'; SignatureType = 'Authenticode'
        SignerCertificate = $signer; TimeStamperCertificate = $timestamp }
    if ($LiteralPath -ceq $tool) {
        $signer.Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, C=US'
        if ($mode -ceq 'ToolUntrusted') { $signature.Status = 'NotTrusted' }
        if ($mode -ceq 'ToolWrongPublisher') { $signer.Subject = 'CN=Artificial Publisher' }
        return $signature
    }
    if ($mode -ceq 'Unsigned') { $signature.Status = 'NotSigned' }
    if ($mode -ceq 'Catalog') { $signature.SignatureType = 'Catalog' }
    if ($mode -ceq 'WrongSigner') { $signer.Thumbprint = '3' * 40 }
    if ($mode -ceq 'NoTimestamp') { $signature.TimeStamperCertificate = $null }
    if ($mode -ceq 'SignerEku') { $signer.Extensions = @() }
    if ($mode -ceq 'TimestampEku') { $timestamp.Extensions = @() }
    if ($mode -ceq 'CandidateChange') {
        $bytes = [IO.File]::ReadAllBytes($LiteralPath)
        $bytes[600] = $bytes[600] -bxor 1
        [IO.File]::WriteAllBytes($LiteralPath, $bytes)
    }
    return $signature
}
function New-FixturePe {
    <# .SYNOPSIS 非実行のx64/PE32+ header/section/overlayを所有byteへ生成する。 #>
    $bytes = [byte[]]::new(1027)
    $bytes[0] = 77; $bytes[1] = 90
    [Array]::Copy([BitConverter]::GetBytes([int]128), 0, $bytes, 60, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]17744), 0, $bytes, 128, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint16]34404), 0, $bytes, 132, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]2), 0, $bytes, 134, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]240), 0, $bytes, 148, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]523), 0, $bytes, 152, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $bytes, 260, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]8192), 0, $bytes, 280, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $bytes, 284, 4)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('.text'), 0, $bytes, 392, 5)
    [Array]::Copy([BitConverter]::GetBytes([uint32]4096), 0, $bytes, 404, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]256), 0, $bytes, 408, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]512), 0, $bytes, 412, 4)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('.rsrc'), 0, $bytes, 432, 5)
    [Array]::Copy([BitConverter]::GetBytes([uint32]8192), 0, $bytes, 444, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]256), 0, $bytes, 448, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]768), 0, $bytes, 452, 4)
    $bytes[600] = 17; $bytes[900] = 34; $bytes[1026] = 51
    return ,$bytes
}
function Add-FixtureSignature([byte[]] $Original) {
    <# .SYNOPSIS alignment/一個のWIN_CERTIFICATEだけを追加する。暗号署名ではない。 #>
    $aligned = $Original.Length + ((8 - $Original.Length % 8) % 8)
    $bytes = [byte[]]::new($aligned + 24)
    [Array]::Copy($Original, $bytes, $Original.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]123), 0, $bytes, 216, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$aligned), 0, $bytes, 296, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]24), 0, $bytes, 300, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]20), 0, $bytes, $aligned, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint16]512), 0, $bytes, $aligned + 4, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]2), 0, $bytes, $aligned + 6, 2)
    $bytes[$aligned + 8] = 91
    return ,$bytes
}
function Invoke-ReleaseSignTool {
    <# .SYNOPSIS 固定argvを検査して人工byteだけを操作する。実process起動0。 #>
    param([hashtable] $Options, [string[]] $Arguments)
    if ($Arguments[0] -ceq 'sign') {
        $script:signCalls++
        $candidate = $Arguments[-1]
        Require ($Arguments.Count -eq 12 -and ($Arguments -join '|') -ceq
            ('sign|/sha1|' + $thumbprint + '|/s|My|/fd|SHA256|/tr|' + $options.TimestampUrl + '|/td|SHA256|' + $candidate)) 'SIGN_ARGV'
        if ($mode -ceq 'SignFailure') { throw 'RELEASE_SIGNING_TOOL_FAILED_1' }
        $bytes = Add-FixtureSignature ([IO.File]::ReadAllBytes($candidate))
        if ($mode -ceq 'ImageChange') { $bytes[600] = $bytes[600] -bxor 1 }
        [IO.File]::WriteAllBytes($candidate, $bytes)
        if ($mode -ceq 'OriginalChange') { [IO.File]::WriteAllText($exe, 'changed original', $utf8) }
        if ($mode -ceq 'ProfileChange') { [IO.File]::WriteAllText($profilePath, '{}', $utf8) }
    } else {
        $script:verifyCalls++
        Require ($Arguments.Count -eq 5 -and ($Arguments[0..3] -join '|') -ceq 'verify|/pa|/all|/tw') 'VERIFY_ARGV'
        if ($mode -ceq 'VerifyFailure') { throw 'RELEASE_SIGNING_TOOL_FAILED_2' }
    }
}
function Reset-Fixture {
    <# .SYNOPSIS 次case用の人工原byteと通常cache/v2を新規内容へ戻す。実buildではない。 #>
    $script:mode = 'Good'
    [IO.File]::WriteAllBytes($exe, (New-FixturePe))
    $profile = [ordered]@{ schema = 'drivercrate-index-build-profile-v2'; localAcceptance = $false
        sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        distributionFingerprint = $fingerprint; acquisitionPolicyRevision = 1 }
    [IO.File]::WriteAllText($profilePath, ($profile | ConvertTo-Json -Compress), $utf8)
    $cache = @(('CMAKE_HOME_DIRECTORY:INTERNAL=' + $root.Replace('\', '/')),
        'CMAKE_GENERATOR:INTERNAL=Ninja Multi-Config', 'CMAKE_CONFIGURATION_TYPES:STRING=Debug;Release',
        'DRIVERCRATE_BUILD_COLLECTOR:BOOL=ON', 'DRIVERCRATE_BUILD_LIVE_TESTS:BOOL=OFF',
        'DRIVERCRATE_ENABLE_ANALYZE:BOOL=OFF', 'DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE:BOOL=OFF',
        'DRIVERCRATE_LOCAL_INDEX_ACQUISITION:BOOL=OFF', 'DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB:FILEPATH=',
        'DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256:STRING=', 'DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH=') -join "`n"
    [IO.File]::WriteAllText($cachePath, $cache + "`n", $utf8)
}
function Invoke-Case([string] $Name, [scriptblock] $Action, [string] $ErrorPattern = '') {
    <# .SYNOPSIS 各元結果を保存し、予定した拒否以外の失敗を成功へ数えない。 #>
    Reset-Fixture
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_.Exception.Message }
    if ($ErrorPattern) { Require ($null -ne $caught -and $caught -match $ErrorPattern) ($Name + '_EXPECTED_REJECTION_' + $caught) }
    else { Require ($null -eq $caught) ($Name + '_UNEXPECTED_' + $caught) }
    $script:caseCount++
    'SIGNING_CASE ' + (@{ name = $Name; passed = $true; originalError = $caught } | ConvertTo-Json -Compress)
}

Invoke-Case 'signature-only-profile-promotion' {
    $original = [IO.File]::ReadAllBytes($exe)
    $result = Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options
    Require ($result.signed -and $result.signature.verified -and $result.role -ceq 'App') 'VERIFIED_RESULT'
    Require ($result.originalSha256 -cne $result.signedSha256) 'FULL_HASH_CHANGED'
    $profile = [IO.File]::ReadAllText($profilePath) | ConvertFrom-Json
    Require ($profile.sha256 -ceq $result.signedSha256) 'SIGNED_PROFILE_BOUND'
    Require ([IO.File]::ReadAllBytes((Join-Path $result.stageDirectory 'original.exe')).Length -eq $original.Length) 'ORIGINAL_RETAINED'
    Assert-IndexPackageExecutable $exe
}
$rejections = [ordered]@{ SignFailure = 'TOOL_FAILED_1'; VerifyFailure = 'TOOL_FAILED_2'; ImageChange = 'IMAGE_CHANGED'
    Unsigned = 'SIGNATURE_REJECTED'; Catalog = 'SIGNATURE_REJECTED'; WrongSigner = 'SIGNATURE_REJECTED'
    NoTimestamp = 'SIGNATURE_REJECTED'; SignerEku = 'SIGNATURE_REJECTED'; TimestampEku = 'SIGNATURE_REJECTED'
    ToolUntrusted = 'TOOL_TRUST_REJECTED'; ToolWrongPublisher = 'TOOL_TRUST_REJECTED'
    Expired = 'CERTIFICATE_REJECTED'; Future = 'CERTIFICATE_REJECTED'; NoKey = 'CERTIFICATE_REJECTED'
    SelfIssued = 'CERTIFICATE_REJECTED'; CertEku = 'CERTIFICATE_REJECTED'
    ChainFailure = 'CERTIFICATE_CHAIN_REJECTED'; CandidateChange = 'CANDIDATE_CHANGED' }
foreach ($testMode in $rejections.Keys) {
    Invoke-Case ('reject-' + $testMode) {
        $beforeExe = (Get-FileHash -LiteralPath $exe).Hash
        $beforeProfile = (Get-FileHash -LiteralPath $profilePath).Hash
        $script:mode = $testMode
        try { Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options }
        finally {
            Require ((Get-FileHash -LiteralPath $exe).Hash -ceq $beforeExe) 'REJECT_PRESERVES_ORIGINAL_EXE'
            Require ((Get-FileHash -LiteralPath $profilePath).Hash -ceq $beforeProfile) 'REJECT_PRESERVES_ORIGINAL_PROFILE'
        }
    } ('^RELEASE_SIGNING_' + $rejections[$testMode] + '$')
}
foreach ($role in @('Collector', 'CollectorSetup')) {
    Invoke-Case ('fixed-role-' + $role) {
        $name = if ($role -ceq 'Collector') { 'DriverCrateCollector.exe' } else { 'DriverCrateCollectorSetup.exe' }
        $target = Join-Path $build ('Release/' + $name)
        [IO.File]::Copy($exe, $target, $true)
        [IO.File]::Copy($profilePath, ($target + '.index-profile.json'), $true)
        $appHash = (Get-FileHash -LiteralPath $exe).Hash
        $result = Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role $role -CodeSigning $options
        Require ($result.signed -and $result.role -ceq $role) 'FIXED_COLLECTOR_ROLE'
        Require ((Get-FileHash -LiteralPath $exe).Hash -ceq $appHash) 'UNSELECTED_APP_UNCHANGED'
        Assert-IndexPackageExecutable $target
    }
}
Invoke-Case 'profile-cas-rejects-change' {
    $script:mode = 'ProfileChange'
    Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options
} '^RELEASE_SIGNING_ORIGINAL_CHANGED$'
Invoke-Case 'pre-sign-copy-hash-rejects-before-key-use' {
    $beforeCalls = $signCalls
    $beforeProfile = (Get-FileHash -LiteralPath $profilePath).Hash
    $script:mode = 'PreSignOriginalChange'
    try { Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options }
    finally {
        Require ($signCalls -eq $beforeCalls) 'UNVERIFIED_COPY_NEVER_SIGNED'
        Require ((Get-FileHash -LiteralPath $profilePath).Hash -ceq $beforeProfile) 'UNVERIFIED_COPY_PROFILE_UNCHANGED'
    }
} '^RELEASE_SIGNING_ORIGINAL_CHANGED$'
Invoke-Case 'original-cas-rejects-change' {
    $script:mode = 'OriginalChange'
    Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options
} '^RELEASE_SIGNING_'
Invoke-Case 'wrong-role' {
    Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role Runtime -CodeSigning $options
} '^RELEASE_SIGNING_ROLE_REJECTED$'
Invoke-Case 'stale-original-profile' {
    [IO.File]::WriteAllBytes($exe, (Add-FixtureSignature (New-FixturePe)))
    Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options
} '^INDEX_BUILD_PROFILE_STALE_EXECUTABLE$'
Invoke-Case 'local-profile' {
    $text = [IO.File]::ReadAllText($profilePath).Replace('"localAcceptance":false', '"localAcceptance":true')
    [IO.File]::WriteAllText($profilePath, $text, $utf8)
    Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options
} '^LOCAL_INDEX_ACCEPTANCE_BUILD_NOT_DISTRIBUTABLE$'
Invoke-Case 'wrong-source' {
    [IO.File]::WriteAllText($cachePath, [IO.File]::ReadAllText($cachePath).Replace($root.Replace('\', '/'), $build.Replace('\', '/')), $utf8)
    Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options
} '^INDEX_PACKAGE_SOURCE_MISMATCH$'
Invoke-Case 'signed-input-not-resigned' {
    [IO.File]::WriteAllBytes($exe, (Add-FixtureSignature (New-FixturePe)))
    $profile = [IO.File]::ReadAllText($profilePath) | ConvertFrom-Json -AsHashtable
    $profile.sha256 = (Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($profilePath, ($profile | ConvertTo-Json -Compress), $utf8)
    Invoke-ReleaseBuildSigning -Context ([pscustomobject]@{ Build = $build }) -Role App -CodeSigning $options
} '^RELEASE_SIGNING_UNSIGNED_INPUT_REQUIRED$'
foreach ($change in @('Section', 'Resource', 'FinalOverlay', 'Alignment', 'CertificatePadding', 'CertificateType', 'CertificateOffset', 'Trailer')) {
    Invoke-Case ('image-reject-' + $change) {
        $bytes = Add-FixtureSignature (New-FixturePe)
        switch ($change) {
            'Section' { $bytes[600] = 18 }
            'Resource' { $bytes[900] = 35 }
            'FinalOverlay' { $bytes[1026] = 52 }
            'Alignment' { $bytes[1027] = 1 }
            'CertificatePadding' { $bytes[-1] = 1 }
            'CertificateType' { $bytes[1038] = 1 }
            'CertificateOffset' { $bytes[296] = 0 }
            'Trailer' { $bytes = [byte[]]($bytes + [byte]1) }
        }
        $candidate = Join-Path $root 'candidate.exe'
        [IO.File]::WriteAllBytes($candidate, $bytes)
        Assert-ReleaseSignatureOnlyChange $exe $candidate
    } '^RELEASE_SIGNING_(IMAGE_CHANGED|CERTIFICATE_TABLE_REJECTED)$'
}
Invoke-Case 'options-closed-fields' { Get-ReleaseSigningOptions ($options + @{ AllowUnsigned = 'true' }) } '^RELEASE_SIGNING_OPTIONS_REJECTED$'
Invoke-Case 'options-wrong-store' { $bad = $options.Clone(); $bad.CertificateStore = 'Root'; Get-ReleaseSigningOptions $bad } '^RELEASE_SIGNING_OPTIONS_REJECTED$'
Invoke-Case 'options-timestamp-credentials' { $bad = $options.Clone(); $bad.TimestampUrl = 'https://user:secret@example.invalid/tsa'; Get-ReleaseSigningOptions $bad } '^RELEASE_SIGNING_TIMESTAMP_URL_REJECTED$'
Invoke-Case 'tool-hash-pin' {
    $bad = $options.Clone(); $bad.SignToolSha256 = '0' * 64
    Assert-ReleaseSigningEnvironment (Get-ReleaseSigningOptions $bad)
} '^RELEASE_SIGNING_TOOL_HASH_REJECTED$'
Invoke-Case 'outer-signature-before-final-checksum' {
    $asset = Join-Path $root 'DriverCrateCollectorSetup-0.1.1-windows-x64.exe'
    [IO.File]::WriteAllBytes($asset, (New-FixturePe))
    $before = (Get-FileHash -LiteralPath $asset).Hash.ToLowerInvariant()
    $result = Invoke-ReleaseInstallerAssetSigning -Executable $asset -ExpectedSha256 $before -BuildDirectory $build -CodeSigning $options
    Require ($result.signed -and $result.role -ceq 'CollectorInstaller') 'OUTER_VERIFIED'
    Require ($result.signedSha256 -ceq (Get-FileHash -LiteralPath $asset).Hash.ToLowerInvariant()) 'OUTER_FINAL_HASH'
    Require (-not (Test-Path -LiteralPath ($asset + '.index-profile.json'))) 'NO_PSEUDO_OUTER_PROFILE'
}
Invoke-Case 'builders-sign-before-package-and-final-checksum' {
    $app = [IO.File]::ReadAllText((Join-Path $repository 'scripts/package-release.ps1'))
    Require ($app.IndexOf('Invoke-ReleaseBuildSigning') -lt $app.IndexOf('Copy-Item -LiteralPath $releaseExecutable')) 'APP_ORDER'
    $collector = [IO.File]::ReadAllText((Join-Path $repository 'scripts/package-collector.ps1'))
    Require ($collector.IndexOf('-Role Collector ') -lt $collector.IndexOf('$mapping =')) 'COLLECTOR_ORDER'
    Require ($collector.IndexOf('-Role CollectorSetup ') -lt $collector.IndexOf('$mapping =')) 'INNER_SETUP_ORDER'
    $outer = [IO.File]::ReadAllText((Join-Path $repository 'scripts/package-collector-installer.ps1'))
    Require ($outer.IndexOf('Assert-ReleaseSignedExecutable') -lt $outer.IndexOf('$resourceRows =')) 'INNER_VERIFY_BEFORE_RESOURCES'
    Require ($outer.IndexOf('& $executable --check-embedded') -lt $outer.IndexOf('Invoke-ReleaseInstallerAssetSigning')) 'OUTER_AFTER_EMBED_CHECK'
    Require ($outer.IndexOf('Invoke-ReleaseInstallerAssetSigning') -lt $outer.IndexOf('[IO.File]::WriteAllText(($asset + ''.sha256'')')) 'CHECKSUM_AFTER_SIGNING'
    Require ($outer.IndexOf('Invoke-ReleaseInstallerAssetSigning') -lt $outer.IndexOf("schema = 'dc-collector-single-exe-build-v1'")) 'RESULT_AFTER_SIGNING'
}
[ordered]@{ status = 'PASS'; cases = $caseCount; fixtureTrustOnly = $true; fixtureRoot = $root
    mockSignCalls = $signCalls; mockVerifyCalls = $verifyCalls; mockChainCalls = $chainCalls
    realSigning = 0; realKeyOperations = 0; certificateQueries = 0; network = 0; realBuilds = 0; realPackages = 0 } | ConvertTo-Json -Compress
