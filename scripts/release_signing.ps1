#requires -Version 7.0
<#.SYNOPSIS
検査済みbuildのAuthenticode遷移だけを配布byteへ結合する任意の開発用helper。
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
ADR0406。実行時に明示した証明書とSDKを使用し、秘密鍵はexportしない。
通常buildは本helperを呼ばない。署名とWindows trust検証には通信/鍵操作が伴い得る。
#>

function Get-ReleaseSigningOptions {
    <# .SYNOPSIS
    操作者の閉field入力を検査する。既定証明書/工具/TSAや秘密入力へのfallbackはない。
    #>
    param([Parameter(Mandatory)][hashtable] $CodeSigning)
    $keys = @('CertificateStore', 'CertificateThumbprint', 'SignToolPath', 'SignToolSha256', 'TimestampUrl')
    if ($CodeSigning.Count -ne $keys.Count -or
        (@($CodeSigning.Keys | Sort-Object) -join ',') -cne ($keys -join ',')) {
        throw 'RELEASE_SIGNING_OPTIONS_REJECTED'
    }
    foreach ($key in $keys) {
        if ($CodeSigning[$key] -isnot [string] -or [string]::IsNullOrWhiteSpace($CodeSigning[$key])) {
            throw 'RELEASE_SIGNING_OPTIONS_REJECTED'
        }
    }
    if ($CodeSigning.CertificateStore -cnotin @('CurrentUser', 'LocalMachine') -or
        $CodeSigning.CertificateThumbprint -cnotmatch '^[0-9A-Fa-f]{40}$' -or
        $CodeSigning.SignToolSha256 -cnotmatch '^[0-9A-Fa-f]{64}$') {
        throw 'RELEASE_SIGNING_OPTIONS_REJECTED'
    }
    $tool = Assert-IndexPackagePath -Path $CodeSigning.SignToolPath
    if ([IO.Path]::GetFileName($tool) -cne 'signtool.exe') { throw 'RELEASE_SIGNING_TOOL_REJECTED' }
    $uri = $null
    if (-not [Uri]::TryCreate($CodeSigning.TimestampUrl, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cnotin @('http', 'https') -or -not $uri.IsDefaultPort -or
        $uri.HostNameType -ne [UriHostNameType]::Dns -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
        $CodeSigning.TimestampUrl -match '[\s\x00-\x1f]') { throw 'RELEASE_SIGNING_TIMESTAMP_URL_REJECTED' }
    return @{ CertificateStore = $CodeSigning.CertificateStore
        CertificateThumbprint = $CodeSigning.CertificateThumbprint.ToUpperInvariant()
        SignToolPath = $tool; SignToolSha256 = $CodeSigning.SignToolSha256.ToLowerInvariant()
        TimestampUrl = $CodeSigning.TimestampUrl }
}

function Get-ReleaseCertificateEku {
    <# .SYNOPSIS
    明示EKU extensionのOIDだけを返し、EKU欠損を全用途許可へ変換しない。
    #>
    param([Parameter(Mandatory)] $Certificate)
    return @($Certificate.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.37' } |
        ForEach-Object { $_.EnhancedKeyUsages | ForEach-Object { $_.Value } })
}

function Assert-ReleaseSigningEnvironment {
    <# .SYNOPSIS
    指定SDKの原hash/Windows署名と選定My証明書一件だけを確認する。秘密鍵を取得/exportしない。
    #>
    param([Parameter(Mandatory)][hashtable] $Options)
    if ((Get-FileHash -LiteralPath $Options.SignToolPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $Options.SignToolSha256) { throw 'RELEASE_SIGNING_TOOL_HASH_REJECTED' }
    $toolSignature = Get-AuthenticodeSignature -LiteralPath $Options.SignToolPath
    if ($toolSignature.Status -ne 'Valid' -or $toolSignature.SignatureType -ne 'Authenticode' -or
        $null -eq $toolSignature.SignerCertificate -or
        $toolSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw 'RELEASE_SIGNING_TOOL_TRUST_REJECTED'
    }
    $certificatePath = 'Cert:\' + $Options.CertificateStore + '\My\' + $Options.CertificateThumbprint
    $certificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
    $now = [DateTime]::UtcNow
    if ($certificate.Thumbprint -cne $Options.CertificateThumbprint -or -not $certificate.HasPrivateKey -or
        $certificate.Subject -ceq $certificate.Issuer -or $certificate.NotBefore.ToUniversalTime() -gt $now -or
        $certificate.NotAfter.ToUniversalTime() -le $now -or
        '1.3.6.1.5.5.7.3.3' -cnotin @(Get-ReleaseCertificateEku $certificate)) {
        throw 'RELEASE_SIGNING_CERTIFICATE_REJECTED'
    }
    Assert-ReleaseCodeSigningChain $certificate
}

function Assert-ReleaseCodeSigningChain {
    <# .SYNOPSIS
    鍵使用前にWindows trust storeのCodeSigning chainとonline revocationを確認する。
    #>
    param([Parameter(Mandatory)] $Certificate)
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        [void]$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(30)
        if (-not $chain.Build($Certificate)) { throw 'RELEASE_SIGNING_CERTIFICATE_CHAIN_REJECTED' }
    } finally { $chain.Dispose() }
}

function Invoke-ReleaseSignTool {
    <# .SYNOPSIS
    毎回工具の原hashを確認して固定argvを実行し、警告exit2も成功にしない。
    #>
    param([Parameter(Mandatory)][hashtable] $Options, [Parameter(Mandatory)][string[]] $Arguments)
    if ((Get-FileHash -LiteralPath $Options.SignToolPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $Options.SignToolSha256) { throw 'RELEASE_SIGNING_TOOL_HASH_REJECTED' }
    & $Options.SignToolPath @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw ('RELEASE_SIGNING_TOOL_FAILED_' + $LASTEXITCODE) }
}

function Assert-ReleaseSignedExecutable {
    <# .SYNOPSIS
    実WinVerifyTrust/既定Authenticode policyと指定signer/timestampを必須にする。
    #>
    param([Parameter(Mandatory)][string] $Executable, [Parameter(Mandatory)][hashtable] $Options)
    Invoke-ReleaseSignTool -Options $Options -Arguments @('verify', '/pa', '/all', '/tw', $Executable)
    $signature = Get-AuthenticodeSignature -LiteralPath $Executable
    if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
        $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate -or
        $signature.SignerCertificate.Thumbprint -cne $Options.CertificateThumbprint -or
        '1.3.6.1.5.5.7.3.3' -cnotin @(Get-ReleaseCertificateEku $signature.SignerCertificate) -or
        '1.3.6.1.5.5.7.3.8' -cnotin @(Get-ReleaseCertificateEku $signature.TimeStamperCertificate)) {
        throw 'RELEASE_SIGNING_SIGNATURE_REJECTED'
    }
    return [ordered]@{ verified = $true; policy = 'WinVerifyTrust-Authenticode'
        certificateThumbprint = $signature.SignerCertificate.Thumbprint
        timestampCertificateThumbprint = $signature.TimeStamperCertificate.Thumbprint
        signToolSha256 = $Options.SignToolSha256; verifiedUtc = [DateTime]::UtcNow.ToString('o') }
}

function Read-ReleasePeLayout {
    <# .SYNOPSIS
    128MiB以内のx64/PE32+を非実行で読み、署名除外位置をheaderから求める。
    #>
    param([Parameter(Mandatory)][string] $Path)
    $path = Assert-IndexPackagePath -Path $Path
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Length -lt 256 -or $item.Length -gt 134217728) { throw 'RELEASE_SIGNING_PE_REJECTED' }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ne $item.Length -or $bytes[0] -ne 77 -or $bytes[1] -ne 90) {
        throw 'RELEASE_SIGNING_PE_REJECTED'
    }
    $offset = [BitConverter]::ToInt32($bytes, 60)
    if ($offset -lt 64 -or $offset -gt 1048576 -or $offset -gt $bytes.Length - 184 -or
        [BitConverter]::ToUInt32($bytes, $offset) -ne 17744 -or
        [BitConverter]::ToUInt16($bytes, $offset + 4) -ne 34404 -or
        [BitConverter]::ToUInt16($bytes, $offset + 20) -lt 160 -or
        [BitConverter]::ToUInt16($bytes, $offset + 24) -ne 523 -or
        [BitConverter]::ToUInt32($bytes, $offset + 24 + 108) -lt 5) {
        throw 'RELEASE_SIGNING_PE_REJECTED'
    }
    $sectionTable = $offset + 24 + [BitConverter]::ToUInt16($bytes, $offset + 20)
    $sectionCount = [BitConverter]::ToUInt16($bytes, $offset + 6)
    if ($sectionCount -lt 1 -or $sectionCount -gt 96 -or
        $sectionTable -gt $bytes.Length - 40 * $sectionCount) { throw 'RELEASE_SIGNING_PE_REJECTED' }
    for ($index = 0; $index -lt $sectionCount; ++$index) {
        # 全sectionのraw範囲をfile内へ閉じ、certificateをimage内部へ挿入させない。
        $size = [long][BitConverter]::ToUInt32($bytes, $sectionTable + 40 * $index + 16)
        $start = [long][BitConverter]::ToUInt32($bytes, $sectionTable + 40 * $index + 20)
        if ($size -gt 0 -and ($start -lt $sectionTable + 40 * $sectionCount -or
            $start -gt $bytes.Length - $size)) { throw 'RELEASE_SIGNING_PE_REJECTED' }
    }
    $directory = $offset + 24 + 144
    return [pscustomobject]@{ Bytes = $bytes; Checksum = $offset + 24 + 64; Directory = $directory
        CertificateOffset = [long][BitConverter]::ToUInt32($bytes, $directory)
        CertificateSize = [long][BitConverter]::ToUInt32($bytes, $directory + 4) }
}

function Get-ReleasePreservedContentHash {
    <# .SYNOPSIS
    checksum/security directory以外の原長全byteを順序通りhashし、overlayも省略しない。
    #>
    param([Parameter(Mandatory)] $Layout, [Parameter(Mandatory)][int] $Length)
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $hash.AppendData($Layout.Bytes, 0, $Layout.Checksum)
        $hash.AppendData($Layout.Bytes, $Layout.Checksum + 4, $Layout.Directory - $Layout.Checksum - 4)
        $hash.AppendData($Layout.Bytes, $Layout.Directory + 8, $Length - $Layout.Directory - 8)
        return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
    } finally { $hash.Dispose() }
}

function Assert-ReleaseSignatureOnlyChange {
    <# .SYNOPSIS
    元全byteの保全と末尾一個の整列certificate追加を検査する。trust検証は別途必須。
    #>
    param([Parameter(Mandatory)][string] $Original, [Parameter(Mandatory)][string] $Signed)
    $before = Read-ReleasePeLayout $Original
    $after = Read-ReleasePeLayout $Signed
    if ($before.CertificateOffset -ne 0 -or $before.CertificateSize -ne 0) {
        throw 'RELEASE_SIGNING_UNSIGNED_INPUT_REQUIRED'
    }
    $length = $before.Bytes.Length
    $aligned = [long]($length + ((8 - $length % 8) % 8))
    if ($after.Checksum -ne $before.Checksum -or $after.Directory -ne $before.Directory -or
        $after.CertificateOffset -ne $aligned -or $after.CertificateSize -lt 8 -or
        $after.CertificateSize -gt 1048576 -or $after.CertificateSize % 8 -ne 0 -or
        $after.CertificateOffset + $after.CertificateSize -ne $after.Bytes.Length -or
        $after.Bytes.Length -le $length) { throw 'RELEASE_SIGNING_IMAGE_CHANGED' }
    for ($index = $length; $index -lt $aligned; ++$index) {
        # 原末尾とcertificate間のalignmentだけをzeroへ限定する。
        if ($after.Bytes[$index] -ne 0) { throw 'RELEASE_SIGNING_IMAGE_CHANGED' }
    }
    $certificateLength = [long][BitConverter]::ToUInt32($after.Bytes, [int]$aligned)
    if ($certificateLength -le 8 -or $certificateLength -gt $after.CertificateSize -or
        $certificateLength + ((8 - $certificateLength % 8) % 8) -ne $after.CertificateSize -or
        [BitConverter]::ToUInt16($after.Bytes, [int]$aligned + 4) -ne 512 -or
        [BitConverter]::ToUInt16($after.Bytes, [int]$aligned + 6) -ne 2) {
        throw 'RELEASE_SIGNING_CERTIFICATE_TABLE_REJECTED'
    }
    for ($index = $aligned + $certificateLength; $index -lt $after.Bytes.Length; ++$index) {
        # WIN_CERTIFICATEの末尾alignmentへ別dataを隠させない。
        if ($after.Bytes[$index] -ne 0) { throw 'RELEASE_SIGNING_CERTIFICATE_TABLE_REJECTED' }
    }
    if ((Get-ReleasePreservedContentHash $before $length) -cne (Get-ReleasePreservedContentHash $after $length)) {
        throw 'RELEASE_SIGNING_IMAGE_CHANGED'
    }
    return [ordered]@{ originalSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($before.Bytes)).ToLowerInvariant()
        signedSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($after.Bytes)).ToLowerInvariant() }
}

function New-ReleaseSignedCandidate {
    <# .SYNOPSIS
    新規stagingだけを署名し、元hash・image同一性・実署名を全て検査して候補を返す。
    #>
    param([Parameter(Mandatory)][string] $Executable, [Parameter(Mandatory)][string] $ExpectedSha256,
        [Parameter(Mandatory)][string] $StageParent, [Parameter(Mandatory)][hashtable] $Options)
    $original = Read-ReleasePeLayout $Executable
    if ($original.CertificateOffset -ne 0 -or $original.CertificateSize -ne 0) {
        throw 'RELEASE_SIGNING_UNSIGNED_INPUT_REQUIRED'
    }
    if ((Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
        throw 'RELEASE_SIGNING_ORIGINAL_CHANGED'
    }
    Assert-ReleaseSigningEnvironment $Options
    $stage = Assert-IndexPackagePath -Path (Join-Path $StageParent ('code-signing-' + [Guid]::NewGuid().ToString('N'))) -Directory -AllowMissing
    if (Test-Path -LiteralPath $stage) { throw 'RELEASE_SIGNING_NEW_STAGE_REQUIRED' }
    [void][IO.Directory]::CreateDirectory($stage)
    $candidate = Join-Path $stage ([IO.Path]::GetFileName($Executable))
    [IO.File]::Copy($Executable, $candidate, $false)
    # chain確認/copy中の原PE変更を、秘密鍵を使う前に既検証の原hashへ照合する。
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256 -or
        (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
        throw 'RELEASE_SIGNING_ORIGINAL_CHANGED'
    }
    $arguments = @('sign', '/sha1', $Options.CertificateThumbprint, '/s', 'My')
    if ($Options.CertificateStore -ceq 'LocalMachine') { $arguments += '/sm' }
    $arguments += @('/fd', 'SHA256', '/tr', $Options.TimestampUrl, '/td', 'SHA256', $candidate)
    Invoke-ReleaseSignTool -Options $Options -Arguments $arguments
    $transition = Assert-ReleaseSignatureOnlyChange -Original $Executable -Signed $candidate
    if ($transition.originalSha256 -cne $ExpectedSha256) { throw 'RELEASE_SIGNING_ORIGINAL_CHANGED' }
    $signature = Assert-ReleaseSignedExecutable -Executable $candidate -Options $Options
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -cne $transition.signedSha256) {
        throw 'RELEASE_SIGNING_CANDIDATE_CHANGED'
    }
    return [pscustomobject]@{ Candidate = $candidate; Stage = $stage
        Evidence = [ordered]@{ schema = 'dc-authenticode-build-transition-v1'; signed = $true
            originalSha256 = $transition.originalSha256; signedSha256 = $transition.signedSha256
            signature = $signature; stageDirectory = $stage; stagingRetained = $true } }
}

function Invoke-ReleaseBuildSigning {
    <# .SYNOPSIS
    通常buildの固定roleだけを原v2へ照合し、検証済み署名後hashだけを同schemaへ結合する。
    #>
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)][string] $Role,
        [Parameter(Mandatory)][hashtable] $CodeSigning)
    $roles = @{ App = 'DriverCrate.exe'; Collector = 'DriverCrateCollector.exe'; CollectorSetup = 'DriverCrateCollectorSetup.exe' }
    if ($Role -cnotin @('App', 'Collector', 'CollectorSetup')) { throw 'RELEASE_SIGNING_ROLE_REJECTED' }
    $normal = Resolve-IndexPackageBuild -BuildDirectory $Context.Build -RequireCollector:($Role -cne 'App')
    $executable = Join-Path $normal.Build ('Release/' + $roles[$Role])
    Assert-IndexPackageExecutable -Executable $executable
    $profilePath = $executable + '.index-profile.json'
    $profileBytes = Read-BoundedIndexProfileBytes -Path $profilePath -Limit 1024
    $profileHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($profileBytes)).ToLowerInvariant()
    $profile = [Text.UTF8Encoding]::new($false, $true).GetString($profileBytes) | ConvertFrom-Json -AsHashtable
    $options = Get-ReleaseSigningOptions $CodeSigning
    $signed = New-ReleaseSignedCandidate -Executable $executable -ExpectedSha256 $profile.sha256 `
        -StageParent (Join-Path $normal.Build 'generated') -Options $options
    if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.sha256 -or
        (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profileHash) {
        throw 'RELEASE_SIGNING_ORIGINAL_CHANGED'
    }
    $utf8 = [Text.UTF8Encoding]::new($false)
    $profile.sha256 = $signed.Evidence.signedSha256
    $stagedProfile = $signed.Candidate + '.index-profile.json'
    [IO.File]::WriteAllText($stagedProfile, ($profile | ConvertTo-Json -Compress), $utf8)
    Assert-IndexPackageExecutable -Executable $signed.Candidate
    [IO.File]::WriteAllBytes((Join-Path $signed.Stage 'original.index-profile.json'), $profileBytes)
    # PE/profileは二段更新。途中失敗はbackup/stagingを保持し、次の既存guardで拒否する。
    [IO.File]::Replace($signed.Candidate, $executable, (Join-Path $signed.Stage 'original.exe'))
    [IO.File]::Replace($stagedProfile, $profilePath, (Join-Path $signed.Stage 'original-profile-replaced.json'))
    Assert-IndexPackageExecutable -Executable $executable
    $signed.Evidence.role = $Role
    $signed.Evidence.originalProfileSha256 = $profileHash
    $signed.Evidence.signedProfileSha256 = (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $signed.Stage 'signing-transition.json'), ($signed.Evidence | ConvertTo-Json -Depth 8), $utf8)
    return [pscustomobject]$signed.Evidence
}

function Invoke-ReleaseInstallerAssetSigning {
    <# .SYNOPSIS
    埋込検査後のfresh outer原hashを署名後byteへ結合する。v2 profileを新設しない。
    #>
    param([Parameter(Mandatory)][string] $Executable, [Parameter(Mandatory)][string] $ExpectedSha256,
        [Parameter(Mandatory)][string] $BuildDirectory, [Parameter(Mandatory)][hashtable] $CodeSigning)
    if ([IO.Path]::GetFileName($Executable) -cnotmatch '^DriverCrateCollectorSetup-[0-9]+\.[0-9]+\.[0-9]+-windows-x64\.exe$') {
        throw 'RELEASE_SIGNING_ROLE_REJECTED'
    }
    $options = Get-ReleaseSigningOptions $CodeSigning
    $signed = New-ReleaseSignedCandidate -Executable $Executable -ExpectedSha256 $ExpectedSha256 `
        -StageParent (Join-Path $BuildDirectory 'generated') -Options $options
    if ((Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
        throw 'RELEASE_SIGNING_ORIGINAL_CHANGED'
    }
    [IO.File]::Replace($signed.Candidate, $Executable, (Join-Path $signed.Stage 'original.exe'))
    if ((Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $signed.Evidence.signedSha256) {
        throw 'RELEASE_SIGNING_CANDIDATE_CHANGED'
    }
    $signed.Evidence.role = 'CollectorInstaller'
    return [pscustomobject]$signed.Evidence
}
