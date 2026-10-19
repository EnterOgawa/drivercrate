<#
.SYNOPSIS
公式台帳の代表packageを有限予算で検査用取得する保守tool（ADR 0228／0240／0242）。
.DESCRIPTION
作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Installer・driverを実行せず、既存の共通検査器だけを起動する。
Payloadは新規work folderへ保存し、可搬証拠にpathや端末情報を含めない。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Registry,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$Inspector,
    [Parameter(Mandatory)][string]$Plan,
    [string]$Locators,
    [string]$Derivations
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-RegularPath([string]$Path) {
    # 新規出力への迂回と、入力・検査器のreparse差替えを拒否する。
    $candidate = [IO.Path]::GetFullPath($Path)
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) {
            if ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'REPARSE_PATH'
            }
        }
        $candidate = [IO.Path]::GetDirectoryName($candidate)
    }
}

function Assert-PublicHost([Uri]$Uri) {
    # 保守用の公開HTTPS URLだけを扱い、cookie・認証・転送を追加しない。
    if ($Uri.Scheme -ne 'https' -or $Uri.Port -ne 443 -or $Uri.UserInfo -or $Uri.Query -or $Uri.Fragment) {
        throw 'URL_POLICY'
    }
    $addresses = [Net.Dns]::GetHostAddresses($Uri.DnsSafeHost)
    # DNSが空なら固定宛先を選べないためGET前に拒否する。
    if ($addresses.Count -eq 0) { throw 'DNS_EMPTY' }
    # DNSが返した全addressを一回ずつ検査し、一つでも禁止宛先や未対応familyなら全要求を拒否する。
    foreach ($address in $addresses) {
        $bytes = $address.GetAddressBytes()
        if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            # IPv4のprivate・loopback・link-local・予約/試験用等の列挙範囲を公開GET宛先から拒否する。
            if ($bytes[0] -in @(0,10,127) -or $bytes[0] -ge 224 -or
                ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) -or
                ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
                ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                ($bytes[0] -eq 192 -and $bytes[1] -in @(0,168)) -or
                ($bytes[0] -eq 198 -and $bytes[1] -in @(18,19)) -or
                ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) -or
                ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113)) { throw 'PRIVATE_DNS' }
        } elseif ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
            # IPv6はglobal unicastだけを保守GETへ使用する。
            if ($bytes[0] -lt 32 -or $bytes[0] -ge 64 -or
                ($bytes[0] -eq 32 -and $bytes[1] -eq 1 -and $bytes[2] -eq 13 -and $bytes[3] -eq 184)) {
                throw 'PRIVATE_DNS'
            }
        } else { throw 'DNS_FAMILY' }
    }
    # 検査した宛先へ一回のGETを固定し、curl側のDNS再解決で制約が変わるのを防ぐ。
    return $addresses[0].ToString()
}

function Assert-AsusPublicRoute($Item, $Record, $Source) {
    # 明示した公開製品の公式配布に限り、任意host・path・credentialの署名要求を拒否する。
    if ($Item.route -cne 'ASUS_PUBLIC_CDN_SESSION' -or $Item.format -cne 'ZIP' -or
        $Item.publicModel -isnot [string] -or $Item.publicModel -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 -]{0,127}$' -or
        $Source.manufacturer -cne 'ASUS' -or $Source.collectionMethod -cne 'MANUAL_RESEARCH' -or
        $Record.publishedSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'ASUS_ROUTE_POLICY' }
    $page = [Uri]$Source.officialPage
    $payload = [Uri]$Record.downloadUrl
    $slug = [Uri]::EscapeDataString($Item.publicModel.ToLowerInvariant())
    if ($Source.officialPage -cne ('https://www.asus.com/jp/supportonly/' + $slug + '/helpdesk_download/') -or
        $page.UserInfo -or $page.Query -or $page.Fragment -or
        $payload.Scheme -cne 'https' -or $payload.DnsSafeHost -cne 'dlcdnta.asus.com' -or
        $payload.Port -ne 443 -or $payload.UserInfo -or $payload.Query -or $payload.Fragment -or
        $payload.AbsolutePath -cnotmatch '^/pub/ASUS/mb/[A-Za-z0-9]+/[A-Za-z0-9_.-]+\.zip$' -or
        $Record.downloadUrl -cne ('https://dlcdnta.asus.com' + $payload.AbsolutePath)) {
        throw 'ASUS_ROUTE_POLICY'
    }
}

function Convert-AsusPublicSession([string]$Body, [long]$Now) {
    # TokenはRAM内の同一要求へだけ結合し、重複key・余分なfield・期限切れを拒否する。
    $document = $null
    try {
        if ([Text.Encoding]::UTF8.GetByteCount($Body) -gt 16384) { throw 'ASUS_SESSION_INVALID' }
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 8
        $document = [System.Text.Json.JsonDocument]::Parse($Body,$options)
        $root = $document.RootElement
        foreach ($element in @($root,$root.GetProperty('result'))) {
            $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $element.EnumerateObject()) {
                if (-not $names.Add($property.Name)) { throw 'ASUS_SESSION_INVALID' }
            }
            $expected = if ($names.Contains('result')) { 'message,result,status' } else { 'expires,keyPairId,signature' }
            if ((@($names | Sort-Object) -join ',') -cne $expected) { throw 'ASUS_SESSION_INVALID' }
        }
        if ($root.GetProperty('status').GetInt32() -ne 200 -or
            $root.GetProperty('message').ValueKind -ne [System.Text.Json.JsonValueKind]::String) {
            throw 'ASUS_SESSION_INVALID'
        }
        $result = $root.GetProperty('result')
        $expires = $result.GetProperty('expires').GetString()
        $signature = $result.GetProperty('signature').GetString()
        $key = $result.GetProperty('keyPairId').GetString()
        if ($expires -cnotmatch '^[0-9]{1,12}$' -or [long]$expires -le $Now -or
            [long]$expires -gt ($Now + 86400) -or $signature -cnotmatch '^[A-Za-z0-9_~.=-]{1,4096}$' -or
            $key -cnotmatch '^[A-Za-z0-9]{1,128}$') { throw 'ASUS_SESSION_INVALID' }
        return [pscustomobject]@{expires=$expires;signature=$signature;keyPairId=$key}
    } catch { throw 'ASUS_SESSION_INVALID' }
    finally { if ($document) { $document.Dispose() } }
}

function Get-AsusPublicRequest($Item, $Record, $Source) {
    # 公式画面で確認した公開POSTだけを一回発行する。応答・署名は出力fileへ渡さない。
    Assert-AsusPublicRoute $Item $Record $Source
    $asset = $Record.downloadUrl + '?model=' + [Uri]::EscapeDataString($Item.publicModel)
    $address = Assert-PublicHost ([Uri]'https://cdnta.asus.com/api/v1/TokenHQ')
    # curlのresolve文字列ではIPv6 literalを角括弧で包み、host:portとの区切りを壊さない。
    if ($address.Contains(':')) { $address = '[' + $address + ']' }
    $api = 'https://cdnta.asus.com/api/v1/TokenHQ?filePath=' +
        [Uri]::EscapeDataString($asset).Replace('%3A',':') + '&systemCode=asus'
    $body = & curl.exe -q --silent --fail --proto '=https' --max-redirs 0 `
        --connect-timeout 15 --max-time 30 --max-filesize 16384 `
        --resolve ('cdnta.asus.com:443:' + $address) --request POST `
        --header 'Content-Type: application/json' --header 'Origin: https://www.asus.com' `
        --referer $Source.officialPage $api 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'TRANSFER_FAILED' }
    $session = Convert-AsusPublicSession ($body -join "`n") ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    return $asset + '&Signature=' + $session.signature + '&Expires=' + $session.expires + '&Key-Pair-Id=' + $session.keyPairId
}

function Assert-FreeSpace([string]$Output, [long]$RequiredBytes, [long]$AvailableBytes = -1) {
    # v3/v4の有限取得予算preflight。試験は明示fake容量を渡し、実HTTPへ進まない。
    if ($RequiredBytes -lt 1) { throw 'DISK_BUDGET' }
    if ($AvailableBytes -eq -1) {
        $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Output))
        if ($root -notmatch '^[A-Za-z]:\\$') { throw 'DISK_BUDGET' }
        $drive = [IO.DriveInfo]::new($root)
        $AvailableBytes = $drive.AvailableFreeSpace
    }
    if ($AvailableBytes -lt $RequiredBytes) { throw 'DISK_BUDGET' }
}

Assert-RegularPath $Registry
Assert-RegularPath $Inspector
Assert-RegularPath $Plan
$registryValue = Get-Content -LiteralPath $Registry -Raw | ConvertFrom-Json
$registryHashOutput = & py -3.13 -X utf8 -B -c 'import sys; from pathlib import Path; sys.path.insert(0,"scripts"); import collector_registry as cr; r=cr.validate_registry(cr.read_json(Path(sys.argv[1]))); print(cr.digest(cr.json_bytes(r)))' $Registry
# 共通registry validatorの失敗や非64桁digestを拒否し、不正台帳をplan検査へ渡さない。
if ($LASTEXITCODE -ne 0 -or $registryHashOutput -notmatch '^[0-9a-f]{64}$') { throw 'REGISTRY_INVALID' }
$planValue = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$largePlan = $planValue.schema -ceq 'dc-sample-acquisition-plan-v3'
$locatorPlan = $planValue.schema -ceq 'dc-locator-sample-acquisition-plan-v4'
$locatorValidation = $null
$planHash = $null
if ($locatorPlan) {
    # 導出根拠・用途・選択recordと有限予算を共通非通信validatorへ結合する。
    if (-not $Locators -or -not $Derivations) { throw 'LOCATOR_PLAN_INPUTS' }
    Assert-RegularPath $Locators
    Assert-RegularPath $Derivations
    $validated = & py -3.13 -X utf8 -B (Join-Path $PSScriptRoot 'collector_locator_acquisition.py') plan `
        --registry $Registry --locators $Locators --derivations $Derivations --input $Plan 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'LOCATOR_PLAN_INVALID' }
    $locatorValidation = ($validated -join "`n") | ConvertFrom-Json
    $planHash = $locatorValidation.planSha256
} elseif ($Locators -or $Derivations) { throw 'LOCATOR_PLAN_MODE' }
elseif ($largePlan) {
    $planHash = & py -3.13 -X utf8 -B (Join-Path $PSScriptRoot 'collector_large_payload_evidence.py') plan --registry $Registry --input $Plan 2>$null
    # large planは共通validator成功と64桁plan hashを必須にし、壊れたplanを予算へ使わない。
    if ($LASTEXITCODE -ne 0 -or $planHash -notmatch '^[0-9a-f]{64}$') { throw 'PLAN_SCHEMA' }
} elseif ($planValue.schema -notin @('dc-sample-acquisition-plan-v1','dc-sample-acquisition-plan-v2') -or $planValue.items.Count -eq 0 -or
    $planValue.revision -cnotmatch '^[a-z0-9][a-z0-9-]{0,79}$' -or
    (@($planValue.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'items,revision,schema') { throw 'PLAN_SCHEMA' }
$seen = [Collections.Generic.HashSet[string]]::new()
$budget = 0L
# 全plan itemを通信前に走査してschema・重複record・個別上限を検査し、全件の最大byteを合算する。
foreach ($item in $planValue.items) {
    $itemFields = if ($planValue.schema -eq 'dc-sample-acquisition-plan-v1') {
        'format,maximumBytes,preDownloadConsent,recordId'
    } elseif ($locatorPlan) { 'format,locatorId,maximumBytes,preDownloadConsent,recordId' }
    elseif ($largePlan) { 'format,maximumBytes,maximumSeconds,preDownloadConsent,publicModel,recordId,route' }
    else { 'format,maximumBytes,preDownloadConsent,publicModel,recordId,route' }
    # itemは固定field・整数正値byte・一意record・既知format・取得前同意区分を必須にし、不正な予算や未承認形式を拒否する。
    if ((@($item.PSObject.Properties.Name | Sort-Object) -join ',') -cne $itemFields -or
        ($item.maximumBytes -isnot [int] -and $item.maximumBytes -isnot [long]) -or
        -not $seen.Add($item.recordId) -or $item.maximumBytes -lt 1 -or
        $item.maximumBytes -gt $(if ($largePlan) { 2147483648L } else { 67108864L }) -or
        $item.preDownloadConsent -cne $(if ($locatorPlan) { 'NO_GATE_OBSERVED_IN_PAGE_FUNCTION' } else { 'NO_GATE_OBSERVED' }) -or
        $item.format -notin @('ZIP','EXE')) { throw 'PLAN_ITEM' }
    $matches = @($registryValue.records | Where-Object id -eq $item.recordId)
    # record IDは台帳内で一意に解決できる必要があり、locator以外では直接URLがなければ拒否する。
    if ($matches.Count -ne 1 -or (-not $locatorPlan -and -not $matches[0].downloadUrl)) { throw 'PLAN_RECORD' }
    if ($planValue.schema -eq 'dc-sample-acquisition-plan-v2' -or ($largePlan -and $item.route -ceq 'ASUS_PUBLIC_CDN_SESSION')) {
        $sources = @($registryValue.sources | Where-Object id -eq $matches[0].sourceId)
        if ($sources.Count -ne 1) { throw 'PLAN_RECORD' }
        Assert-AsusPublicRoute $item $matches[0] $sources[0]
    }
    $budget += [long]$item.maximumBytes
}
# 合計最大byteがschema別のbatch上限を超えるplanは、出力作成も通信もせず拒否する。
if ($budget -gt $(if ($largePlan -or $locatorPlan) { $planValue.maximumTotalBytes } else { 83886080L })) { throw 'BATCH_BUDGET' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
Assert-RegularPath $output
if (Test-Path -LiteralPath $output) { throw 'OUTPUT_EXISTS' }
if ($largePlan) { Assert-FreeSpace $output ($budget + $planValue.reserveFreeBytes) }
elseif ($locatorPlan) { Assert-FreeSpace $output ($budget + 67108864L) }
$null = New-Item -ItemType Directory -Path $output
$inspectorPath = (Resolve-Path -LiteralPath $Inspector).Path
$inspectorHash = (Get-FileHash -LiteralPath $inspectorPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($locatorPlan) {
    # 同じplanを新しい出力先で再送しない。許可された二要求を通信前に一度だけ予約する。
    $usedPath = [IO.Path]::GetFullPath($Plan) + '.used.json'
    Assert-RegularPath $usedPath
    $used = [ordered]@{schema='dc-locator-acquisition-use-v1';planSha256=$planHash;
        reservedRequests=$planValue.items.Count;startedAt=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ');
        postRequests=0;javascriptExecutions=0}
    $usedBytes = [Text.UTF8Encoding]::new($false).GetBytes(($used | ConvertTo-Json -Compress) + "`n")
    $stream = [IO.File]::Open($usedPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($usedBytes,0,$usedBytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
$results = @()
# 固定planの各itemを一回ずつ処理し、取得/検査失敗はそのrowへ保存して残りへ進む。途中payloadと使用予約を残し自動再送しない。
foreach ($item in $planValue.items) {
    $record = @($registryValue.records | Where-Object id -eq $item.recordId)[0]
    $row = [ordered]@{
        id = 'acquisition-' + $item.recordId
        recordId = $item.recordId
        checkedAt = ''
        state = 'FAILED'
        httpStatus = $null
        bytes = 0L
        sha256 = $null
        outerSignature = 'NOT_CHECKED'
        publisher = $null
        inspection = 'NOT_CHECKED'
        inspectorSha256 = $null
        inspectionExitCode = $null
        verifiedInfs = 0
        rejectedInfs = 0
        inventoryFiles = 0
        reason = 'TRANSFER_FAILED'
    }
    try {
        if ($largePlan) { Assert-FreeSpace $output ($item.maximumBytes + $planValue.reserveFreeBytes) }
        $requestUrl = $record.downloadUrl
        if ($locatorPlan) {
            # queryの一般許可を追加せず、検証済み限定URLをRAMの同一planから解決する。
            $selected = @($locatorValidation.payloadUrls | Where-Object recordId -CEQ $item.recordId)
            if ($selected.Count -ne 1 -or $selected[0].locatorId -cne $item.locatorId) { throw 'URL_POLICY' }
            $requestUrl = $selected[0].url
        }
        $requestUri = [Uri]$requestUrl
        # v4のqueryは先に用途限定検査済み。既存DNS／HTTPS検査には同じorigin／pathだけを渡す。
        $publicAddress = if ($locatorPlan) {
            Assert-PublicHost ([Uri]$requestUri.GetLeftPart([UriPartial]::Path))
        } else { Assert-PublicHost $requestUri }
        # resolve先のIPv6 literalは角括弧で包み、host:443:addressの構成を保つ。
        if ($publicAddress.Contains(':')) { $publicAddress = '[' + $publicAddress + ']' }
        $resolvedDestination = $requestUri.DnsSafeHost + ':443:' + $publicAddress
        $destination = Join-Path $output ($item.recordId + '.' + $item.format.ToLowerInvariant())
        if ($planValue.schema -eq 'dc-sample-acquisition-plan-v2' -or ($largePlan -and $item.route -ceq 'ASUS_PUBLIC_CDN_SESSION')) {
            $source = @($registryValue.sources | Where-Object id -eq $record.sourceId)[0]
            $requestUrl = Get-AsusPublicRequest $item $record $source
        }
        # CurlはHTTPS・有限byte・有限時間・redirectなし。失敗fileを成功へ昇格しない。
        # URLはstdinのconfigへ渡し、期限付き署名をprocess command lineへ残さない。
        $configUrl = $requestUrl.Replace('\','\\').Replace('"','\"')
        $maximumSeconds = if ($largePlan) { $item.maximumSeconds } else { 120 }
        $transfer = ('url = "' + $configUrl + '"') | & curl.exe -q --silent --fail --proto '=https' --max-redirs 0 `
            --connect-timeout 20 --max-time $maximumSeconds --max-filesize $item.maximumBytes `
            --resolve $resolvedDestination --output $destination --write-out '%{http_code}' --config - 2>$null
        $requestUrl = $null
        $configUrl = $null
        $transferExit = $LASTEXITCODE
        if ($transfer -match '^\d{3}$') { $row.httpStatus = [int]$transfer }
        if ($transferExit -ne 0 -or $row.httpStatus -ne 200) { throw 'TRANSFER_FAILED' }
        $file = Get-Item -LiteralPath $destination
        if ($file.Length -lt 1 -or $file.Length -gt $item.maximumBytes) { throw 'PAYLOAD_SIZE' }
        $stream = [IO.File]::OpenRead($destination)
        try { $magic = [byte[]]::new(4); $read = $stream.Read($magic,0,4) } finally { $stream.Dispose() }
        # 不足headerまたは宣言ZIP/EXEとmagicが合わないpayloadを拒否し、拡張子だけで形式を信用しない。
        if ($read -ne 4 -or ($item.format -eq 'ZIP' -and ($magic[0] -ne 80 -or $magic[1] -ne 75)) -or
            ($item.format -eq 'EXE' -and ($magic[0] -ne 77 -or $magic[1] -ne 90))) { throw 'PAYLOAD_TYPE' }
        $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        # 公開SHA256があるrecordは実取得hashと一致を必須にし、違うbyteを証拠へ採用しない。
        if ($record.publishedSha256 -and $hash -ne $record.publishedSha256) { throw 'PUBLISHED_HASH_MISMATCH' }
        $row.state = 'DOWNLOADED'; $row.bytes = $file.Length; $row.sha256 = $hash; $row.reason = 'NONE'
        if ($largePlan -and $item.format -eq 'ZIP' -and $file.Length -gt 134217728) {
            # アプリの共通上限を変更せず、大型外側入力の未対応を構造不合格と区別する。
            $row.inspection = 'UNSUPPORTED'
        } elseif ($item.format -eq 'ZIP') {
            $inspectionOutput = (& $inspectorPath --inspect-only $destination | Out-String)
            $row.inspectionExitCode = $LASTEXITCODE
            $row.inspectorSha256 = $inspectorHash
            $inventory = [regex]::Match($inspectionOutput,'Inspection error=0x([0-9A-Fa-f]+) files=(\d+)')
            $content = [regex]::Match($inspectionOutput,'Content verified=(\d+) rejected=(\d+)')
            if ($inventory.Success) { $row.inventoryFiles = [int]$inventory.Groups[2].Value }
            if ($content.Success) {
                $row.verifiedInfs = [int]$content.Groups[1].Value
                $row.rejectedInfs = [int]$content.Groups[2].Value
            }
            $row.inspection = 'REJECTED'
            # 合格INFと拒否INFが混在するとPARTIALを保持し、全体PASSEDへまとめない。
            if ($row.verifiedInfs -gt 0 -and $row.rejectedInfs -gt 0) { $row.inspection = 'PARTIAL' }
            # inspector exit0・inventory error0・合格INFあり・拒否0の全条件が揃ったときだけPASSEDとする。
            if ($row.inspectionExitCode -eq 0 -and $inventory.Success -and $inventory.Groups[1].Value -eq '00000000' -and
                $row.verifiedInfs -gt 0 -and $row.rejectedInfs -eq 0) { $row.inspection = 'PASSED' }
        } else {
            $signature = Get-AuthenticodeSignature -LiteralPath $destination
            $row.outerSignature = if ($signature.Status -eq 'Valid') { 'VALID' } elseif ($signature.Status -eq 'NotSigned') { 'UNSIGNED' } else { 'INVALID' }
            if ($signature.SignerCertificate) {
                $row.publisher = $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
            }
            $row.inspection = 'UNSUPPORTED'
        }
        # 元byteと検査器が途中で変わった場合は、取得・内容証拠を作らない。
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash -or
            (Get-FileHash -LiteralPath $inspectorPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inspectorHash) { throw 'INPUT_CHANGED' }
    } catch {
        # 例外のpath・network文字列を証拠へ漏らさず、失敗種別だけを保存する。
        # rowだけを失敗へ戻し、既作成の途中payloadとplan.usedの使用予約は保持する。
        # 途中fileの自動削除や同じplanの自動再送は行わない。
        $reason = $_.Exception.Message
        if ($reason -notin @('TRANSFER_FAILED','PAYLOAD_SIZE','PAYLOAD_TYPE','PUBLISHED_HASH_MISMATCH','INPUT_CHANGED','PRIVATE_DNS','DNS_EMPTY','DNS_FAMILY','URL_POLICY')) {
            $reason = 'OBSERVATION_FAILED'
        }
        $row.state = 'FAILED'; $row.bytes = 0L; $row.sha256 = $null; $row.reason = $reason
        $row.inspection = 'NOT_CHECKED'; $row.inspectorSha256 = $null; $row.inspectionExitCode = $null
        $row.verifiedInfs = 0; $row.rejectedInfs = 0; $row.inventoryFiles = 0
        $row.outerSignature = 'NOT_CHECKED'; $row.publisher = $null
    }
    $row.checkedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $results += [pscustomobject]$row
    [pscustomobject]@{recordId=$row.recordId;state=$row.state;bytes=$row.bytes;inspection=$row.inspection;reason=$row.reason} | ConvertTo-Json -Compress
}
$evidence = [ordered]@{
    schema = 'dc-public-payload-evidence-v1'
    revision = $planValue.revision
    registryRevision = $registryValue.revision
    registrySha256 = $registryHashOutput
    asOf = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    acquisitions = $results
}
# 証拠だけを新規fileへ保存する。Payloadをsnapshotへ複写しない。
$document = if ($locatorPlan) {
    [ordered]@{schema='dc-locator-payload-evidence-v1';planSha256=$planHash;
        registrySha256=$registryHashOutput;asOf=$evidence.asOf;acquisitions=$results}
} elseif ($largePlan) {
    [ordered]@{schema='dc-large-payload-evidence-v1';plan=$planValue;planSha256=$planHash;evidence=$evidence}
} else { $evidence }
$json = ($document | ConvertTo-Json -Depth 12).Replace("`r`n","`n") + "`n"
[IO.File]::WriteAllText((Join-Path $output 'payload-evidence.json'),$json,[Text.UTF8Encoding]::new($false))
# 保存済みevidenceはlarge/locator各共通validatorで再検査し、mode別の根拠結合が崩れた出力を拒否する。
if ($largePlan) {
    $null = & py -3.13 -X utf8 -B (Join-Path $PSScriptRoot 'collector_large_payload_evidence.py') evidence --registry $Registry --input (Join-Path $output 'payload-evidence.json')
    if ($LASTEXITCODE -ne 0) { throw 'EVIDENCE_INVALID' }
} elseif ($locatorPlan) {
    $null = & py -3.13 -X utf8 -B (Join-Path $PSScriptRoot 'collector_locator_acquisition.py') evidence `
        --registry $Registry --locators $Locators --derivations $Derivations --input $Plan `
        --evidence (Join-Path $output 'payload-evidence.json') 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'LOCATOR_EVIDENCE_INVALID' }
}
