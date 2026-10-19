# ADR0348: build metadataをEXE原hashへ結合する。署名・両file同時改変への保証ではない。
function Read-BoundedIndexProfileBytes {
    <#
    .SYNOPSIS
    stat済みの非秘密fileを上限+1まで一回読み、所有byteを返す。
    .PARAMETER Path
    呼出し元が選んだsidecarまたはsource公開定数file。
    .PARAMETER Limit
    許可する正のbyte上限。上限超過、stat時の長さと読取りbyte数の不一致、短いreadは例外で拒否する。
    #>
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][int] $Limit)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt $Limit) {
        throw 'INDEX_BUILD_PROFILE_SIZE_REJECTED'
    }
    $stream = [IO.File]::OpenRead($item.FullName)
    try {
        $buffer = [byte[]]::new($Limit + 1)
        $count = $stream.Read($buffer, 0, $buffer.Length)
        if ($count -ne $item.Length -or $count -gt $Limit) { throw 'INDEX_BUILD_PROFILE_READ_CHANGED' }
        return ,([byte[]]$buffer[0..($count - 1)])
    } finally { $stream.Dispose() }
}

function Assert-DistributableIndexBuild {
    <#
    .SYNOPSIS
    固定source公開policyと厳密v2 sidecarを照合し、EXEを実行せずhashだけ検査する。
    .PARAMETER Executable
    packageへ渡す既存EXE。sidecar/source正本の不在、型・field・policy・hash違いは例外。
    .NOTES
    source headerは本script相対の正本だけを読む。鍵store・秘密・network・runtime trust引数なし。
    信頼したbuild metadataの整合検査であり、署名や悪意ある同時改変への保証ではない。
    #>
    param([Parameter(Mandatory)][string] $Executable)
    $receiptPath = $Executable + '.index-profile.json'
    if (!(Test-Path -LiteralPath $receiptPath -PathType Leaf)) { throw 'INDEX_BUILD_PROFILE_MISSING' }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $sourcePath = Join-Path $PSScriptRoot '../src/platform/index_distribution_trust.h'
    $source = $utf8.GetString((Read-BoundedIndexProfileBytes -Path $sourcePath -Limit 16384))
    $fingerprints = [regex]::Matches($source, 'PUBLIC_FINGERPRINT\s*=\s*"([0-9a-f]{64})"')
    $revisions = [regex]::Matches($source, 'ACQUISITION_POLICY_REVISION\s*=\s*([0-9]+)U')
    $blobs = [regex]::Matches($source, '(?s)PUBLIC_BLOB\s*\{(.*?)\}\s*;')
    if ($fingerprints.Count -ne 1 -or $revisions.Count -ne 1 -or $blobs.Count -ne 1 -or
        $revisions[0].Groups[1].Value -cne '1') { throw 'INDEX_BUILD_SOURCE_POLICY_REJECTED' }
    $expectedFingerprint = $fingerprints[0].Groups[1].Value
    $values = [regex]::Matches($blobs[0].Groups[1].Value, '0x([0-9a-f]{2})U')
    if ($values.Count -ne 411) { throw 'INDEX_BUILD_SOURCE_POLICY_REJECTED' }
    $publicBytes = [byte[]]::new(411)
    for ($offset = 0; $offset -lt $values.Count; ++$offset) {
        # source正本の公開byteだけを復元し、自己申告fingerprintとの差を拒否する。
        $publicBytes[$offset] = [Convert]::ToByte($values[$offset].Groups[1].Value, 16)
    }
    $publicHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($publicBytes)).ToLowerInvariant()
    if ($publicHash -cne $expectedFingerprint) { throw 'INDEX_BUILD_SOURCE_PIN_DRIFT' }
    $json = $utf8.GetString((Read-BoundedIndexProfileBytes -Path $receiptPath -Limit 1024))
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 8
    $document = [System.Text.Json.JsonDocument]::Parse($json, $options)
    try {
        $receipt = $document.RootElement
        if ($receipt.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'INDEX_BUILD_PROFILE_REJECTED' }
        $fields = @($receipt.EnumerateObject() | ForEach-Object { $_.Name })
        if ($fields.Count -ne 5 -or (($fields | Sort-Object) -join ',') -cne
            'acquisitionPolicyRevision,distributionFingerprint,localAcceptance,schema,sha256') {
            throw 'INDEX_BUILD_PROFILE_REJECTED'
        }
        $schema = $receipt.GetProperty('schema')
        $local = $receipt.GetProperty('localAcceptance')
        $hash = $receipt.GetProperty('sha256')
        $fingerprint = $receipt.GetProperty('distributionFingerprint')
        $revision = $receipt.GetProperty('acquisitionPolicyRevision')
        if ($schema.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            $schema.GetString() -cne 'drivercrate-index-build-profile-v2' -or
            $local.ValueKind -notin @([System.Text.Json.JsonValueKind]::True, [System.Text.Json.JsonValueKind]::False) -or
            $hash.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            $hash.GetString() -cnotmatch '^[0-9a-f]{64}$' -or
            $fingerprint.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            $revision.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or
            $revision.GetRawText() -cne '1') { throw 'INDEX_BUILD_PROFILE_REJECTED' }
        if ($local.GetBoolean()) { throw 'LOCAL_INDEX_ACCEPTANCE_BUILD_NOT_DISTRIBUTABLE' }
        if ($fingerprint.GetString() -cne $expectedFingerprint) { throw 'INDEX_BUILD_DISTRIBUTION_POLICY_REJECTED' }
        $actual = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $hash.GetString()) { throw 'INDEX_BUILD_PROFILE_STALE_EXECUTABLE' }
    } finally { $document.Dispose() }
}
