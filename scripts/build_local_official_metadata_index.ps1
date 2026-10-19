<#
.SYNOPSIS
型付き公式recordの開発用射影から非公開のローカル索引を生成する。
.DESCRIPTION
作成者: Shunji Ogawa。Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0。repository rootのLICENSEを参照する。
G13-D6j15j2q2b2。秘密URL、EULA全文、端末IDは入力にも出力にも扱わない。
索引は研究用であり公開・download・導入許可には使用しない。
#>
param(
    [Parameter(Mandatory=$true)][string]$PreparedRoot,
    [Parameter(Mandatory=$true)][string[]]$PreparedDirectories,
    [Parameter(Mandatory=$true)][string]$Destination
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# prepared runを1～32件に限定し、無対象や過大batchで索引生成しない。
if ($PreparedDirectories.Count -lt 1 -or $PreparedDirectories.Count -gt 32) { throw 'RUN_COUNT' }
# 既存Destinationを拒否し、前回索引や途中成果物を上書きしない。
if (Test-Path -LiteralPath $Destination) { throw 'OUTPUT_EXISTS' }
$root=[IO.Path]::GetFullPath($PreparedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
# prepared rootが実在directoryでなければrun走査を始めない。
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'ROOT_MISSING' }
$allowedTop=@('schema','researchOnly','publishable','downloadEligible','source','querySha256','snapshotSha256','fingerprintsSha256','recordCount','records')
$allowedRecord=@('fingerprint','providerId','policyId','resourceId','parserId','parserRevision','productFamily','driverCategory','operatingSystem','architecture','packageVersion','publishedDate','terms','resolvedUtcSeconds','bodyAcquiredUtcSeconds','originValidatedUtcSeconds','payloadCount','payloads')
$allowedPayload=@('publishedSizeBytes','publishedSha256','publishedSha512')
$seenRuns=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$records=@{}
$runs=[Collections.Generic.List[object]]::new()
$slotCount=0
# 全PreparedDirectoriesを絶対pathへ正規化しsortしてからrun検査へ渡し、入力順に依存しない索引生成順を作る。
$paths=@($PreparedDirectories | ForEach-Object {[IO.Path]::GetFullPath($_)} | Sort-Object)
# sorted run全件を一回ずつ検査し、固定file/hash/schema/record結合に合格した内容だけ統合する。
foreach ($path in $paths) {
    # root外・重複・非directory・reparseのrunを拒否し、入力範囲を固定する。
    if (-not $path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        -not $seenRuns.Add($path) -or -not (Test-Path -LiteralPath $path -PathType Container) -or
        ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'RUN_PATH' }
    $metadataPath=Join-Path $path 'index-metadata.json'
    $metadataHashPath=Join-Path $path 'index-metadata.sha256'
    $snapshotPath=Join-Path $path 'input.dcgraph'
    $fingerprintPath=Join-Path $path 'record.txt'
    $sourcePath=Join-Path $path 'source.txt'
    # 各runの固定5入力を全件検査し、欠落・非leaf・reparseを拒否してから読取る。
    foreach ($file in @($metadataPath,$metadataHashPath,$snapshotPath,$fingerprintPath,$sourcePath)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
            ((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'RUN_FILE_MISSING' }
    }
    # metadata/snapshotは1MiB、fingerprint2048B、source64B、hash64Bへ限定して過大/不正入力を拒否する。
    if ((Get-Item $metadataPath).Length -gt 1MB -or (Get-Item $snapshotPath).Length -gt 1MB -or
        (Get-Item $fingerprintPath).Length -gt 2048 -or (Get-Item $sourcePath).Length -gt 64 -or
        (Get-Item $metadataHashPath).Length -ne 64) { throw 'RUN_FILE_LIMIT' }
    # metadata実hashをASCII sidecarへ結合し、射影の変更を拒否する。
    if ([IO.File]::ReadAllText($metadataHashPath,[Text.Encoding]::ASCII) -cne
        (Get-FileHash $metadataPath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'METADATA_HASH' }
    $text=[IO.File]::ReadAllText($metadataPath,[Text.Encoding]::UTF8)
    if ($text -match '(?i)https?://|PCI\\|USB\\|VEN_|DEV_|VID_|PID_|<html|<script') { throw 'SECRET_OR_URL_IN_PROJECTION' }
    $metadata=$text | ConvertFrom-Json
    # metadataの固定field・schema・研究flag・非公開/非downloadとrecord1～16件の一致を要求する。
    if (@($metadata.PSObject.Properties.Name).Count -ne $allowedTop.Count -or
        @($metadata.PSObject.Properties.Name | Where-Object {$_ -cnotin $allowedTop}).Count -ne 0 -or
        $metadata.schema -cne 'local-official-metadata-v1' -or -not $metadata.researchOnly -or
        $metadata.publishable -or $metadata.downloadEligible -or
        $metadata.recordCount -lt 1 -or $metadata.recordCount -gt 16 -or
        @($metadata.records).Count -ne $metadata.recordCount) { throw 'METADATA_SCHEMA' }
    $source=[IO.File]::ReadAllText($sourcePath,[Text.Encoding]::UTF8)
    # source.txtと射影sourceを一致させ、既知のASUS/Intel Ethernet以外を拒否する。
    if ($source -cne $metadata.source -or $source -cnotin @('AsusCatalog','IntelEthernetLivePage')) { throw 'SOURCE_BINDING' }
    # snapshotとfingerprintの実hashをmetadataへ結合して別run入力への付替えを拒否する。
    if ((Get-FileHash $snapshotPath -Algorithm SHA256).Hash -ne $metadata.snapshotSha256 -or
        (Get-FileHash $fingerprintPath -Algorithm SHA256).Hash -ne $metadata.fingerprintsSha256) { throw 'FILE_BINDING' }
    $fingerprints=[IO.File]::ReadAllText($fingerprintPath,[Text.Encoding]::ASCII).Split([char]10)
    # fingerprint一覧のheader・件数・終端を照合して欠落/余分行を拒否する。
    if ($fingerprints[0] -cne 'DCRECORDS1' -or $fingerprints.Count -ne $metadata.recordCount+2 -or
        $fingerprints[-1] -cne '') { throw 'FINGERPRINT_LIST' }
    $queryCategory=$null;$queryMaker=$null;$queryProduct=$null
    # ASUSだけ固定query fileをhash/schema検査してhintを保存し、非ASUSではquery hash混入を拒否する。
    if ($source -ceq 'AsusCatalog') {
        $queryPath=Join-Path $path 'query.txt'
        $queryHashPath=Join-Path $path 'query.sha256'
        # ASUS query二fileを通常leaf・非reparse・固定size以内に限定する。
        if (-not (Test-Path -LiteralPath $queryPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $queryHashPath -PathType Leaf) -or
            ((Get-Item -LiteralPath $queryPath).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            ((Get-Item -LiteralPath $queryHashPath).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            (Get-Item -LiteralPath $queryPath).Length -gt 512 -or
            (Get-Item -LiteralPath $queryHashPath).Length -ne 64) { throw 'QUERY_MISSING' }
        $hash=(Get-FileHash $queryPath -Algorithm SHA256).Hash
        # query実hashがmetadataまたはsidecarと違う場合に拒否する。
        if ($hash -ne $metadata.querySha256 -or
            [IO.File]::ReadAllText($queryHashPath,[Text.Encoding]::ASCII) -cne $hash.ToLowerInvariant()) { throw 'QUERY_BINDING' }
        $queryLines=[IO.File]::ReadAllText($queryPath,[Text.Encoding]::ASCII).Split([char]10)
        # query v1の固定6行/header/終端を確認してからhintを取り出す。
        if ($queryLines.Count -ne 6 -or $queryLines[0] -cne 'DCASUSQUERY1' -or $queryLines[-1] -cne '') { throw 'QUERY_SCHEMA' }
        $queryCategory=$queryLines[1];$queryMaker=$queryLines[2];$queryProduct=$queryLines[3]
    } elseif ($null -ne $metadata.querySha256) { throw 'UNEXPECTED_QUERY' }
    $ordinal=$runs.Count+1
    $runs.Add([ordered]@{ordinal=$ordinal;source=$source;queryIsHintOnly=$true;
        categoryHint=$queryCategory;manufacturerHint=$queryMaker;productHint=$queryProduct;
        recordCount=$metadata.recordCount;metadataSha256=(Get-FileHash $metadataPath -Algorithm SHA256).Hash})
    # 各recordを同ordinalのfingerprintへ結合し、payload検査後に一意fingerprintへ統合する。
    for ($i=0;$i -lt $metadata.recordCount;$i++) {
        $record=$metadata.records[$i]
        # recordの固定field・fingerprint・x64・payload1～32件・terms既知値を必須にして壊れたmetadataを拒否する。
        if (@($record.PSObject.Properties.Name).Count -ne $allowedRecord.Count -or
            @($record.PSObject.Properties.Name | Where-Object {$_ -cnotin $allowedRecord}).Count -ne 0 -or
            $record.fingerprint -cnotmatch '^[0-9a-f]{64}$' -or
            $fingerprints[$i+1] -cne $record.fingerprint -or
            $record.architecture -cne 'x64' -or
            $record.payloadCount -lt 1 -or $record.payloadCount -gt 32 -or
            @($record.payloads).Count -ne $record.payloadCount -or
            $record.terms -cnotin @('CONFIRMED_NO_CONSENT','ACCEPTANCE_REQUIRED')) { throw 'RECORD_SCHEMA_OR_BINDING' }
        $expected=if($source -ceq 'AsusCatalog'){'asus-official'}else{'intel-ethernet-windows11-official'}
        # sourceから決めたprovider IDと異なるrecordを拒否して取得元の付替えを避ける。
        if ($record.providerId -cne $expected) { throw 'PROVIDER_BINDING' }
        # record内の有限payload全件について固定fieldと指定済みSHA256/SHA512の桁・文字形式を検査し、不正な公開hashを保存しない。
        foreach ($payload in $record.payloads) {
            if (@($payload.PSObject.Properties.Name).Count -ne $allowedPayload.Count -or
                @($payload.PSObject.Properties.Name | Where-Object {$_ -cnotin $allowedPayload}).Count -ne 0 -or
                ($payload.publishedSha256 -and $payload.publishedSha256 -notmatch '^[0-9a-fA-F]{64}$') -or
                ($payload.publishedSha512 -and $payload.publishedSha512 -notmatch '^[0-9a-fA-F]{128}$')) { throw 'PAYLOAD_SCHEMA' }
        }
        $slotCount++
        $key=[string]$record.fingerprint
        # 同fingerprintの安定比較ではresolvedUtcSeconds・bodyAcquiredUtcSeconds・originValidatedUtcSecondsだけを除き、残る全property値を列挙順にJSON化して内容差を競合検出へ残す。
        $stable=@($record.PSObject.Properties | Where-Object {$_.Name -cnotin @('resolvedUtcSeconds','bodyAcquiredUtcSeconds','originValidatedUtcSeconds')} | ForEach-Object {$_.Value} | ConvertTo-Json -Depth 7 -Compress)
        $stableJson=$stable -join ''
        # 同fingerprintは観測時刻を除く安定metadataの一致を必須にし、違いは競合として拒否する。一致時は観測runだけ追加し、新規は初回recordを保存する。
        if ($records.ContainsKey($key)) {
            if ($records[$key].stable -cne $stableJson) { throw 'DUPLICATE_METADATA_CONFLICT' }
            $records[$key].observedRuns.Add($ordinal)
        } else {
            $list=[Collections.Generic.List[int]]::new();$list.Add($ordinal)
            $records[$key]=[pscustomobject]@{stable=$stableJson;record=$record;observedRuns=$list}
        }
    }
}
# 一意fingerprintをsort順で全件出力し、適用性・内容検査・download許可は未評価のまま保つ。
$outputRecords=foreach ($key in @($records.Keys | Sort-Object)) {
    [ordered]@{metadata=$records[$key].record;observedRunOrdinals=@($records[$key].observedRuns.ToArray());
        deviceApplicability='NOT_ASSESSED';payloadInspected=$false;downloadEligible=$false}
}
$index=[ordered]@{schema='local-official-index-v1';researchOnly=$true;publishable=$false;
    downloadEligible=$false;inventoryNodeCount=247;deviceMatchCount=0;notAssessedNodeCount=247;
    runCount=$runs.Count;rawRecordSlots=$slotCount;uniqueRecordCount=$records.Count;
    runs=@($runs.ToArray());records=@($outputRecords)}
$jsonBytes=[Text.UTF8Encoding]::new($false).GetBytes(($index|ConvertTo-Json -Depth 12 -Compress)+"`n")
# 生成済みJSONが128MiB超なら圧縮/保存を拒否する。生成前memory上限は保証しない。
if ($jsonBytes.Length -gt 128MB) { throw 'INDEX_EXPANDED_LIMIT' }
$memory=[IO.MemoryStream]::new()
try {$gzip=[IO.Compression.GZipStream]::new($memory,[IO.Compression.CompressionLevel]::Optimal,$true)
    try {$gzip.Write($jsonBytes,0,$jsonBytes.Length)}finally{$gzip.Dispose()}
    $gzipBytes=$memory.ToArray()
}finally{$memory.Dispose()}
# 圧縮結果のbyte数32MiB超は保存へ進めない。
if ($gzipBytes.Length -gt 32MB) { throw 'INDEX_COMPRESSED_LIMIT' }
$sha=[Security.Cryptography.SHA256]::Create()
try {$jsonHash=[Convert]::ToHexString($sha.ComputeHash($jsonBytes));$gzipHash=[Convert]::ToHexString($sha.ComputeHash($gzipBytes))}finally{$sha.Dispose()}
$receipt=[ordered]@{schema='local-official-index-receipt-v1';signed=$false;publishable=$false;
    runCount=$runs.Count;rawRecordSlots=$slotCount;uniqueRecordCount=$records.Count;
    deviceMatchCount=0;payloadGets=0;indexJsonBytes=$jsonBytes.Length;indexJsonSha256=$jsonHash;
    indexGzipBytes=$gzipBytes.Length;indexGzipSha256=$gzipHash}
$receiptBytes=[Text.UTF8Encoding]::new($false).GetBytes(($receipt|ConvertTo-Json -Depth 4 -Compress)+"`n")
# receipt生成後64KiB超なら逐次保存を始めない。
if ($receiptBytes.Length -gt 64KB) { throw 'RECEIPT_LIMIT' }
# 新規Destinationへ三fileを逐次保存する。途中I/O失敗では先行fileとdirectoryを保持し、完成とは扱わない。
# 同じDestinationで再実行すると既存先の検査で拒否するため、途中成果物を自動再利用しない。
$null=New-Item -ItemType Directory -Path $Destination
[IO.File]::WriteAllBytes((Join-Path $Destination 'index.json'),$jsonBytes)
[IO.File]::WriteAllBytes((Join-Path $Destination 'index.json.gz'),$gzipBytes)
[IO.File]::WriteAllBytes((Join-Path $Destination 'receipt-local.json'),$receiptBytes)
Write-Output ('PASS: runs='+$runs.Count+' rawRecordSlots='+$slotCount+' uniqueFingerprints='+$records.Count+' deviceMatches=0 payloadGets=0 jsonBytes='+$jsonBytes.Length+' gzipBytes='+$gzipBytes.Length)
