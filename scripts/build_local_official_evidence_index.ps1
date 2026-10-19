<#
.SYNOPSIS
公式metadata v1と公開model根拠v2を結合した非公開索引を作る。
.DESCRIPTION
作成者: Shunji Ogawa。Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0。repository rootのLICENSEを参照する。
G13-D6j15j2q4b2c。公開・download・導入を許可しない開発用出力。
#>
param(
    [Parameter(Mandatory=$true)][string]$PreparedRoot,
    [Parameter(Mandatory=$true)][string[]]$PreparedDirectories,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][ValidateRange(1,100000)][int]$InventoryNodeCount
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# prepared runは1～32件に限り、無対象や過大batchを索引生成へ進めない。
if ($PreparedDirectories.Count -lt 1 -or $PreparedDirectories.Count -gt 32) { throw 'RUN_COUNT' }
# 新規Destinationのみを受け付け、前回成果物や途中fileを上書きしない。
if (Test-Path -LiteralPath $Destination) { throw 'OUTPUT_EXISTS' }
$root=[IO.Path]::GetFullPath($PreparedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
# prepared rootが実在directoryでなければrun pathの検査を始めない。
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'ROOT_MISSING' }
$allowedEnvelope=@('schema','researchOnly','publishable','downloadEligible','metadataSha256','recordCount','records')
$allowedEvidence=@('fingerprint','displayTitle','driverCategory','operatingSystem','architecture','productScope','purposeMatch','publicModel','publicPageUrl')
$seenRuns=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$records=@{}
$runs=[Collections.Generic.List[object]]::new()
$rawCount=0
# 全PreparedDirectoriesを絶対pathへ正規化しsortしてからrun検査へ渡し、入力順に依存しない観測ordinalを作る。
$paths=@($PreparedDirectories | ForEach-Object {[IO.Path]::GetFullPath($_)} | Sort-Object)
function Assert-File([string]$path,[long]$limit) {
    # 入力fileを通常leafかつ指定byte上限以内へ限定し、reparseや過大文書を拒否する。
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        (Get-Item -LiteralPath $path).Length -gt $limit) { throw 'RUN_FILE' }
}
function Canonical-AsusPage([string]$model) {
    # 公開modelを限定ASCII/長さ/非ID文字列へ絞り、端末IDや余分空白を公式page生成へ持ち込ませない。
    if ($model.Length -lt 1 -or $model.Length -gt 128 -or
        $model -cnotmatch '\A[A-Za-z0-9 ._()+-]+\z' -or
        $model.Trim() -cne $model -or
        $model -match '(?i)VEN_|DEV_|VID_|PID_|\APCI_|\AUSB_') { throw 'MODEL_INVALID' }
    $path=[Text.StringBuilder]::new()
    # 検査済みmodelの全文字を小文字で順に処理し、unreserved文字はそのまま、その他はpercent encodeして公式page pathを作る。
    foreach($character in $model.ToLowerInvariant().ToCharArray()) {
        if ($character -cmatch '[a-z0-9._~-]') { $null=$path.Append($character) }
        else { $null=$path.Append(('%{0:X2}' -f [int][char]$character)) }
    }
    return 'https://www.asus.com/supportonly/'+$path.ToString()+'/helpdesk_download/'
}
# 固定sorted run全件を一回ずつ検査し、file/hash/schema/record結合を通したものだけ重複統合へ進める。
foreach($path in $paths) {
    # root外・重複run・非directory・reparseを拒否し、別場所の射影を索引へ混ぜない。
    if (-not $path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        -not $seenRuns.Add($path) -or -not (Test-Path -LiteralPath $path -PathType Container) -or
        ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'RUN_PATH' }
    $v1Path=Join-Path $path 'index-metadata.json'
    $v1HashPath=Join-Path $path 'index-metadata.sha256'
    $v2Path=Join-Path $path 'index-evidence-v2.json'
    $v2HashPath=Join-Path $path 'index-evidence-v2.sha256'
    $snapshotPath=Join-Path $path 'input.dcgraph'
    $fingerprintPath=Join-Path $path 'record.txt'
    $sourcePath=Join-Path $path 'source.txt'
    # 各runの固定7入力fileを全て存在/型/上限検査してから読む。
    foreach($file in @($v1Path,$v1HashPath,$v2Path,$v2HashPath,$snapshotPath,$fingerprintPath,$sourcePath)) {
        $limit=if($file -eq $v1Path -or $file -eq $v2Path -or $file -eq $snapshotPath){1MB}else{2048}
        Assert-File $file $limit
    }
    $v1Hash=(Get-FileHash -LiteralPath $v1Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $v2Hash=(Get-FileHash -LiteralPath $v2Path -Algorithm SHA256).Hash.ToLowerInvariant()
    # v1/v2射影の実hashとsidecar値を完全一致させ、編集された射影を拒否する。
    if ([IO.File]::ReadAllText($v1HashPath,[Text.Encoding]::ASCII) -cne $v1Hash -or
        [IO.File]::ReadAllText($v2HashPath,[Text.Encoding]::ASCII) -cne $v2Hash) { throw 'PROJECTION_HASH' }
    $v1Text=[IO.File]::ReadAllText($v1Path,[Text.Encoding]::UTF8)
    $v2Text=[IO.File]::ReadAllText($v2Path,[Text.Encoding]::UTF8)
    # metadata内URLと端末ID/HTML/script、evidence内端末ID/HTML/scriptを拒否し、許可する公開page以外の情報を混ぜない。
    if ($v1Text -match '(?i)https?://|PCI\\|USB\\|VEN_|DEV_|VID_|PID_|<html|<script' -or
        $v2Text -match '(?i)PCI\\|USB\\|VEN_|DEV_|VID_|PID_|<html|<script') { throw 'SECRET_TEXT' }
    $v1=$v1Text|ConvertFrom-Json
    $v2=$v2Text|ConvertFrom-Json
    # v1/v2の固定field・非公開/非download・hashとrecord件数、およびv2の研究flagを結合し、不正なenvelopeを拒否する。
    if (@($v2.PSObject.Properties.Name).Count -ne $allowedEnvelope.Count -or
        @($v2.PSObject.Properties.Name|Where-Object {$_ -cnotin $allowedEnvelope}).Count -ne 0 -or
        $v2.schema -cne 'local-official-evidence-v2' -or -not $v2.researchOnly -or
        $v2.publishable -or $v2.downloadEligible -or $v2.metadataSha256 -cne $v1Hash -or
        $v2.recordCount -lt 1 -or $v2.recordCount -gt 16 -or
        @($v2.records).Count -ne $v2.recordCount -or
        $v1.schema -cne 'local-official-metadata-v1' -or $v1.publishable -or
        $v1.downloadEligible -or $v1.recordCount -ne $v2.recordCount -or
        @($v1.records).Count -ne $v2.recordCount) { throw 'ENVELOPE_BINDING' }
    $source=[IO.File]::ReadAllText($sourcePath,[Text.Encoding]::UTF8)
    # source.txtを射影へ結合し、既知ASUSまたはIntel Ethernet source以外を拒否する。
    if ($source -cne $v1.source -or $source -cnotin @('AsusCatalog','IntelEthernetLivePage')) { throw 'SOURCE_BINDING' }
    # 元snapshot実hashがmetadataと違うrunを拒否し、射影を別入力へ付け替えない。
    if ((Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash -ne $v1.snapshotSha256) { throw 'SNAPSHOT_HASH' }
    # record fingerprint fileの実hashがmetadataと違うrunを拒否する。
    if ((Get-FileHash -LiteralPath $fingerprintPath -Algorithm SHA256).Hash -ne $v1.fingerprintsSha256) { throw 'FINGERPRINT_HASH' }
    $fingerprints=[IO.File]::ReadAllText($fingerprintPath,[Text.Encoding]::ASCII).Split([char]10)
    # fingerprint fileのheader・record数・終端空行を照合し、欠落行や余分行を拒否する。
    if ($fingerprints.Count -ne $v2.recordCount+2 -or $fingerprints[0] -cne 'DCRECORDS1' -or
        $fingerprints[-1] -cne '') { throw 'FINGERPRINT_FILE' }
    $expectedModel=$null;$expectedOs=$null;$expectedPage=$null
    # ASUSだけquery根拠をhash検査し、v2 queryなら公開model/OS/pageを固定する。v1はscope未確定に保ち、非ASUSのquery混入は拒否する。
    if ($source -ceq 'AsusCatalog') {
        $queryPath=Join-Path $path 'query.txt'
        $queryHashPath=Join-Path $path 'query.sha256'
        Assert-File $queryPath 512
        Assert-File $queryHashPath 64
        $queryHash=(Get-FileHash -LiteralPath $queryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        # ASUS queryの実hashをmetadataとsidecarの両方へ結合し、違う照会条件を拒否する。
        if ($v1.querySha256 -cne $queryHash -or
            [IO.File]::ReadAllText($queryHashPath,[Text.Encoding]::ASCII) -cne $queryHash) { throw 'QUERY_BINDING' }
        $query=[IO.File]::ReadAllText($queryPath,[Text.Encoding]::ASCII).Split([char]10)
        # query v2はmodel/OS付き8行、v1は6行を許し、それ以外のschemaを拒否する。
        if ($query[0] -ceq 'DCASUSQUERY2') {
            if ($query.Count -ne 8 -or $query[-1] -cne '') { throw 'QUERY_SCHEMA' }
            $expectedModel=$query[5];$expectedOs=$query[6]
            # 公開model根拠に使うOSをWindows10/11 64bitだけへ限定し、別OSをexact根拠へ使わない。
            if ($expectedOs -cnotin @('Windows 11 64-bit','Windows 10 64-bit')) { throw 'QUERY_OS' }
            $expectedPage=Canonical-AsusPage $expectedModel
        } elseif ($query[0] -ceq 'DCASUSQUERY1') {
            if ($query.Count -ne 6 -or $query[-1] -cne '') { throw 'QUERY_SCHEMA' }
        } else { throw 'QUERY_SCHEMA' }
    } elseif ($null -ne $v1.querySha256) { throw 'UNEXPECTED_QUERY' }
    $ordinal=$runs.Count+1
    $runs.Add([ordered]@{ordinal=$ordinal;source=$source;v1Sha256=$v1Hash;v2Sha256=$v2Hash;
        publicModel=$expectedModel;recordCount=$v2.recordCount})
    # v2 recordCount全件をv1とfingerprintの同ordinalへ結合し、公開model根拠を検査して同fingerprintを統合する。
    for($i=0;$i -lt $v2.recordCount;$i++) {
        $old=$v1.records[$i];$entry=$v2.records[$i]
        # 各evidenceのfield集合・fingerprint・title/class/OS/archと未評価purposeをv1/record fileへ結合し、不一致を拒否する。
        if (@($entry.PSObject.Properties.Name).Count -ne $allowedEvidence.Count -or
            @($entry.PSObject.Properties.Name|Where-Object {$_ -cnotin $allowedEvidence}).Count -ne 0 -or
            $entry.fingerprint -cnotmatch '^[0-9a-f]{64}$' -or
            $entry.fingerprint -cne $old.fingerprint -or
            $entry.fingerprint -cne $fingerprints[$i+1] -or
            $entry.displayTitle -cne $old.productFamily -or
            $entry.driverCategory -cne $old.driverCategory -or
            $entry.operatingSystem -cne $old.operatingSystem -or
            $entry.architecture -cne $old.architecture -or
            $entry.purposeMatch -cne 'NOT_ASSESSED') { throw 'RECORD_BINDING' }
        # query v2のmodelがあるrecordだけexact scopeを許し、elseはUNKNOWNかつmodel/page nullを必須にする。
        if ($null -ne $expectedModel) {
            # exact model・公式page・OSがqueryから導いた値と違うrecordを拒否する。
            if ($entry.productScope -cne 'EXACT_PUBLIC_MODEL' -or
                $entry.publicModel -cne $expectedModel -or
                $entry.publicPageUrl -cne $expectedPage -or
                $entry.operatingSystem -cne $expectedOs) { throw 'MODEL_BINDING' }
        } elseif ($entry.productScope -cne 'UNKNOWN' -or $null -ne $entry.publicModel -or
            $null -ne $entry.publicPageUrl) { throw 'UNKNOWN_SCOPE' }
        $rawCount++
        $key=[string]$entry.fingerprint
        $stable=($entry|ConvertTo-Json -Depth 5 -Compress)
        # 同fingerprintは全evidence一致を必須にして観測runだけ追加し、食い違いは競合として拒否する。新規は初回metadata/evidenceを保存する。
        if ($records.ContainsKey($key)) {
            if ($records[$key].stable -cne $stable) { throw 'DUPLICATE_EVIDENCE_CONFLICT' }
            $records[$key].runs.Add($ordinal)
        } else {
            $list=[Collections.Generic.List[int]]::new();$list.Add($ordinal)
            $records[$key]=[pscustomobject]@{stable=$stable;metadata=$old;evidence=$entry;runs=$list}
        }
    }
}
# 一意fingerprintをsort順で全件出力し、観測runは残すが適用性・内容・download許可を未評価のまま保つ。
$outputRecords=foreach($key in @($records.Keys|Sort-Object)) {
    [ordered]@{metadata=$records[$key].metadata;evidence=$records[$key].evidence;
        observedRunOrdinals=@($records[$key].runs.ToArray());deviceApplicability='NOT_ASSESSED';
        payloadInspected=$false;downloadEligible=$false}
}
$exactCount=@($outputRecords|Where-Object {$_.evidence.productScope -ceq 'EXACT_PUBLIC_MODEL'}).Count
$index=[ordered]@{schema='local-official-evidence-index-v2';researchOnly=$true;publishable=$false;
    downloadEligible=$false;evaluationInventoryNodeCount=$InventoryNodeCount;deviceMatchCount=0;
    notAssessedNodeCount=$InventoryNodeCount;runCount=$runs.Count;rawRecordSlots=$rawCount;
    uniqueRecordCount=$records.Count;exactPublicModelCount=$exactCount;
    runs=@($runs.ToArray());records=@($outputRecords)}
$jsonBytes=[Text.UTF8Encoding]::new($false).GetBytes(($index|ConvertTo-Json -Depth 12 -Compress)+"`n")
# JSON生成後のbyteが128MiB超なら圧縮/保存へ進めない。生成前memoryのhard capではない。
if ($jsonBytes.Length -gt 128MB) { throw 'INDEX_EXPANDED_LIMIT' }
$memory=[IO.MemoryStream]::new()
try {$gzip=[IO.Compression.GZipStream]::new($memory,[IO.Compression.CompressionLevel]::Optimal,$true)
    try {$gzip.Write($jsonBytes,0,$jsonBytes.Length)}finally{$gzip.Dispose()}
    $gzipBytes=$memory.ToArray()
}finally{$memory.Dispose()}
# 圧縮結果32MiB超は保存へ進めず、配布形式の圧縮byte上限を維持する。
if ($gzipBytes.Length -gt 32MB) { throw 'INDEX_COMPRESSED_LIMIT' }
$sha=[Security.Cryptography.SHA256]::Create()
try {$jsonHash=[Convert]::ToHexString($sha.ComputeHash($jsonBytes));$gzipHash=[Convert]::ToHexString($sha.ComputeHash($gzipBytes))}finally{$sha.Dispose()}
$receipt=[ordered]@{schema='local-official-evidence-index-receipt-v2';signed=$false;publishable=$false;
    runCount=$runs.Count;rawRecordSlots=$rawCount;uniqueRecordCount=$records.Count;
    exactPublicModelCount=$exactCount;deviceMatchCount=0;payloadGets=0;
    indexJsonBytes=$jsonBytes.Length;indexJsonSha256=$jsonHash;
    indexGzipBytes=$gzipBytes.Length;indexGzipSha256=$gzipHash}
$receiptBytes=[Text.UTF8Encoding]::new($false).GetBytes(($receipt|ConvertTo-Json -Depth 4 -Compress)+"`n")
# receiptの生成byteを64KiB以内に制限してから逐次保存へ進む。
if ($receiptBytes.Length -gt 64KB) { throw 'RECEIPT_LIMIT' }
# 新規Destinationへ三fileを逐次保存する。途中I/O失敗では先行fileとdirectoryを保持し、完成とは扱わない。
# 同じDestinationで再実行すると既存先の検査で拒否するため、途中成果物を自動再利用しない。
$null=New-Item -ItemType Directory -Path $Destination
[IO.File]::WriteAllBytes((Join-Path $Destination 'index.json'),$jsonBytes)
[IO.File]::WriteAllBytes((Join-Path $Destination 'index.json.gz'),$gzipBytes)
[IO.File]::WriteAllBytes((Join-Path $Destination 'receipt-local.json'),$receiptBytes)
Write-Output ('PASS: runs='+$runs.Count+' raw='+$rawCount+' unique='+$records.Count+
    ' exactPublicModel='+$exactCount+' deviceMatches=0 payloadGets=0 jsonBytes='+$jsonBytes.Length+
    ' gzipBytes='+$gzipBytes.Length)
