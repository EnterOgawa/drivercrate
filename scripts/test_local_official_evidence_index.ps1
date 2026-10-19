<#
.SYNOPSIS
公式公開model根拠索引v2の再現性と拒否境界を非通信で検証する。
.DESCRIPTION
作成者: Shunji Ogawa。Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0。repository rootのLICENSEを参照する。
G13-D6j15j2q4b2c。既存の実runをcopyし、network・payload・導入は行わない。
#>
param(
    [Parameter(Mandatory=$true)][string]$PreparedRoot,
    [Parameter(Mandatory=$true)][string[]]$PreparedDirectories,
    [Parameter(Mandatory=$true)][string]$ReferenceIndex,
    [Parameter(Mandatory=$true)][string]$TestRoot,
    [Parameter(Mandatory=$true)][int]$InventoryNodeCount
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath($PreparedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$testPath=[IO.Path]::GetFullPath($TestRoot)
# TestRootは未存在かつPreparedRoot配下の子pathへ限定し、既存結果や別場所へfixtureを作らない。
if ((Test-Path -LiteralPath $TestRoot) -or
    -not $testPath.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'TEST_ROOT'
}
$null=New-Item -ItemType Directory -Path $TestRoot
$builder=Join-Path $PSScriptRoot 'build_local_official_evidence_index.ps1'
$second=Join-Path $TestRoot 'second-index'
& $builder -PreparedRoot $PreparedRoot -PreparedDirectories $PreparedDirectories -Destination $second -InventoryNodeCount $InventoryNodeCount | Out-Null
# 再生成したJSON/gzip/receiptの固定三fileを参照hashへ一件ずつ照合して再現性を確認する。
foreach($name in @('index.json','index.json.gz','receipt-local.json')) {
    if ((Get-FileHash (Join-Path $ReferenceIndex $name) -Algorithm SHA256).Hash -ne
        (Get-FileHash (Join-Path $second $name) -Algorithm SHA256).Hash) { throw ('NONDETERMINISTIC:'+ $name) }
}
$index=Get-Content (Join-Path $second 'index.json') -Raw | ConvertFrom-Json
$receipt=Get-Content (Join-Path $second 'receipt-local.json') -Raw | ConvertFrom-Json
# 研究索引の未署名・非公開・非download・適用未評価と固定run/record/model件数を全て照合する。
if ($index.publishable -or $index.downloadEligible -or $index.deviceMatchCount -ne 0 -or
    $index.notAssessedNodeCount -ne $InventoryNodeCount -or $index.runCount -ne 3 -or
    $index.rawRecordSlots -ne 6 -or $index.uniqueRecordCount -ne 6 -or
    $index.exactPublicModelCount -ne 1 -or $receipt.signed -or $receipt.payloadGets -ne 0 -or
    @($index.records|Where-Object {$_.downloadEligible -or $_.deviceApplicability -ne 'NOT_ASSESSED'}).Count -ne 0) {
    throw 'INDEX_CONTRACT'
}
$bytes=[IO.File]::ReadAllBytes((Join-Path $second 'index.json'))
$compressed=[IO.File]::ReadAllBytes((Join-Path $second 'index.json.gz'))
$input=[IO.MemoryStream]::new($compressed)
$output=[IO.MemoryStream]::new()
try {$gzip=[IO.Compression.GZipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)
    try {$gzip.CopyTo($output)}finally{$gzip.Dispose()}
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$bytes,[byte[]]$output.ToArray())) { throw 'GZIP' }
}finally{$output.Dispose();$input.Dispose()}
function Copy-TestRun([string]$label,[string]$omit='') {
    $target=Join-Path $TestRoot $label
    $null=New-Item -ItemType Directory -Path $target
    # 固定9入力fileをfixture runへcopyし、omit指定fileだけ除いて欠落拒否を試せるようにする。
    foreach($name in @('index-metadata.json','index-metadata.sha256','index-evidence-v2.json',
        'index-evidence-v2.sha256','input.dcgraph','record.txt','source.txt','query.txt','query.sha256')) {
        if ($name -ne $omit) { Copy-Item -LiteralPath (Join-Path $PreparedDirectories[0] $name) -Destination (Join-Path $target $name) }
    }
    return $target
}
function Rewrite-Evidence([string]$directory,[object]$object) {
    $path=Join-Path $directory 'index-evidence-v2.json'
    [IO.File]::WriteAllText($path,(($object|ConvertTo-Json -Depth 8 -Compress)+"`n"),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $directory 'index-evidence-v2.sha256'),
        (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant(),[Text.Encoding]::ASCII)
}
function Rewrite-Metadata([string]$directory,[object]$object) {
    $path=Join-Path $directory 'index-metadata.json'
    [IO.File]::WriteAllText($path,(($object|ConvertTo-Json -Depth 10 -Compress)+"`n"),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $directory 'index-metadata.sha256'),
        (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant(),[Text.Encoding]::ASCII)
}
function Expect-Rejection([string[]]$paths,[string]$label) {
    $destination=Join-Path $TestRoot ('reject-'+$label)
    $rejected=$false
    try {& $builder -PreparedRoot $PreparedRoot -PreparedDirectories $paths -Destination $destination -InventoryNodeCount $InventoryNodeCount | Out-Null}
    catch {$rejected=$true}
    if (-not $rejected -or (Test-Path -LiteralPath $destination)) { throw ('REJECTION_FAILED:'+ $label) }
}
$missing=Copy-TestRun 'missing' 'index-evidence-v2.json'
Expect-Rejection @($missing) 'missing'
$hash=Copy-TestRun 'hash'
[IO.File]::AppendAllText((Join-Path $hash 'index-evidence-v2.json'),' ',[Text.Encoding]::UTF8)
Expect-Rejection @($hash) 'hash'
$query=Copy-TestRun 'query'
[IO.File]::AppendAllText((Join-Path $query 'query.txt'),' ',[Text.Encoding]::ASCII)
Expect-Rejection @($query) 'query'
$url=Copy-TestRun 'url'
$object=Get-Content (Join-Path $url 'index-evidence-v2.json') -Raw | ConvertFrom-Json
$object.records[0].publicPageUrl='https://example.invalid/redirect'
Rewrite-Evidence $url $object
Expect-Rejection @($url) 'url'
$scope=Copy-TestRun 'scope'
$object=Get-Content (Join-Path $scope 'index-evidence-v2.json') -Raw | ConvertFrom-Json
$object.records[0].productScope='UNKNOWN'
Rewrite-Evidence $scope $object
Expect-Rejection @($scope) 'scope'
$secret=Copy-TestRun 'secret'
$object=Get-Content (Join-Path $secret 'index-evidence-v2.json') -Raw | ConvertFrom-Json
$object.records[0].displayTitle='PCI\VEN_1234'
Rewrite-Evidence $secret $object
Expect-Rejection @($secret) 'secret'
Expect-Rejection @($PreparedDirectories[0],$PreparedDirectories[0]) 'duplicate-run'
$fingerprint=Copy-TestRun 'fingerprint'
[IO.File]::AppendAllText((Join-Path $fingerprint 'record.txt'),' ',[Text.Encoding]::ASCII)
Expect-Rejection @($fingerprint) 'fingerprint'
$missingField=Copy-TestRun 'missing-field'
$object=Get-Content (Join-Path $missingField 'index-evidence-v2.json') -Raw | ConvertFrom-Json
$object.records[0].PSObject.Properties.Remove('publicModel')
Rewrite-Evidence $missingField $object
Expect-Rejection @($missingField) 'missing-field'
$changedModel=Copy-TestRun 'changed-model'
$queryPath=Join-Path $changedModel 'query.txt'
$queryText=[IO.File]::ReadAllText($queryPath,[Text.Encoding]::ASCII).Replace('PRIME B760-PLUS D4','PRIME B760-PLUS D5')
[IO.File]::WriteAllText($queryPath,$queryText,[Text.Encoding]::ASCII)
$queryHash=(Get-FileHash $queryPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $changedModel 'query.sha256'),$queryHash,[Text.Encoding]::ASCII)
$metadata=Get-Content (Join-Path $changedModel 'index-metadata.json') -Raw | ConvertFrom-Json
$metadata.querySha256=$queryHash
Rewrite-Metadata $changedModel $metadata
$evidence=Get-Content (Join-Path $changedModel 'index-evidence-v2.json') -Raw | ConvertFrom-Json
$evidence.metadataSha256=(Get-FileHash (Join-Path $changedModel 'index-metadata.json') -Algorithm SHA256).Hash.ToLowerInvariant()
Rewrite-Evidence $changedModel $evidence
Expect-Rejection @($changedModel) 'changed-model'
Write-Output ('PASS: deterministic=3 gzip=1 reject=10 runs=3 records=6 exactPublicModel=1 deviceMatches=0 payloadGets=0 network=0')
