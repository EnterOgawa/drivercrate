<#
.SYNOPSIS
実公式metadata射影のローカル索引を再生成・拒否試験する。
.DESCRIPTION
作成者: Shunji Ogawa。Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0。repository rootのLICENSEを参照する。
G13-D6j15j2q2b3。通信・payload取得・導入を行わない。
#>
param(
    [Parameter(Mandatory=$true)][string]$PreparedRoot,
    [Parameter(Mandatory=$true)][string[]]$PreparedDirectories,
    [Parameter(Mandatory=$true)][string]$ReferenceIndex,
    [Parameter(Mandatory=$true)][string]$TestRoot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# TestRootの既存先を拒否し、前回fixtureを上書きしない。
if (Test-Path -LiteralPath $TestRoot) { throw 'TEST_ROOT_EXISTS' }
$root=[IO.Path]::GetFullPath($PreparedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$testPath=[IO.Path]::GetFullPath($TestRoot)
# 正規TestRootをPreparedRootの子へ限定し、fixtureを別場所へ作らない。
if (-not $testPath.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'TEST_ROOT_OUTSIDE_WORK' }
$null=New-Item -ItemType Directory -Path $TestRoot
$builder=Join-Path $PSScriptRoot 'build_local_official_metadata_index.ps1'
$second=Join-Path $TestRoot 'second-index'
& $builder -PreparedRoot $PreparedRoot -PreparedDirectories $PreparedDirectories -Destination $second | Out-Null
# 再生成JSON/gzip/receiptの固定三fileを一回ずつ参照hashへ照合し、byte再現性を確認する。
foreach ($name in @('index.json','index.json.gz','receipt-local.json')) {
    if ((Get-FileHash (Join-Path $ReferenceIndex $name) -Algorithm SHA256).Hash -ne
        (Get-FileHash (Join-Path $second $name) -Algorithm SHA256).Hash) { throw ('NONDETERMINISTIC:'+ $name) }
}
$receipt=Get-Content (Join-Path $second 'receipt-local.json') -Raw | ConvertFrom-Json
$index=Get-Content (Join-Path $second 'index.json') -Raw | ConvertFrom-Json
# 未署名・非公開・未適用と固定9run/32slot/25unique/247device分母を照合し、研究結果を取得/導入許可へ昇格しない。
if ($receipt.signed -or $receipt.publishable -or $receipt.runCount -ne 9 -or
    $receipt.rawRecordSlots -ne 32 -or $receipt.uniqueRecordCount -ne 25 -or
    $receipt.deviceMatchCount -ne 0 -or $receipt.payloadGets -ne 0 -or
    $index.schema -ne 'local-official-index-v1' -or $index.publishable -or
    $index.inventoryNodeCount -ne 247 -or $index.notAssessedNodeCount -ne 247 -or
    @($index.records).Count -ne 25 -or
    @($index.records | Where-Object {$_.downloadEligible -or $_.deviceApplicability -ne 'NOT_ASSESSED'}).Count -ne 0) { throw 'INDEX_CONTRACT' }
$bytes=[IO.File]::ReadAllBytes((Join-Path $second 'index.json'))
$gzipBytes=[IO.File]::ReadAllBytes((Join-Path $second 'index.json.gz'))
$stream=[IO.MemoryStream]::new($gzipBytes)
$decoded=[IO.MemoryStream]::new()
try {
    $gzip=[IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionMode]::Decompress)
    try {$gzip.CopyTo($decoded)}finally{$gzip.Dispose()}
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$bytes,[byte[]]$decoded.ToArray())) { throw 'GZIP_ROUNDTRIP' }
}finally{$decoded.Dispose();$stream.Dispose()}
$indexText=[Text.Encoding]::UTF8.GetString($bytes)
# 生成索引にURL・端末ID・HTML/scriptの禁止文字列が残れば、研究metadataのprivacy境界違反として拒否する。
if ($indexText -match '(?i)https?://|PCI\\|USB\\|VEN_|DEV_|VID_|PID_|<html|<script') { throw 'SECRET_IN_INDEX' }

function Copy-TestRun([string]$label,[string]$omit='') {
    $target=Join-Path $TestRoot $label
    $null=New-Item -ItemType Directory -Path $target
    # 固定7入力fileをfixture runへcopyし、omitだけ除いて欠落拒否を試す。
    foreach ($name in @('index-metadata.json','index-metadata.sha256','input.dcgraph','record.txt','source.txt','query.txt','query.sha256')) {
        if ($name -ne $omit) {Copy-Item -LiteralPath (Join-Path $PreparedDirectories[0] $name) -Destination (Join-Path $target $name)}
    }
    return $target
}
function Expect-Rejection([string[]]$paths,[string]$label) {
    $destination=Join-Path $TestRoot ('reject-'+$label)
    $rejected=$false
    try {& $builder -PreparedRoot $PreparedRoot -PreparedDirectories $paths -Destination $destination | Out-Null}
    catch {$rejected=$true}
    if (-not $rejected -or (Test-Path -LiteralPath $destination)) {throw ('REJECTION_FAILED:'+ $label)}
}
function Write-TestMetadata([string]$directory,[object]$object) {
    $path=Join-Path $directory 'index-metadata.json'
    $text=($object|ConvertTo-Json -Depth 10 -Compress)+"`n"
    [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $directory 'index-metadata.sha256'),
        (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant(),[Text.Encoding]::ASCII)
}
$missing=Copy-TestRun 'missing' 'index-metadata.json'
Expect-Rejection @($missing) 'missing'
$hashMismatch=Copy-TestRun 'metadata-hash'
[IO.File]::AppendAllText((Join-Path $hashMismatch 'index-metadata.json'),' ',[Text.Encoding]::UTF8)
Expect-Rejection @($hashMismatch) 'metadata-hash'
$fingerprintMismatch=Copy-TestRun 'fingerprint-hash'
[IO.File]::AppendAllText((Join-Path $fingerprintMismatch 'record.txt'),' ',[Text.Encoding]::ASCII)
Expect-Rejection @($fingerprintMismatch) 'fingerprint-hash'
$secret=Copy-TestRun 'secret'
$object=Get-Content (Join-Path $secret 'index-metadata.json') -Raw | ConvertFrom-Json
$object | Add-Member -NotePropertyName secretUrl -NotePropertyValue 'https://example.invalid/secret'
Write-TestMetadata $secret $object
Expect-Rejection @($secret) 'secret'
$conflict=Copy-TestRun 'conflict'
$object=Get-Content (Join-Path $conflict 'index-metadata.json') -Raw | ConvertFrom-Json
$object.records[0].packageVersion='unbound-version'
Write-TestMetadata $conflict $object
Expect-Rejection @($PreparedDirectories[0],$conflict) 'conflict'
Expect-Rejection @($PreparedDirectories[0],$PreparedDirectories[0]) 'duplicate-run'
$omitted=Copy-TestRun 'omitted-field'
$object=Get-Content (Join-Path $omitted 'index-metadata.json') -Raw | ConvertFrom-Json
$object.records[0].PSObject.Properties.Remove('productFamily')
Write-TestMetadata $omitted $object
Expect-Rejection @($omitted) 'omitted-field'
$oversize=Copy-TestRun 'oversize'
[IO.File]::AppendAllText((Join-Path $oversize 'index-metadata.json'),(' ' * 1MB),[Text.Encoding]::UTF8)
Expect-Rejection @($oversize) 'oversize'
$unicode=Copy-TestRun 'unicode'
$object=Get-Content (Join-Path $unicode 'index-metadata.json') -Raw | ConvertFrom-Json
$object.records[0].productFamily="日本語`"検査`n行"
Write-TestMetadata $unicode $object
$unicodeIndex=Join-Path $TestRoot 'unicode-index'
& $builder -PreparedRoot $PreparedRoot -PreparedDirectories @($unicode) -Destination $unicodeIndex | Out-Null
$decoded=Get-Content (Join-Path $unicodeIndex 'index.json') -Raw -Encoding UTF8 | ConvertFrom-Json
# 日本語・quote・改行を含むproductFamilyが生成索引へ一件正確に戻ることを確認し、Unicodeの消失や重複を拒否する。
if (@($decoded.records).Count -ne $object.recordCount -or
    @($decoded.records | Where-Object {$_.metadata.productFamily -ceq "日本語`"検査`n行"}).Count -ne 1) {
    throw 'UNICODE_ROUNDTRIP'
}
Write-Output ('PASS: deterministic=3 gzip=1 reject=8 unicode=1 runs=9 records=25 deviceMatches=0 payloadGets=0 network=0')
