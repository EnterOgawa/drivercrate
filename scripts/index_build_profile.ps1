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

function Assert-IndexPackagePath {
    <# .SYNOPSIS
    完全修飾local pathと全既存祖先を検査する。link先の採用や欠損親の修復はしない。
    #>
    param([Parameter(Mandatory)][string] $Path, [switch] $Directory, [switch] $AllowMissing)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 32767 -or
        $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':') -or
        $Path -match '[\x00-\x1f<>"|?*]' -or $Path -match '(^|[\\/])\.{1,2}([\\/]|$)' -or
        @($Path.Substring(3) -split '[\\/]' | Where-Object { $_ -match '[ .]$' }).Count -ne 0) {
        throw 'INDEX_PACKAGE_PATH_REJECTED'
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if ($full.Length -lt 3) { throw 'INDEX_PACKAGE_PATH_REJECTED' }
    $current = $full
    $first = $true
    # 欠損するleafの親も、volume rootまで成分ごとに照合する。
    while ($current) {
        $item = $null
        try { $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] {
            # Test-Pathのfalseだけでdangling linkを欠損扱いせず、実providerの不在だけを許す。
            if ($first -and -not $AllowMissing) { throw 'INDEX_PACKAGE_PATH_MISSING' }
        }
        if ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (($Directory -or -not $first) -and -not $item.PSIsContainer) -or
                ($first -and -not $Directory -and $item.PSIsContainer)) {
                throw 'INDEX_PACKAGE_PATH_REJECTED'
            }
        }
        $first = $false
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $full
}

function Get-IndexPackageCacheValue {
    <# .SYNOPSIS
    必須cache keyの欠損・重複・宣言type違いを拒否し、未解釈の値を返す。
    #>
    param([string] $Text, [string] $Name, [string] $Type)
    $key = [regex]::Escape($Name)
    $rows = [regex]::Matches($Text, ('(?m)^[ \t]*' + $key + '(?::[^=\r\n]*)?=[^\r\n]*'))
    if ($rows.Count -ne 1 -or $rows[0].Value -notmatch ('^' + $key + ':' + [regex]::Escape($Type) + '=(.*)$')) {
        throw 'INDEX_PACKAGE_CACHE_FIELD_REJECTED'
    }
    return $Matches[1]
}

function Resolve-IndexPackageBuild {
    <# .SYNOPSIS
    明示buildをscript自身のsourceと通常profileへ束縛する。Private fallbackは行わない。
    .PARAMETER AllowedEmbeddedResources
    installer内だけが自身の固定生成pathと空値を明示する。通常callerは空だけを許可する。
    #>
    param([Parameter(Mandatory)][string] $BuildDirectory, [string[]] $AllowedEmbeddedResources = @(''),
        [switch] $RequireCollector)
    $source = Assert-IndexPackagePath -Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) -Directory
    $build = Assert-IndexPackagePath -Path $BuildDirectory -Directory
    $cachePath = Assert-IndexPackagePath -Path (Join-Path $build 'CMakeCache.txt')
    $text = [Text.UTF8Encoding]::new($false, $true).GetString(
        (Read-BoundedIndexProfileBytes -Path $cachePath -Limit 1048576))
    $packageSourceHome = Assert-IndexPackagePath -Path (Get-IndexPackageCacheValue $text 'CMAKE_HOME_DIRECTORY' 'INTERNAL') -Directory
    if (-not $packageSourceHome.Equals($source, [StringComparison]::OrdinalIgnoreCase)) { throw 'INDEX_PACKAGE_SOURCE_MISMATCH' }
    if ((Get-IndexPackageCacheValue $text 'CMAKE_GENERATOR' 'INTERNAL') -cne 'Ninja Multi-Config' -or
        (Get-IndexPackageCacheValue $text 'CMAKE_CONFIGURATION_TYPES' 'STRING') -cne 'Debug;Release') {
        throw 'INDEX_PACKAGE_CONFIGURATION_REJECTED'
    }
    foreach ($name in @('DRIVERCRATE_BUILD_LIVE_TESTS', 'DRIVERCRATE_ENABLE_ANALYZE',
        'DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE', 'DRIVERCRATE_LOCAL_INDEX_ACQUISITION')) {
        if ((Get-IndexPackageCacheValue $text $name 'BOOL') -cne 'OFF') { throw 'INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED' }
    }
    if ((Get-IndexPackageCacheValue $text 'DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB' 'FILEPATH') -cne '' -or
        (Get-IndexPackageCacheValue $text 'DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256' 'STRING') -cne '') {
        throw 'INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED'
    }
    $collector = Get-IndexPackageCacheValue $text 'DRIVERCRATE_BUILD_COLLECTOR' 'BOOL'
    if ($collector -cnotin @('ON', 'OFF')) { throw 'INDEX_PACKAGE_COLLECTOR_FLAG_REJECTED' }
    if ($RequireCollector -and $collector -cne 'ON') { throw 'INDEX_PACKAGE_COLLECTOR_BUILD_REQUIRED' }
    $embeddedRows = [regex]::Matches($text,
        '(?m)^[ \t]*DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES(?::[^=\r\n]*)?=[^\r\n]*')
    # CMakeが生成しないapp-onlyの一keyだけ欠損を認め、collector ON時は必須のままにする。
    $embedded = if ($collector -ceq 'OFF' -and $embeddedRows.Count -eq 0) { '' } else {
        Get-IndexPackageCacheValue $text 'DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES' 'PATH'
    }
    # CMakeのslash表記と同じpathだけを比較し、別resource入力を包括許可しない。
    $allowed = @($AllowedEmbeddedResources | ForEach-Object { $_.Replace('\', '/') })
    if ($embedded.Replace('\', '/') -cnotin $allowed) { throw 'INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED' }
    return [pscustomobject]@{ Source = $source; Build = $build
        OutputRoots = @((Join-Path $source 'out'), (Join-Path ([IO.Path]::GetDirectoryName($build)) 'out')) }
}

function Assert-IndexPackageOutput {
    <# .SYNOPSIS
    source/out又は選択build親/outの新規childだけを受理し、既存先を削除しない。
    #>
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)][string] $Path,
        [switch] $AllowRoot, [switch] $Fresh)
    $full = Assert-IndexPackagePath -Path $Path -Directory -AllowMissing
    $accepted = $false
    foreach ($base in $Context.OutputRoots) {
        $base = [IO.Path]::GetFullPath($base).TrimEnd('\', '/')
        if ($full.StartsWith(($base + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) -or
            ($AllowRoot -and $full.Equals($base, [StringComparison]::OrdinalIgnoreCase))) { $accepted = $true }
    }
    if (-not $accepted -or ($Fresh -and (Test-Path -LiteralPath $full))) { throw 'INDEX_PACKAGE_NEW_OUTPUT_REQUIRED' }
    return $full
}

function Assert-IndexPackageDistinctPaths {
    <# .SYNOPSIS
    package入力と出力/fixtureの同一又は相互包含を拒否する。
    #>
    param([Parameter(Mandatory)][string[]] $Paths)
    for ($i = 0; $i -lt $Paths.Count; ++$i) {
        for ($j = $i + 1; $j -lt $Paths.Count; ++$j) {
            $left = [IO.Path]::GetFullPath($Paths[$i]).TrimEnd('\', '/')
            $right = [IO.Path]::GetFullPath($Paths[$j]).TrimEnd('\', '/')
            if ($left.Equals($right, [StringComparison]::OrdinalIgnoreCase) -or
                $left.StartsWith(($right + '\'), [StringComparison]::OrdinalIgnoreCase) -or
                $right.StartsWith(($left + '\'), [StringComparison]::OrdinalIgnoreCase)) {
                throw 'INDEX_PACKAGE_INPUT_OUTPUT_OVERLAP'
            }
        }
    }
}

function Assert-IndexPackageExecutable {
    <# .SYNOPSIS
    既存v2のtrust/hash照合後、実PE headerのx64/PE32+を非実行で確認する。
    #>
    param([Parameter(Mandatory)][string] $Executable)
    $path = Assert-IndexPackagePath -Path $Executable
    Assert-DistributableIndexBuild -Executable $path
    $stream = [IO.File]::OpenRead($path)
    try {
        $dos = [byte[]]::new(64)
        if ($stream.Read($dos, 0, 64) -ne 64 -or $dos[0] -ne 77 -or $dos[1] -ne 90) { throw 'INDEX_PACKAGE_X64_REQUIRED' }
        $offset = [BitConverter]::ToInt32($dos, 60)
        if ($offset -lt 64 -or $offset -gt 1048576 -or $offset -gt $stream.Length - 26) { throw 'INDEX_PACKAGE_X64_REQUIRED' }
        [void]$stream.Seek($offset, [IO.SeekOrigin]::Begin)
        $pe = [byte[]]::new(26)
        if ($stream.Read($pe, 0, 26) -ne 26 -or [BitConverter]::ToUInt32($pe, 0) -ne 17744 -or
            [BitConverter]::ToUInt16($pe, 4) -ne 34404 -or [BitConverter]::ToUInt16($pe, 24) -ne 523) {
            throw 'INDEX_PACKAGE_X64_REQUIRED'
        }
    } finally { $stream.Dispose() }
}

function Invoke-IndexPackageBuildAndRestore {
    <# .SYNOPSIS
    固定builder処理と復帰を順に実行し、両方の原例外を失わない。
    #>
    param([Parameter(Mandatory)][scriptblock] $Operation, [Parameter(Mandatory)][scriptblock] $Restore)
    $primary = $null
    $recovery = $null
    $result = $null
    try { $result = & $Operation } catch { $primary = $_ }
    finally { try { & $Restore } catch { $recovery = $_ } }
    if ($null -ne $primary -and $null -ne $recovery) {
        $failure = [AggregateException]::new('INSTALLER_BUILD_AND_RESTORE_FAILED',
            [Exception[]]@($primary.Exception, $recovery.Exception))
        $failure.Data['PrimaryErrorRecord'] = $primary
        $failure.Data['RestoreErrorRecord'] = $recovery
        throw $failure
    }
    if ($null -ne $primary) { throw $primary }
    if ($null -ne $recovery) { throw $recovery }
    return $result
}
