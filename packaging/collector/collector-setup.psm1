#requires -Version 5.1
<#
.SYNOPSIS
Validates and installs the manual, metadata-only collector preview.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
No elevation, execution-policy changes, network, task registration, or recursive deletion.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CollectorPayloadFiles {
    param([switch] $Seeded, [switch] $RegistryRuntime, [switch] $ProtectedWorkspace)
    @('bin/DriverCrateCollector.exe', 'DriverCrateCollectorSetup.exe', 'config/targets.json',
        'docs/adr/0209-local-first-recurring-driver-collector.md', 'LICENSE',
        'THIRD_PARTY_NOTICES.md', 'README-collector.md',
        'Install.cmd', 'Validate.cmd', 'Collect.cmd', 'Uninstall.cmd')
    if ($Seeded) {
        Get-CollectorSeedFiles
        if ($RegistryRuntime) { 'seed/collector-data/locators.json' }
    }
    if ($RegistryRuntime) {
        @('registry_daily_monitor', 'collector_locator_snapshot', 'collector_public_locators',
            'collector_registry', 'registry_locator_requests', 'registry_monitor_http',
            'registry_page_requests', 'collector_payload_evidence', 'collector_page_encoding',
            'collector_published_hrefs') | ForEach-Object { 'scripts/' + $_ + '.py' }
        'runtime/python-runtime-manifest.json'
        Get-CollectorRuntimeFiles | ForEach-Object { 'runtime/' + $_ }
    }
    if ($ProtectedWorkspace) {
        @('scripts/collector_workspace.py', 'config/monitor-policy.json', 'Initialize.cmd', 'Import.cmd', 'Export.cmd')
    }
}

function Get-CollectorRuntimeFiles {
    @('LICENSE.txt', '_asyncio.pyd', '_bz2.pyd', '_ctypes.pyd', '_decimal.pyd',
        '_elementtree.pyd', '_hashlib.pyd', '_lzma.pyd', '_multiprocessing.pyd',
        '_overlapped.pyd', '_queue.pyd', '_socket.pyd', '_sqlite3.pyd', '_ssl.pyd',
        '_uuid.pyd', '_wmi.pyd', '_zoneinfo.pyd', 'libcrypto-3.dll', 'libffi-8.dll',
        'libssl-3.dll', 'pyexpat.pyd', 'python.cat', 'python.exe', 'python3.dll',
        'python313._pth', 'python313.dll', 'python313.zip', 'pythonw.exe', 'select.pyd',
        'sqlite3.dll', 'unicodedata.pyd', 'vcruntime140.dll', 'vcruntime140_1.dll', 'winsound.pyd')
}

function Assert-CollectorRuntime {
    param([Parameter(Mandatory)][string] $Directory)
    $root = Join-Path $Directory 'runtime'
    $path = Join-Path $root 'python-runtime-manifest.json'
    # runtime manifest自身の固定hashを先に照合し、差し替えたmetadataでpayloadを正当化させない。
    if ((Get-CollectorSetupHash $path) -cne '00691561b72690d21156e5777ddc9fec9226353fd3b816e614894f9c6503942e') {
        throw 'SETUP_RUNTIME_METADATA_HASH_REJECTED'
    }
    $metadata = Read-CollectorSetupJson $path
    $expected = @(Get-CollectorRuntimeFiles)
    # CPythonのschema・版・x64と固定file数が異なるruntimeを拒否する。
    if ($metadata.schema -cne 'dc-cpython-runtime-v1' -or $metadata.version -cne '3.13.16' -or
        $metadata.architecture -cne 'x64' -or @($metadata.files).Count -ne $expected.Count) {
        throw 'SETUP_RUNTIME_SCHEMA_REJECTED'
    }
    # 固定runtime一覧を順序どおり最後まで走査し、各fileのpath・size・hashと必要なx64 PEを検査する。
    for ($i = 0; $i -lt $expected.Count; ++$i) {
        $row = $metadata.files[$i]
        $file = Join-Path $root $expected[$i]
        # 順序を含むmanifest path・実size・hashが違うruntime fileを拒否する。
        if ($row.path -cne $expected[$i] -or (Get-Item -LiteralPath $file -Force).Length -ne $row.bytes -or
            (Get-CollectorSetupHash $file) -cne $row.sha256) { throw 'SETUP_RUNTIME_HASH_REJECTED' }
        # exe・dll・pydだけPEのx64検査を追加し、data fileへPE検査を適用しない。
        if ($expected[$i] -cmatch '\.(exe|dll|pyd)$') { Assert-CollectorX64Executable $file }
    }
}

function Get-CollectorSeedFiles {
    @('manifest.json', 'observations.json', 'payload-evidence.json', 'products.json',
        'records.json', 'sources.json', 'index/drivers.json') |
        ForEach-Object { 'seed/collector-data/' + $_ }
}

function Get-CollectorDefaultDirectory {
    Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'DriverCrate\Collector'
}

function Assert-CollectorSetupPath {
    param([Parameter(Mandatory)][string] $Path, [switch] $Existing)
    # Use only explicit local-drive paths; do not reinterpret UNC or device namespaces.
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.IndexOf(':', 2) -ge 0 -or
        $Path -match '(^|[\\/])\.{1,2}([\\/]|$)') { throw 'SETUP_PATH_REJECTED' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    # drive root自身や非固定driveを配置先にせず、固定driveの子directoryだけを受け付ける。
    if ($full.Length -le 3 -or (New-Object IO.DriveInfo($full.Substring(0, 3))).DriveType -ne 'Fixed') {
        throw 'SETUP_FIXED_DRIVE_REQUIRED'
    }
    $probe = $full
    # Inspect every existing ancestor before reading or creating children.
    while ($probe) {
        if (Test-Path -LiteralPath $probe) {
            $item = Get-Item -LiteralPath $probe -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'SETUP_REPARSE_OR_FILE_REJECTED'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($probe)
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
    if ($Existing -and -not (Test-Path -LiteralPath $full -PathType Container)) {
        throw 'SETUP_DIRECTORY_MISSING'
    }
    $full
}

function Get-CollectorSetupHash {
    param([Parameter(Mandatory)][string] $Path)
    $item = Get-Item -LiteralPath $Path -Force
    # hash対象を通常fileに限定し、directoryやreparse fileの中身をhashして受理しない。
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'SETUP_PAYLOAD_FILE_REJECTED'
    }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-CollectorSetupJson {
    param([Parameter(Mandatory)][string] $Path, [long] $MaximumBytes = 262144)
    $item = Get-Item -LiteralPath $Path -Force
    # JSON入力は通常fileかつ呼出し上限以内に限り、directory・reparse・過大入力をdecode前に拒否する。
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -gt $MaximumBytes) { throw 'SETUP_JSON_REJECTED' }
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $utf8.GetString([IO.File]::ReadAllBytes($Path)) | ConvertFrom-Json
}

function Assert-CollectorX64Executable {
    param([Parameter(Mandatory)][string] $Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        # PE入力を128B以上64MiB以下とMZに限定し、過小・過大・非実行形式を先に拒否する。
        if ($stream.Length -lt 128 -or $stream.Length -gt 67108864 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw 'SETUP_PE_REJECTED'
        }
        $stream.Position = 0x3c
        $offset = $reader.ReadUInt32()
        # PE offsetを64B以上1MiB以下かつfile内へ限定し、後続26Bを読めない入力を拒否する。
        if ($offset -lt 64 -or $offset -gt 1048576 -or [long]$offset + 26 -gt $stream.Length) {
            throw 'SETUP_PE_REJECTED'
        }
        $stream.Position = $offset
        # PE signatureとAMD64 machineを照合し、x86や別architectureの実行fileを拒否する。
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw 'SETUP_X64_REQUIRED'
        }
        $stream.Position = [long]$offset + 24
        # optional headerがPE32+でない実行fileを拒否し、readerとstreamはfinallyで閉じる。
        if ($reader.ReadUInt16() -ne 0x20b) { throw 'SETUP_PE32_PLUS_REQUIRED' }
    }
    finally { $reader.Dispose(); $stream.Dispose() }
}

function Get-CollectorBundleInventory {
    param([Parameter(Mandatory)][string] $Directory, [switch] $Installed, [switch] $Seeded,
        [switch] $RegistryRuntime)
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($Directory)
    $count = 0
    # Never traverse collection data or a reparse directory; cap bundle entries.
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $current -Force)) {
            if (++$count -gt 128 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'SETUP_INVENTORY_REJECTED'
            }
            $relative = $item.FullName.Substring($Directory.Length + 1).Replace('\', '/')
            if ($item.PSIsContainer) {
                if ($Installed -and $relative -ceq 'work') { continue }
                $directories = @('bin', 'config', 'docs', 'docs/adr')
                if ($Seeded) { $directories += @('seed', 'seed/collector-data', 'seed/collector-data/index') }
                if ($RegistryRuntime) { $directories += @('runtime', 'scripts') }
                if ($relative -cnotin $directories) {
                    throw 'SETUP_EXTRA_DIRECTORY'
                }
                $pending.Push($item.FullName)
            }
            else { $relative }
        }
    }
}

function Assert-CollectorSeedFields {
    param($Document, [string[]] $Names)
    $actual = @($Document.PSObject.Properties.Name | Sort-Object)
    # JSONのproperty集合を固定名と完全照合し、欠落だけでなく余分なfieldも拒否する。
    if (($actual -join "`n") -cne (($Names | Sort-Object) -join "`n")) { throw 'SETUP_SEED_FIELDS_REJECTED' }
}

<#
.SYNOPSIS
研究seedの文書間整合性をlocal読取りだけで検査する。
.DESCRIPTION
manifest、台帳、索引、取得証拠と対象modeのlocatorについて、固定schema、field、順序、
hashと件数を照合する。不一致・I/O失敗は例外で拒否する。検査の通過は端末適合・署名・
通信・driver導入・公開の許可ではなく、研究用の境界flagを維持する。
.PARAMETER Directory
seed/collector-dataを含む検査対象のbundle root。
.PARAMETER RegistryRuntime
runtime付き研究seedのschemaとlocatorを検査する既存mode。
#>
function Assert-CollectorResearchSeed {
    param([Parameter(Mandatory)][string] $Directory, [switch] $RegistryRuntime)
    $root = Join-Path $Directory 'seed\collector-data'
    $manifest = Read-CollectorSetupJson (Join-Path $root 'manifest.json')
    $fields = @('schema', 'revision', 'asOf', 'registrySha256', 'files')
    $schema = 'dc-portable-research-snapshot-v2'
    if ($RegistryRuntime) {
        $fields += @('registrySchema', 'includesPayloadEvidence', 'includesPublicLocators')
        $schema = 'dc-portable-research-snapshot-v4'
    }
    Assert-CollectorSeedFields $manifest $fields
    if ($manifest.schema -cne $schema -or
        $manifest.registrySha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'SETUP_SEED_SCHEMA_REJECTED' }
    if ($RegistryRuntime -and ($manifest.registrySchema -cne 'dc-public-driver-registry-v2' -or
        $manifest.includesPayloadEvidence -isnot [bool] -or -not $manifest.includesPayloadEvidence -or
        $manifest.includesPublicLocators -isnot [bool] -or -not $manifest.includesPublicLocators)) {
        throw 'SETUP_SEED_REGISTRY_SCHEMA_REJECTED'
    }
    $expected = @('index/drivers.json', 'observations.json', 'payload-evidence.json',
        'products.json', 'records.json', 'sources.json')
    if ($RegistryRuntime) { $expected = @('index/drivers.json', 'locators.json', 'observations.json',
        'payload-evidence.json', 'products.json', 'records.json', 'sources.json') }
    $rows = @($manifest.files)
    if ($rows.Count -ne $expected.Count) { throw 'SETUP_SEED_COUNT_REJECTED' }
    for ($i = 0; $i -lt $rows.Count; ++$i) {
        $row = $rows[$i]
        Assert-CollectorSeedFields $row @('path', 'bytes', 'sha256')
        $path = Join-Path $root $expected[$i]
        if ($row.path -cne $expected[$i] -or $row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $row.bytes -is [bool] -or $row.bytes -isnot [ValueType] -or $row.bytes -lt 0 -or
            $row.bytes -gt 16777216 -or [Math]::Floor([double]$row.bytes) -ne $row.bytes -or
            (Get-Item -LiteralPath $path -Force).Length -ne $row.bytes -or
            (Get-CollectorSetupHash $path) -cne $row.sha256) { throw 'SETUP_SEED_HASH_REJECTED' }
    }
    $documents = @{}
    foreach ($name in @('sources', 'products', 'records', 'observations')) {
        $document = Read-CollectorSetupJson (Join-Path $root ($name + '.json')) -MaximumBytes 16777216
        Assert-CollectorSeedFields $document @('schema', 'revision', 'asOf', 'items')
        $suffix = '-v1'
        if ($RegistryRuntime) { $suffix = '-v2' }
        if ($document.schema -cne ('dc-public-driver-' + $name + $suffix) -or
            $document.revision -cne $manifest.revision -or $document.asOf -cne $manifest.asOf -or
            $document.items -isnot [Array]) { throw 'SETUP_SEED_COLLECTION_REJECTED' }
        $documents[$name] = $document
    }
    $index = Read-CollectorSetupJson (Join-Path $root 'index\drivers.json') -MaximumBytes 16777216
    $indexFields = @('schema', 'revision', 'asOf', 'researchOnly', 'publishable',
        'installAuthorized', 'applicability', 'counts', 'sources', 'products', 'records', 'payloadEvidence')
    if ($RegistryRuntime) { $indexFields += 'registrySchema' }
    Assert-CollectorSeedFields $index $indexFields
    $evidence = Read-CollectorSetupJson (Join-Path $root 'payload-evidence.json') -MaximumBytes 16777216
    $evidenceFields = @('schema', 'revision', 'registryRevision', 'registrySha256', 'asOf', 'acquisitions')
    $indexSchema = 'dc-local-research-index-v2'
    $evidenceSchema = 'dc-public-payload-evidence-v1'
    if ($RegistryRuntime) {
        $evidenceFields += 'originRegistry'
        $indexSchema = 'dc-local-research-index-v3'
        $evidenceSchema = 'dc-public-payload-evidence-v2'
    }
    Assert-CollectorSeedFields $evidence $evidenceFields
    if ($index.schema -cne $indexSchema -or $index.revision -cne $manifest.revision -or
        $index.researchOnly -isnot [bool] -or -not $index.researchOnly -or
        $index.publishable -isnot [bool] -or $index.publishable -or
        $index.installAuthorized -isnot [bool] -or $index.installAuthorized -or
        $index.applicability -cne 'NOT_CHECKED' -or $index.asOf -cne $evidence.asOf -or
        $evidence.schema -cne $evidenceSchema -or
        $evidence.registryRevision -cne $manifest.revision -or
        $evidence.registrySha256 -cne $manifest.registrySha256) { throw 'SETUP_SEED_RESEARCH_BOUNDARY_REJECTED' }
    if ($RegistryRuntime) {
        $locators = Read-CollectorSetupJson (Join-Path $root 'locators.json') -MaximumBytes 16777216
        Assert-CollectorSeedFields $locators @('schema', 'revision', 'asOf', 'registry', 'researchOnly',
            'publishable', 'installAuthorized', 'locators')
        Assert-CollectorSeedFields $locators.registry @('schema', 'revision', 'asOf', 'sha256')
        if ($index.registrySchema -cne 'dc-public-driver-registry-v2' -or
            $locators.schema -cne 'dc-public-driver-locators-v2' -or $locators.researchOnly -isnot [bool] -or
            -not $locators.researchOnly -or $locators.publishable -isnot [bool] -or $locators.publishable -or
            $locators.installAuthorized -isnot [bool] -or $locators.installAuthorized -or
            $locators.registry.schema -cne $manifest.registrySchema -or
            $locators.registry.revision -cne $manifest.revision -or $locators.registry.asOf -cne $manifest.asOf -or
            $locators.registry.sha256 -cne $manifest.registrySha256) { throw 'SETUP_SEED_LOCATOR_BINDING_REJECTED' }
    }
    foreach ($name in @('sources', 'products')) {
        if (($index.$name | ConvertTo-Json -Depth 80 -Compress) -cne
            ($documents[$name].items | ConvertTo-Json -Depth 80 -Compress)) { throw 'SETUP_SEED_INDEX_BINDING_REJECTED' }
    }
    if ($index.records -isnot [Array] -or $index.records.Count -ne $documents.records.items.Count -or
        $index.counts.targetProducts -is [bool] -or $index.counts.distributionRecords -is [bool] -or
        $index.counts.deviceApplicabilityMeasured -is [bool] -or
        $index.counts.targetProducts -ne $documents.products.items.Count -or
        $index.counts.distributionRecords -ne $documents.records.items.Count -or
        $index.counts.deviceApplicabilityMeasured -ne 0 -or
        ($index.payloadEvidence | ConvertTo-Json -Depth 80 -Compress) -cne
        ($evidence | ConvertTo-Json -Depth 80 -Compress)) { throw 'SETUP_SEED_INDEX_BINDING_REJECTED' }
    for ($i = 0; $i -lt $index.records.Count; ++$i) {
        if ($index.records[$i].id -cne $documents.records.items[$i].id) { throw 'SETUP_SEED_RECORD_BINDING_REJECTED' }
    }
}

<#
.SYNOPSIS
固定bundleをread-onlyで検査し、root、manifest、hashとmode flagを返す。
.DESCRIPTION
固定file集合、hash、x64 PE、該当seed/runtimeとInstalled時のreceiptを照合し、
不一致・I/O失敗は例外で拒否する。Installed時のconfig/targets.jsonは編集可能なため
JSON検査を行い、native検証を必須とする既存例外を維持する。
戻り値だけで収集・process実行・通信・driver導入を許可しない。
.PARAMETER Directory
既存の検査対象bundle directory。
.PARAMETER Installed
配置済みworkspaceのreceiptと編集可能な設定を扱う検査mode。
.OUTPUTS
正規root、manifest、manifest hash、Seeded、RegistryRuntime、ProtectedWorkspaceの値。
#>
function Read-CollectorBundle {
    param([Parameter(Mandatory)][string] $Directory, [switch] $Installed)
    $root = Assert-CollectorSetupPath $Directory -Existing
    $manifestPath = Join-Path $root 'package-manifest.json'
    $manifest = Read-CollectorSetupJson $manifestPath
    $protectedWorkspace = ($manifest.schema -ceq 'dc-collector-package-v4' -and
        $manifest.mode -ceq 'OFFLINE_PROTECTED_REGISTRY_WORKSPACE') -or
        ($manifest.schema -ceq 'dc-collector-package-v5' -and $manifest.mode -ceq 'EXPLICIT_ONCE_REGISTRY_MONITOR')
    $registryRuntime = $protectedWorkspace -or ($manifest.schema -ceq 'dc-collector-package-v3' -and
        $manifest.mode -ceq 'MANUAL_REGISTRY_WITH_RUNTIME')
    $seeded = $registryRuntime -or ($manifest.schema -ceq 'dc-collector-package-v2' -and
        $manifest.mode -ceq 'MANUAL_METADATA_WITH_RESEARCH_SEED')
    $legacy = $manifest.schema -ceq 'dc-collector-package-v1' -and $manifest.mode -ceq 'MANUAL_METADATA_ONLY'
    if (@($manifest.PSObject.Properties).Count -ne 5 -or (-not $seeded -and -not $legacy) -or
        $manifest.version -notmatch '^\d+\.\d+\.\d+$' -or $manifest.architecture -cne 'x64') {
        throw 'SETUP_MANIFEST_REJECTED'
    }
    $expected = @(Get-CollectorPayloadFiles -Seeded:$seeded -RegistryRuntime:$registryRuntime -ProtectedWorkspace:$protectedWorkspace)
    $rows = @($manifest.files)
    if ($rows.Count -ne $expected.Count) { throw 'SETUP_FILE_COUNT_REJECTED' }
    $allowed = @($expected) + @('package-manifest.json')
    if ($Installed) { $allowed += 'install-receipt.json' }
    $inventory = @(Get-CollectorBundleInventory $root -Installed:$Installed -Seeded:$seeded -RegistryRuntime:$registryRuntime)
    if (@($inventory | Where-Object { $_.StartsWith('seed/', [StringComparison]::Ordinal) -and
            $_ -cnotin $expected }).Count -ne 0) { throw 'SETUP_FILE_INVENTORY_REJECTED' }
    if ($registryRuntime -and @($inventory | Where-Object { ($_ -cmatch '^(runtime|scripts)/') -and
            $_ -cnotin $expected }).Count -ne 0) { throw 'SETUP_FILE_INVENTORY_REJECTED' }
    $missing = @($allowed | Where-Object { $_ -cnotin $inventory })
    if ($missing.Count -ne 0 -or (-not $Installed -and
        (($inventory | Sort-Object) -join "`n") -cne (($allowed | Sort-Object) -join "`n"))) {
        throw 'SETUP_FILE_INVENTORY_REJECTED'
    }
    for ($index = 0; $index -lt $expected.Count; ++$index) {
        $row = $rows[$index]
        if (@($row.PSObject.Properties).Count -ne 3 -or $row.path -cne $expected[$index] -or
            $row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $row.bytes -is [bool] -or $row.bytes -isnot [ValueType] -or
            $row.bytes -lt 0 -or $row.bytes -gt 67108864 -or [Math]::Floor([double]$row.bytes) -ne $row.bytes) {
            throw 'SETUP_FILE_RECORD_REJECTED'
        }
        $path = Join-Path $root $row.path
        # User configuration remains editable after installation; native validation is mandatory.
        if ($Installed -and $row.path -ceq 'config/targets.json') {
            [void](Read-CollectorSetupJson $path)
            continue
        }
        if ((Get-Item -LiteralPath $path -Force).Length -ne $row.bytes -or
            (Get-CollectorSetupHash $path) -cne $row.sha256) { throw 'SETUP_PAYLOAD_HASH_REJECTED' }
    }
    Assert-CollectorX64Executable (Join-Path $root 'bin/DriverCrateCollector.exe')
    Assert-CollectorX64Executable (Join-Path $root 'DriverCrateCollectorSetup.exe')
    if ($seeded) { Assert-CollectorResearchSeed $root -RegistryRuntime:$registryRuntime }
    if ($registryRuntime) { Assert-CollectorRuntime $root }
    $manifestHash = Get-CollectorSetupHash $manifestPath
    if ($Installed) {
        $receipt = Read-CollectorSetupJson (Join-Path $root 'install-receipt.json')
        if (@($receipt.PSObject.Properties).Count -ne 3 -or
            $receipt.schema -cne 'dc-collector-install-receipt-v1' -or
            $receipt.packageManifestSha256 -cne $manifestHash -or
            -not ($receipt.installedUtc -is [DateTime] -or
                ($receipt.installedUtc -is [string] -and $receipt.installedUtc -match '^\d{4}-\d{2}-\d{2}T'))) {
            throw 'SETUP_RECEIPT_REJECTED'
        }
    }
    [pscustomobject]@{ Root = $root; Manifest = $manifest; ManifestHash = $manifestHash; Seeded = $seeded
        RegistryRuntime = $registryRuntime; ProtectedWorkspace = $protectedWorkspace }
}

<#
.SYNOPSIS
bundleを検査し、ShouldProcess承認後だけ新規workspaceへ配置する。
.DESCRIPTION
保護modeは固定native setupへ委譲し、native側の保護作成・後処理契約に従う。
このwrapperはnative処理や後続の再検査失敗を自動rollbackしない。
旧modeは固定管理fileを上書きせず逐次copyする。途中のI/Oや検証失敗では配置済みfileと
作成済みのreceiptを保持し、自動rollback・再帰削除しない。Task登録や通信開始は行わない。
.PARAMETER PackageDirectory
配置前にread-only検査する既存bundle directory。
.PARAMETER InstallDirectory
既存directoryを拒否する新規配置先。
#>
function Install-CollectorWorkspace {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string] $PackageDirectory,
        [Parameter(Mandatory)][string] $InstallDirectory)
    # 配置はx64 OS上のx64 PowerShell processに限り、別architectureの実行環境を拒否する。
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'SETUP_WINDOWS_X64_PROCESS_REQUIRED'
    }
    $bundle = Read-CollectorBundle $PackageDirectory
    $destination = Assert-CollectorSetupPath $InstallDirectory
    if (Test-Path -LiteralPath $destination) { throw 'SETUP_EXISTING_DIRECTORY_REJECTED' }
    if (-not $PSCmdlet.ShouldProcess($destination, 'Install manual metadata collector; no tasks or network')) {
        return
    }
    if ($bundle.ProtectedWorkspace) {
        # The native creator applies the protected DACL before any v4 file exists.
        & (Join-Path $bundle.Root 'DriverCrateCollectorSetup.exe') --install $destination --yes
        if ($LASTEXITCODE -ne 0) { throw 'SETUP_PROTECTED_NATIVE_INSTALL_REJECTED' }
        [void](Read-CollectorBundle $destination -Installed)
        Write-Output 'COLLECTOR_SETUP_COMPLETE mode=offline-protected tasks=0 network=0 installed_drivers=0'
        return
    }
    [void][IO.Directory]::CreateDirectory($destination)
    # Copy only fixed managed files into a new workspace; never overwrite existing content.
    foreach ($relative in @((Get-CollectorPayloadFiles -Seeded:$bundle.Seeded -RegistryRuntime:$bundle.RegistryRuntime -ProtectedWorkspace:$bundle.ProtectedWorkspace)) + @('package-manifest.json')) {
        $source = Join-Path $bundle.Root $relative
        $target = Join-Path $destination $relative
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        [IO.File]::Copy($source, $target, $false)
    }
    $copied = Read-CollectorBundle $destination
    if ($copied.ManifestHash -cne $bundle.ManifestHash) { throw 'SETUP_COPY_BINDING_REJECTED' }
    # Native collector alone creates its protected private state directory later.
    [void][IO.Directory]::CreateDirectory((Join-Path $destination 'work\state'))
    $receipt = [ordered]@{ schema = 'dc-collector-install-receipt-v1'
        packageManifestSha256 = $bundle.ManifestHash; installedUtc = [DateTimeOffset]::UtcNow.ToString('o') }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $destination 'install-receipt.json'),
        ($receipt | ConvertTo-Json -Compress), $utf8)
    [void](Read-CollectorBundle $destination -Installed)
    Write-Output 'COLLECTOR_SETUP_COMPLETE mode=manual tasks=0 network=0 installed_drivers=0'
}

<#
.SYNOPSIS
検査済みの固定管理fileだけをShouldProcess承認後に逐次削除する。
.DESCRIPTION
途中の削除失敗はStopの例外として伝播し、先行削除を元に戻さない。
config/targets.jsonとseed、work/data、workspace directoryは保持し、再帰削除しない。
seedは管理file列挙へSeededを渡さないことで削除対象から外す。
.PARAMETER InstallDirectory
削除前に配置済みbundleとして検査するworkspace directory。
#>
function Uninstall-CollectorWorkspace {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string] $InstallDirectory)
    $bundle = Read-CollectorBundle $InstallDirectory -Installed
    if (-not $PSCmdlet.ShouldProcess($bundle.Root, 'Remove managed program files; retain config and all work data')) {
        return
    }
    # Resolve a fixed list before deleting any file; never accept paths supplied by the receipt.
    $managed = @((Get-CollectorPayloadFiles -RegistryRuntime:$bundle.RegistryRuntime -ProtectedWorkspace:$bundle.ProtectedWorkspace) | Where-Object { $_ -cne 'config/targets.json' }) +
        @('package-manifest.json', 'install-receipt.json')
    foreach ($relative in $managed) { Remove-Item -LiteralPath (Join-Path $bundle.Root $relative) -Force }
    # Deliberately retain the workspace directories, configuration, and collection data.
    Write-Output 'COLLECTOR_SETUP_REMOVED config_retained=1 data_retained=1 tasks=0'
}

Export-ModuleMember -Function Get-CollectorPayloadFiles, Get-CollectorDefaultDirectory,
    Assert-CollectorSetupPath, Get-CollectorSetupHash, Assert-CollectorX64Executable,
    Read-CollectorBundle, Install-CollectorWorkspace, Uninstall-CollectorWorkspace, Get-CollectorRuntimeFiles
