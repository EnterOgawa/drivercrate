<#
.SYNOPSIS
代表取得toolの非通信preflight・公開宛先拒否試験。
.DESCRIPTION
作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
HTTPと検査器を実行せず、試験専用temporary directoryだけを変更する。
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'acquire_registry_samples.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'SCRIPT_SYNTAX' }
# 関数定義だけを読み、script本体の取得処理は起動しない。
$definitions = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] },$true)
foreach ($definition in $definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
$checks = 1
# 容量不足をfake値で拒否し、閾値ちょうどだけを受理する。実diskの状態を変更しない。
Assert-FreeSpace 'C:\fixture' 100 100
$checks++
foreach ($case in @(@{required=100;available=99},@{required=0;available=100})) {
    $rejected = $false
    try { Assert-FreeSpace 'C:\fixture' $case.required $case.available }
    catch { if ($_.Exception.Message -ne 'DISK_BUDGET') { throw }; $rejected = $true }
    if (-not $rejected) { throw 'DISK_BUDGET_ACCEPTED' }
    $checks++
}
# 固定private/予約IPv4とIPv6 literal全件で公開host拒否を確認し、一つも成功へ流さない。
foreach ($address in @('127.0.0.1','10.0.0.1','172.16.1.1','192.168.1.1','169.254.1.1',
                       '100.64.0.1','192.0.2.1','198.51.100.1','203.0.113.1','224.0.0.1',
                       '[::1]','[fc00::1]','[2001:db8::1]')) {
    $rejected = $false
    try { $null = Assert-PublicHost ([Uri]('https://' + $address + '/file.zip')) }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'PRIVATE_ADDRESS_ACCEPTED' }
    $checks++
}
# HTTP・別port・UserInfo・query・fragmentの固定不正URL全件を公開host拒否へ結合する。
foreach ($url in @('http://8.8.8.8/file.zip','https://8.8.8.8:444/file.zip',
                   'https://user@8.8.8.8/file.zip','https://8.8.8.8/file.zip?key=value',
                   'https://8.8.8.8/file.zip#anchor')) {
    $rejected = $false
    try { $null = Assert-PublicHost ([Uri]$url) } catch { $rejected = $true }
    if (-not $rejected) { throw 'URL_POLICY_ACCEPTED' }
    $checks++
}
if ((Assert-PublicHost ([Uri]'https://8.8.8.8/file.zip')) -ne '8.8.8.8') { throw 'PUBLIC_ADDRESS' }
$checks++
$registryPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'data/collector-registry/registry.json'
# 架空の公開routeと署名だけを検査し、実API・実credentialへ接続しない。
$asusItem = [pscustomobject]@{route='ASUS_PUBLIC_CDN_SESSION';format='ZIP';publicModel='ProArt X870E-CREATOR WIFI'}
$asusRecord = [pscustomobject]@{publishedSha256=('a' * 64);downloadUrl='https://dlcdnta.asus.com/pub/ASUS/mb/04LAN/test.zip'}
$asusSource = [pscustomobject]@{manufacturer='ASUS';collectionMethod='MANUAL_RESEARCH';officialPage='https://www.asus.com/jp/supportonly/proart%20x870e-creator%20wifi/helpdesk_download/'}
Assert-AsusPublicRoute $asusItem $asusRecord $asusSource
$checks++
foreach ($change in @(@{target='item';name='route';value='DIRECT'},
    @{target='item';name='publicModel';value='Other Model'},@{target='item';name='publicModel';value='credential=secret'},
    @{target='item';name='format';value='EXE'},@{target='record';name='publishedSha256';value=$null},
    @{target='record';name='downloadUrl';value='https://example.org/pub/ASUS/mb/04LAN/test.zip'},
    @{target='record';name='downloadUrl';value='https://dlcdnta.asus.com/pub/ASUS/mb/04LAN/test.zip?Signature=fixture'},
    @{target='record';name='downloadUrl';value='https://dlcdnta.asus.com/pub/ASUS/mb/04LAN/../test.zip'},
    @{target='record';name='downloadUrl';value='https://dlcdnta.asus.com/pub/ASUS/mb/04LAN/test.zip#anchor'},
    @{target='source';name='manufacturer';value='Other'},@{target='source';name='collectionMethod';value='LEGACY_ASUS_METADATA'})) {
    $values = @{item=($asusItem | ConvertTo-Json | ConvertFrom-Json);record=($asusRecord | ConvertTo-Json | ConvertFrom-Json);source=($asusSource | ConvertTo-Json | ConvertFrom-Json)}
    $values[$change.target].($change.name) = $change.value
    $rejected = $false
    try { Assert-AsusPublicRoute $values.item $values.record $values.source }
    catch { if ($_.Exception.Message -ne 'ASUS_ROUTE_POLICY') { throw }; $rejected = $true }
    if (-not $rejected) { throw 'ASUS_ROUTE_ACCEPTED' }
    $checks++
}
$response = '{"status":200,"message":"ok","result":{"expires":"200","signature":"fixture-safe_~=-","keyPairId":"PUBLICFIXTURE"}}'
$session = Convert-AsusPublicSession $response 100
if ($session.expires -cne '200') { throw 'ASUS_VALID_SESSION' }
$checks++
# 期限・型・重複/余分key・署名文字/長さ・巨大応答の固定改変全件をsession拒否へ結合する。
foreach ($body in @('not-json','[]',$response.Replace('"200"','"99"'),$response.Replace('"200"','"100"'),
    $response.Replace('"200"','"86501"'),$response.Replace('"200"','200'),$response.Replace('200,"message"','"200","message"'),
    $response.Replace('fixture-safe_~=-','unsafe&other=1'),$response.Replace('PUBLICFIXTURE','unsafe/key'),
    $response.Replace('"status":200','"status":200,"status":200'),
    $response.Replace('"expires":"200"','"expires":"200","expires":"200"'),
    $response.Replace('"status":200','"unknown":1,"status":200'),
    $response.Replace('"expires":"200"','"unknown":1,"expires":"200"'),
    $response.Replace('fixture-safe_~=-',('a' * 4097)),(' ' * 16385))) {
    $rejected = $false
    try { $null = Convert-AsusPublicSession $body 100 }
    catch { if ($_.Exception.Message -ne 'ASUS_SESSION_INVALID') { throw }; $rejected = $true }
    if (-not $rejected) { throw 'ASUS_SESSION_ACCEPTED' }
    $checks++
}
$originalPublicHost = (Get-Item -LiteralPath Function:Assert-PublicHost).ScriptBlock
try {
    # 公開DNSと公式POSTをfakeへ置換し、実際の署名応答を取得しない。
    function Assert-PublicHost([Uri]$Uri) {
        if ($Uri.AbsoluteUri -cne 'https://cdnta.asus.com/api/v1/TokenHQ') { throw 'MOCK_HOST' }
        return '8.8.8.8'
    }
    $script:mockExit = 0
    $script:mockBody = $response.Replace('"200"',('"' + ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 600) + '"'))
    function curl.exe {
        $script:mockArguments = @($args)
        $global:LASTEXITCODE = $script:mockExit
        return $script:mockBody
    }
    $request = Get-AsusPublicRequest $asusItem $asusRecord $asusSource
    if (-not $request.StartsWith($asusRecord.downloadUrl + '?model=ProArt%20X870E-CREATOR%20WIFI&Signature=') -or
        $script:mockArguments -notcontains 'POST' -or
        $script:mockArguments -notcontains 'Origin: https://www.asus.com' -or
        $script:mockArguments -notcontains $asusSource.officialPage -or
        $script:mockArguments -notcontains 'cdnta.asus.com:443:8.8.8.8') { throw 'ASUS_REQUEST_BINDING' }
    $checks++
    # curl非zeroと壊れたJSONの二失敗をfake応答で順に発生させ、各期待errorを検査する。
    foreach ($failure in @(@{exit=22;body='';reason='TRANSFER_FAILED'},
                           @{exit=0;body='not-json';reason='ASUS_SESSION_INVALID'})) {
        $script:mockExit = $failure.exit
        $script:mockBody = $failure.body
        $rejected = $false
        try { $null = Get-AsusPublicRequest $asusItem $asusRecord $asusSource }
        catch { if ($_.Exception.Message -ne $failure.reason) { throw }; $rejected = $true }
        if (-not $rejected) { throw 'ASUS_TRANSFER_ACCEPTED' }
        $checks++
    }
} finally { Set-Item -LiteralPath Function:Assert-PublicHost -Value $originalPublicHost }
$registryValue = Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json
$records = @($registryValue.records | Where-Object { $_.downloadUrl } | Select-Object -First 2)
$baseItem = [ordered]@{recordId=$records[0].id;maximumBytes=1024;format='ZIP';preDownloadConsent='NO_GATE_OBSERVED'}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('drivercrate-sample-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
# 通信へ進むregressionは必ずfailし、実際のcurlを呼ばない。
function curl.exe { throw 'NETWORK_MUST_NOT_RUN' }
try {
    $cases = @(
        @{schema='future';revision='test';items=@($baseItem)},
        @{schema='dc-sample-acquisition-plan-v1';revision='C:/private';items=@($baseItem)},
        @{schema='dc-sample-acquisition-plan-v1';revision='test';items=@()},
        @{schema='dc-sample-acquisition-plan-v1';revision='test';items=@($baseItem);extra=$true},
        @{schema='dc-sample-acquisition-plan-v1';revision='test';items=@($baseItem,$baseItem)},
        @{schema='dc-sample-acquisition-plan-v2';revision='test';items=@($baseItem)},
        @{schema='dc-sample-acquisition-plan-v2';revision='test';items=@((@{} + $baseItem + @{route='DIRECT';publicModel='ProArt X870E-CREATOR WIFI'}))}
    )
    # 固定item改変ごとに独立itemを作り、bool/範囲/format/同意/未知ID/余分fieldをplan拒否例へ追加する。
    foreach ($changes in @(@{maximumBytes=$true},@{maximumBytes=0},@{maximumBytes=67108865},
                           @{format='MSI'},@{preDownloadConsent='CONSENT_REQUIRED'},@{recordId='absent'},@{extra='unknown'})) {
        $item = @{} + $baseItem
        foreach ($name in $changes.Keys) { $item[$name] = $changes[$name] }
        $cases += @{schema='dc-sample-acquisition-plan-v1';revision='test';items=@($item)}
    }
    $budgetItems = @((@{} + $baseItem), (@{} + $baseItem))
    $budgetItems[0].maximumBytes = 67108864
    $budgetItems[1].recordId = $records[1].id
    $budgetItems[1].maximumBytes = 67108864
    $cases += @{schema='dc-sample-acquisition-plan-v1';revision='test';items=$budgetItems}
    # 全不正planを順に新規出力名へ渡し、通信到達なし・例外あり・出力未作成を各caseで確認する。
    foreach ($plan in $cases) {
        $planPath = Join-Path $temporary 'plan.json'
        [IO.File]::WriteAllText($planPath,($plan | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
        $output = Join-Path $temporary 'not-created'
        $rejected = $false
        try { & $scriptPath -Registry $registryPath -Plan $planPath -Inspector $scriptPath -OutputDirectory $output }
        catch {
            if ($_.Exception.Message -eq 'NETWORK_MUST_NOT_RUN') { throw }
            $rejected = $true
        }
        if (-not $rejected -or (Test-Path -LiteralPath $output)) { throw 'PREFLIGHT_DID_NOT_REJECT' }
        $checks++
    }
    $valid = @{schema='dc-sample-acquisition-plan-v1';revision='test';items=@($baseItem)}
    [IO.File]::WriteAllText($planPath,($valid | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & $scriptPath -Registry $registryPath -Plan $planPath -Inspector $scriptPath -OutputDirectory $temporary }
    catch { if ($_.Exception.Message -ne 'OUTPUT_EXISTS') { throw }; $rejected = $true }
    if (-not $rejected) { throw 'EXISTING_OUTPUT_ACCEPTED' }
    $checks++
    # 正しいv3も既存出力を拒否し、取得には進まない。
    $large = @{schema='dc-sample-acquisition-plan-v3';revision='large-test';maximumTotalBytes=1073741824L;
        reserveFreeBytes=2147483648L;items=@((@{} + $baseItem + @{maximumSeconds=900;route='DIRECT';publicModel=$null}))}
    [IO.File]::WriteAllText($planPath,($large | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & $scriptPath -Registry $registryPath -Plan $planPath -Inspector $scriptPath -OutputDirectory $temporary }
    catch { if ($_.Exception.Message -ne 'OUTPUT_EXISTS') { throw }; $rejected = $true }
    if (-not $rejected) { throw 'LARGE_EXISTING_OUTPUT_ACCEPTED' }
    $checks++
    $source = Get-Content -LiteralPath $scriptPath -Raw
    if (-not $source.Contains('curl.exe -q ') -or $source.Contains('--location') -or
        -not $source.Contains('--max-redirs 0')) { throw 'CURL_POLICY' }
    $checks++
    [pscustomobject]@{result='OK';checks=$checks;httpRequests=0;installerExecutions=0} | ConvertTo-Json -Compress
} finally {
    # 正確な試験用directoryに限って後始末し、workspaceとユーザーデータへ触れない。
    $resolved = [IO.Path]::GetFullPath($temporary)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
    if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\','/') -eq $parent -and
        [IO.Path]::GetFileName($resolved) -match '^drivercrate-sample-test-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
