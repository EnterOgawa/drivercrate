#requires -Version 5.1
<#
.SYNOPSIS
ADR0369/0370のproduction guardをfake scheduler/config/ACLで直接検査する有限69case。
.NOTES
作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実Task/保護store/HTTP/native processを使用しない。全caseのmutation数をJSONへ出力する。
#>
param([switch]$InputCasesOnly)
$ErrorActionPreference = 'Stop'
$taskTestSource = Join-Path $PSScriptRoot 'register_daily_index_task.ps1'
$taskTestTokens = $null
$taskTestErrors = $null
$taskTestAst = [Management.Automation.Language.Parser]::ParseFile($taskTestSource, [ref]$taskTestTokens, [ref]$taskTestErrors)
if ($taskTestErrors.Count -ne 0) { throw 'PRODUCTION_PARSE_FAILED' }
# top-levelは実行せず、実sourceの関数本体を変更せず取り込む。
foreach ($taskTestFunction in $taskTestAst.FindAll({ param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($taskTestFunction.Extent.Text))
}
function Assert-TestValue {
    <# .SYNOPSIS
    fakeの観測が固定期待値から外れた場合にcase失敗へ変換する。
    #>
    param([bool]$Condition)
    if (-not $Condition) { throw 'TEST_EXPECTATION_MISMATCH' }
}
function New-TestXml {
    <# .SYNOPSIS
    架空SIDと固定日程による最小の既存Task fixtureを作る。
    #>
    param([string]$Arguments)
    return '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task" version="1.4"><RegistrationInfo><Description>artificial</Description></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>2026-10-16T15:00:00+09:00</StartBoundary><EndBoundary>2026-10-22T15:31:00+09:00</EndBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers><Principals><Principal id="CurrentUser"><UserId>S-1-5-21-111-222-333-1001</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><ExecutionTimeLimit>PT30M</ExecutionTimeLimit><Enabled>true</Enabled></Settings><Actions Context="CurrentUser"><Exec><Command>C:\artificial\runtime\pythonw.exe</Command><Arguments>' + $Arguments + '</Arguments><WorkingDirectory>C:\artificial\repository</WorkingDirectory></Exec></Actions></Task>'
}
$taskTestRows = [Collections.Generic.List[object]]::new()
if (-not $InputCasesOnly) {
$taskTestNames = @('success', 'wrong-name', 'xml-pin', 'action-pin', 'old-config-pin', 'new-config-pin',
    'root-changed', 'running', 'disabled', 'missing', 'principal', 'logon', 'runlevel', 'multiple-action',
    'registration-trigger', 'trigger-dates', 'instances-policy', 'retry', 'execution-limit', 'proposed-command',
    'proposed-principal', 'proposed-settings', 'proposed-trigger', 'input-pin', 'input-acl', 'runtime-closure',
    'recheck-drift', 'readback-drift', 'update-unknown', 'due-too-close')
$taskTestExpected = @('', 'TASK_CUTOVER_AUTHORITY', 'TASK_PRIOR_DEFINITION_PIN', 'TASK_OLD_ACTION_REJECTED',
    'TASK_CONFIG_OR_XML_PIN', 'TASK_CONFIG_OR_XML_PIN', 'TASK_INHERITED_FIELD_CHANGED', 'TASK_NOT_READY',
    'TASK_NOT_READY', 'TASK_EXPECTED_EXISTING_REQUIRED', 'TASK_PRINCIPAL_REJECTED', 'TASK_PRINCIPAL_REJECTED',
    'TASK_PRINCIPAL_REJECTED', 'TASK_OLD_ACTION_REJECTED', 'TASK_ORIGINAL_TRIGGER_REQUIRED',
    'TASK_ORIGINAL_TRIGGER_REQUIRED', 'TASK_SETTINGS_REJECTED', 'TASK_SETTINGS_REJECTED', 'TASK_SETTINGS_REJECTED',
    'TASK_ACTION_CONFIG_BINDING', 'TASK_PROPOSED_BOUNDARY_CHANGED', 'TASK_PROPOSED_BOUNDARY_CHANGED',
    'TASK_PROPOSED_BOUNDARY_CHANGED', 'TASK_INPUT_PIN', 'TASK_INPUT_GENERAL_USER_WRITE', 'TASK_RUNTIME_PIN_MISSING',
    'TASK_PRIOR_DEFINITION_PIN', 'TASK_CUTOVER_READBACK_UNKNOWN', 'TASK_CUTOVER_UPDATE_OUTCOME_UNKNOWN', 'TASK_NEXT_RUN_TOO_CLOSE')
# 全30guard caseを独立の初期snapshotから一回ずつ実行する。
for ($taskTestNumber = 1; $taskTestNumber -le 30; $taskTestNumber++) {
    $taskOldXml = New-TestXml '-I C:\artificial\scripts\daily_index_pipeline.py run C:\artificial\control\old\config.json'
    $taskProposedXml = New-TestXml '-I C:\artificial\scripts\v2-fixture\daily_index_pipeline.py run C:\artificial\control\new\config.json'
    $taskOldConfig = [ordered]@{schema='dc-private-daily-index-config-v1'; repositoryRoot='C:\artificial\repository';
        stateRoot='D:\artificial\state'; outputRoot='C:\artificial\operations'; firstDailyLocal='2026-10-16T15:00:00+09:00';
        smokeLocal='2026-10-15T15:00:00+09:00'; pythonExe='C:\artificial\runtime\python.exe'}
    $taskOldText = $taskOldConfig | ConvertTo-Json -Compress
    $taskNewConfig = $taskOldText | ConvertFrom-Json
    $taskNewConfig.schema = 'dc-private-daily-index-config-v2'
    $taskNewConfig | Add-Member purpose 'DISTRIBUTION_ACQUISITION'
    $taskNewConfig | Add-Member legacyMetadata ([pscustomobject]@{configFile='C:\artificial\control\old\config.json';configSha256=(Get-TaskCutoverHash $taskOldText)})
    switch ($taskTestNumber) {
        7 { $taskNewConfig.outputRoot='C:\artificial\other' }
        11 { $taskOldXml=$taskOldXml.Replace('S-1-5-21-111-222-333-1001', 'S-1-5-21-111-222-333-1002') }
        12 { $taskOldXml=$taskOldXml.Replace('InteractiveToken', 'Password') }
        13 { $taskOldXml=$taskOldXml.Replace('HighestAvailable', 'LeastPrivilege') }
        14 { $taskOldXml=$taskOldXml.Replace('</Actions>', '<Exec /></Actions>') }
        15 { $taskOldXml=$taskOldXml.Replace('CalendarTrigger', 'RegistrationTrigger') }
        16 { $taskOldXml=$taskOldXml.Replace('2026-10-22', '2026-10-23') }
        17 { $taskOldXml=$taskOldXml.Replace('IgnoreNew', 'Parallel') }
        18 { $taskOldXml=$taskOldXml.Replace('</Settings>', '<RestartOnFailure><Count>1</Count><Interval>PT1M</Interval></RestartOnFailure></Settings>') }
        19 { $taskOldXml=$taskOldXml.Replace('PT30M', 'PT31M') }
        20 { $taskProposedXml=$taskProposedXml.Replace('pythonw.exe', 'other.exe') }
        21 { $taskProposedXml=$taskProposedXml.Replace('S-1-5-21-111-222-333-1001', 'S-1-5-21-111-222-333-1002') }
        22 { $taskProposedXml=$taskProposedXml.Replace('PT30M', 'PT31M') }
        23 { $taskProposedXml=$taskProposedXml.Replace('2026-10-22', '2026-10-23') }
    }
    $taskNewText = $taskNewConfig | ConvertTo-Json -Depth 5 -Compress
    $taskOldDocument = Read-TaskCutoverXml $taskOldXml
    $taskAuthority = [pscustomobject]@{schema='dc-private-daily-task-cutover-v1';taskName='DriverCrate.PrivateIndex.Daily229';
        expectedTaskXmlSha256=(Get-TaskCutoverHash $taskOldXml);expectedSddlSha256=(Get-TaskCutoverHash 'artificial-sddl');
        expectedOldActionSha256=(Get-TaskCutoverHash (Get-TaskCutoverNode $taskOldDocument '/t:Task/t:Actions').OuterXml);
        expectedOldConfigSha256=(Get-TaskCutoverHash $taskOldText);proposedConfigSha256=(Get-TaskCutoverHash $taskNewText);
        proposedXmlSha256=(Get-TaskCutoverHash $taskProposedXml);oldConfigPath='C:\artificial\control\old\config.json';
        newConfigPath='C:\artificial\control\new\config.json';oldPipelinePath='C:\artificial\scripts\daily_index_pipeline.py';
        newPipelinePath='C:\artificial\scripts\v2-fixture\daily_index_pipeline.py'}
    switch ($taskTestNumber) {
        2 { $taskAuthority.taskName='unknown' }
        3 { $taskAuthority.expectedTaskXmlSha256='0'*64 }
        4 { $taskAuthority.expectedOldActionSha256='0'*64 }
        5 { $taskAuthority.expectedOldConfigSha256='0'*64 }
        6 { $taskAuthority.proposedConfigSha256='0'*64 }
    }
    $taskContext = [pscustomobject]@{Number=$taskTestNumber;Xml=$taskOldXml;Reads=0;Updates=0;Validations=0;Starts=0;Deletes=0;Disables=0}
    $taskFakeScheduler = @{
        Read = {
            $taskContext.Reads++
            if ($taskContext.Number -eq 10) { return $null }
            $taskXml = $taskContext.Xml
            if ($taskContext.Number -eq 27 -and $taskContext.Reads -eq 2) { $taskXml=$taskXml.Replace('PT30M','PT31M') }
            if ($taskContext.Number -eq 28 -and $taskContext.Reads -eq 3) { $taskXml=$taskXml.Replace('PT30M','PT31M') }
            [pscustomobject]@{Name='DriverCrate.PrivateIndex.Daily229';Path='\DriverCrate.PrivateIndex.Daily229';Xml=$taskXml;
                Sddl='artificial-sddl';State=$(if ($taskContext.Number -eq 8) {4} else {3});
                Enabled=($taskContext.Number -ne 9);Instances=0;
                NextRunUtc=$(if ($taskContext.Number -eq 30) {[datetime]'2026-10-17T15:01:00Z'} else {[datetime]'2026-10-18T06:00:00Z'})}
        }.GetNewClosure()
        Update = {
            param($Xml, $Flags, $Sid)
            $taskContext.Updates++
            Assert-TestValue ($Flags -eq 52 -and $Sid -ceq 'S-1-5-21-111-222-333-1001')
            if ($taskContext.Number -eq 29) { throw 'ARTIFICIAL_UPDATE_EXCEPTION' }
            $taskContext.Xml=$Xml
        }.GetNewClosure()
    }
    $taskValidation = {
        param($Authority, $Configuration)
        $taskContext.Validations++
        if ($taskContext.Number -eq 24) { throw 'TASK_INPUT_PIN' }
        if ($taskContext.Number -eq 25) { throw 'TASK_INPUT_GENERAL_USER_WRITE' }
        if ($taskContext.Number -eq 26) { throw 'TASK_RUNTIME_PIN_MISSING' }
    }.GetNewClosure()
    $taskActualError = ''
    try {
        $taskResult = Invoke-TaskActionCutover $taskAuthority 'S-1-5-21-111-222-333-1001' $taskOldText $taskNewText `
            $taskProposedXml $taskFakeScheduler $taskValidation { [datetime]'2026-10-17T15:00:00Z' }
        Assert-TestValue ($taskResult -ceq 'TASK_ACTION_UPDATED_NOT_STARTED')
    } catch { $taskActualError=$_.Exception.Message }
    $taskExpectedUpdates = if ($taskTestNumber -in @(1,28,29)) {1} else {0}
    $taskOk = $taskActualError -ceq $taskTestExpected[$taskTestNumber-1] -and $taskContext.Updates -eq $taskExpectedUpdates -and
        $taskContext.Starts -eq 0 -and $taskContext.Deletes -eq 0 -and $taskContext.Disables -eq 0
    $taskRow = [pscustomobject]@{case=('C{0:00}' -f $taskTestNumber);name=$taskTestNames[$taskTestNumber-1];ok=$taskOk;
        expectedError=$taskTestExpected[$taskTestNumber-1];actualError=$taskActualError;expectedUpdate=$taskExpectedUpdates;
        update=$taskContext.Updates;read=$taskContext.Reads;inputValidation=$taskContext.Validations;start=0;delete=0;disable=0;retry=0;rollback=0;native=0;network=0}
    $taskTestRows.Add($taskRow)
    $taskRow | ConvertTo-Json -Compress
}
# productionのmode選択関数を四つの固定組合せで実行する。
for ($taskRoute = 1; $taskRoute -le 4; $taskRoute++) {
    $taskRouteActual = ''
    try { $taskRouteActual=Get-DailyTaskRegistrationMode -Register:($taskRoute -in @(2,4)) -UpdateExistingAction:($taskRoute -in @(3,4)) }
    catch { $taskRouteActual=$_.Exception.Message }
    $taskRouteExpected=@('DEFINITION','CREATE','ACTION_UPDATE','TASK_MODE_CONFLICT')[$taskRoute-1]
    $taskRow=[pscustomobject]@{case=('R{0:00}' -f $taskRoute);ok=($taskRouteActual -ceq $taskRouteExpected);actual=$taskRouteActual;expected=$taskRouteExpected;update=0;start=0;delete=0}
    $taskTestRows.Add($taskRow); $taskRow | ConvertTo-Json -Compress
}
# 実ACL取得はせず、.NETのRAM security descriptorを既存production ACL validatorへ渡す。
for ($taskAclNumber = 1; $taskAclNumber -le 4; $taskAclNumber++) {
    $taskAcl=[Security.AccessControl.DirectorySecurity]::new()
    $taskOwner=if($taskAclNumber -eq 2){'S-1-5-32-545'}else{'S-1-5-32-544'}
    $taskAcl.SetOwner([Security.Principal.SecurityIdentifier]::new($taskOwner))
    if ($taskAclNumber -in @(3,4)) {
        $taskPropagation=if($taskAclNumber -eq 4){[Security.AccessControl.PropagationFlags]::InheritOnly}else{[Security.AccessControl.PropagationFlags]::None}
        $taskRule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
            [Security.AccessControl.FileSystemRights]::WriteData,[Security.AccessControl.InheritanceFlags]::ContainerInherit,
            $taskPropagation,[Security.AccessControl.AccessControlType]::Allow)
        [void]$taskAcl.AddAccessRule($taskRule)
    }
    $taskAclError=''
    try { Assert-TaskProtectedAcl $taskAcl } catch { $taskAclError=$_.Exception.Message }
    $taskAclExpected=@('','TASK_INPUT_OWNER_NOT_PROTECTED','TASK_INPUT_GENERAL_USER_WRITE','')[$taskAclNumber-1]
    $taskRow=[pscustomobject]@{case=('A{0:00}' -f $taskAclNumber);ok=($taskAclError -ceq $taskAclExpected);expected=$taskAclExpected;actual=$taskAclError;update=0;start=0;delete=0}
    $taskTestRows.Add($taskRow);$taskRow | ConvertTo-Json -Compress
}
}
# production filesystem adapterも固定fakeの実体/hash/ACL/列挙へ接続し、callback拒否だけで代用しない。
$taskFixturePath = Join-Path ([IO.Path]::GetTempPath()) ('DriverCrate-CutoverFixture-' + [guid]::NewGuid().ToString('N') + '.json')
$taskFixtureOwned = $false
$taskFixtureCreated = $false
$taskFixtureCleaned = $false
try {
    # 一意な合成fileだけをCreateNewで所有し、既存fileを上書きしない。
    $taskFixtureStream = [IO.File]::Open($taskFixturePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $taskFixtureOwned = $true
    try {
        $taskFixtureBytes = [Text.UTF8Encoding]::new($false).GetBytes('{"synthetic":true}')
        $taskFixtureStream.Write($taskFixtureBytes, 0, $taskFixtureBytes.Length)
    } finally { $taskFixtureStream.Dispose() }
    $taskFixtureCreated = [IO.File]::Exists($taskFixturePath)
    Assert-TestValue $taskFixtureCreated
$taskFixtureRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DriverCrate\PrivateIndex229'
$taskFixtureVersion = Join-Path $taskFixtureRoot 'scripts\v2-fixture'
$taskFixtureRuntime = Join-Path $taskFixtureRoot 'runtime'
$taskFixtureApprovalPath = Join-Path $taskFixtureRoot 'control\approved-workspace.json'
$taskFixtureManifestHash = '556636e998dc3b33f8d9223aaacf9301c3c99cf5b2bbcedc569756065c18dd83'
$taskFixtureApprovalText = '{"schema":"dc-approved-daily-workspace-v1","approvalKind":"EXPLICIT_EXISTING_DAILY_WORKSPACE","taskName":"DriverCrate.PrivateIndex.Daily229","collectorManifestSha256":"' + $taskFixtureManifestHash + '","repositoryRoot":"C:\\artificial\\repository","stateRoot":"C:\\artificial\\repository\\work\\state\\driver-collector-acceptance-20261013-202"}'
$taskFixtureApprovalHash = Get-TaskCutoverHash $taskFixtureApprovalText
$taskFixtureModuleNames = @('daily_index_pipeline.py','project_collected_native_index.py','collector_registry.py','prepare_daily_index_config.py')
$taskRamAcl = [Security.AccessControl.DirectorySecurity]::new()
$taskRamAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
$taskRamAcl.SetAccessRuleProtection($true, $false)
# 各fakeはRAMだけを読み、実filesystemへのfallbackを持たせない。
function Resolve-Path { param($LiteralPath) [pscustomobject]@{Path=$LiteralPath} }
function Get-Item {
    param($LiteralPath, [switch]$Force)
    # 欠損は実storeへfallbackせず、固定recordのfake取得境界で拒否する。
    if ($script:taskInputCase -eq 15 -and $LiteralPath -ceq $taskFixtureApprovalPath) { throw 'ARTIFICIAL_APPROVAL_RECORD_MISSING' }
    if ($LiteralPath -ceq $taskFixtureApprovalPath) { $script:taskApprovalPathSeen=$true }
    $taskIsFile=$script:taskFakeFileMap.ContainsKey($LiteralPath)
    if ($script:taskInputCase -eq 23 -and $LiteralPath -ceq $taskFixtureApprovalPath) { $taskIsFile=$false }
    $taskAttributes=if($script:taskInputCase -eq 11 -and $LiteralPath -ceq (Join-Path $taskFixtureRuntime 'python313.dll')){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal}
    if ($script:taskInputCase -eq 22 -and $LiteralPath -ceq $taskFixtureApprovalPath) { $taskAttributes=[IO.FileAttributes]::ReparsePoint }
    [pscustomobject]@{PSIsContainer=(-not $taskIsFile);Length=$(if($taskIsFile){$script:taskFakeFileMap[$LiteralPath].bytes}else{0});Attributes=$taskAttributes}
}
function Get-FileHash {
    param($LiteralPath, $Algorithm)
    $taskHash=$script:taskFakeFileMap[$LiteralPath].sha256
    if (($script:taskInputCase -eq 2 -and $LiteralPath -ceq (Join-Path $taskFixtureRuntime 'python.exe')) -or
        ($script:taskInputCase -eq 3 -and $LiteralPath -ceq $taskFixturePath)) { $taskHash='f'*64 }
    # 初回検査後の同一record変更も、productionの二回目の入力検査へ実際に届ける。
    if ($LiteralPath -ceq $taskFixtureApprovalPath -and ($script:taskInputCase -eq 17 -or
        ($script:taskInputCase -eq 28 -and $taskInputContext.Validations -eq 2))) { $taskHash='f'*64 }
    [pscustomobject]@{Hash=$taskHash}
}
function Get-Acl {
    param($LiteralPath)
    if ($script:taskInputCase -eq 10 -and $LiteralPath -ceq $taskFixtureRuntime) {
        $taskUnprotected=[Security.AccessControl.DirectorySecurity]::new()
        $taskUnprotected.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        return $taskUnprotected
    }
    if (($script:taskInputCase -eq 12 -and $LiteralPath -ceq (Join-Path $taskFixtureRuntime 'python.exe')) -or
        ($script:taskInputCase -eq 21 -and $LiteralPath -ceq $taskFixtureApprovalPath) -or
        ($script:taskInputCase -eq 30 -and $script:taskApprovalPathSeen -and
            $LiteralPath -ceq (Split-Path -Parent $taskFixtureApprovalPath))) {
        $taskWritable=[Security.AccessControl.DirectorySecurity]::new()
        $taskWritable.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $taskWritable.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::WriteData,
            [Security.AccessControl.AccessControlType]::Allow))
        return $taskWritable
    }
    return $taskRamAcl
}
function Get-ChildItem {
    param($LiteralPath, [switch]$File, $Filter, [switch]$Recurse, [switch]$Force, $ErrorAction)
    if ($LiteralPath -ceq $taskFixtureVersion) {
        foreach($taskFakeName in $taskFixtureModuleNames){[pscustomobject]@{Name=$taskFakeName;FullName=(Join-Path $taskFixtureVersion $taskFakeName);PSIsContainer=$false}}
        return
    }
    if ($LiteralPath -cne $taskFixtureRuntime) { throw 'FAKE_UNEXPECTED_ENUMERATION' }
    foreach($taskFakeName in @('python.exe','pythonw.exe','python313.dll')){
        [pscustomobject]@{Name=$taskFakeName;FullName=(Join-Path $taskFixtureRuntime $taskFakeName);PSIsContainer=$false}
    }
    if ($script:taskInputCase -eq 5) {[pscustomobject]@{Name='unlisted.dll';FullName=(Join-Path $taskFixtureRuntime 'unlisted.dll');PSIsContainer=$false}}
}
$taskInputExpected=@('', 'TASK_INPUT_PIN', 'TASK_INPUT_PIN', 'TASK_INPUT_CLOSURE', 'TASK_RUNTIME_PIN_MISSING',
    'TASK_PROTECTED_VERSIONED_BIN', 'TASK_MODULE_PIN', 'TASK_ORIGINAL_INPUT_PIN', 'TASK_LEGACY_FENCE_PIN',
    'TASK_PYTHON_RUNTIME_PROTECTED_INSTALL_REQUIRED', 'TASK_INPUT_REPARSE', 'TASK_INPUT_GENERAL_USER_WRITE')
$taskInputExpected+=@('', 'TASK_WORKSPACE_APPROVAL_PIN_REQUIRED', 'ARTIFICIAL_APPROVAL_RECORD_MISSING',
    'TASK_WORKSPACE_APPROVAL_PIN_REQUIRED', 'TASK_INPUT_PIN', 'TASK_INPUT_PIN', 'TASK_WORKSPACE_APPROVAL_SIZE',
    'TASK_WORKSPACE_APPROVAL_SIZE', 'TASK_INPUT_GENERAL_USER_WRITE', 'TASK_INPUT_REPARSE', 'TASK_INPUT_PIN',
    'TASK_WORKSPACE_APPROVAL_PIN_REQUIRED', 'TASK_INPUT_CLOSURE', 'TASK_INPUT_CLOSURE', '', 'TASK_INPUT_PIN', '',
    'TASK_INPUT_GENERAL_USER_WRITE', 'TASK_WORKSPACE_APPROVAL_PIN_REQUIRED')
$taskApprovalNames=@('approval-valid-pin','approval-missing-pin','approval-record-absent','approval-wrong-path',
    'approval-hash-mismatch','approval-byte-count-mismatch','approval-empty','approval-oversize','approval-unprotected-acl',
    'approval-reparse','approval-directory','approval-path-case','approval-duplicate-pin','approval-invalid-sha',
    'approval-maximum-size','approval-final-hash-drift','approval-minimum-size','approval-control-parent-acl',
    'approval-outside-protected-root')
# 原12入力caseと新19caseは同一の有限集合から始め、実file readは架空authority fixture一件だけとする。
for ($script:taskInputCase=1; $script:taskInputCase -le 31; $script:taskInputCase++) {
    $script:taskApprovalPathSeen=$false
    $taskInputContext=[pscustomobject]@{Xml='';Updates=0;Reads=0;Validations=0;Starts=0;Deletes=0;Disables=0}
    $taskInputAuthority=[pscustomobject]@{authorityPath=$taskFixturePath;authoritySha256=('e'*64);
        registrationScriptPath=(Join-Path $taskFixtureRoot 'scripts\register_daily_index_task.ps1');
        newPipelinePath=(Join-Path $taskFixtureVersion 'daily_index_pipeline.py');oldPipelinePath=(Join-Path $taskFixtureRoot 'scripts\daily_index_pipeline.py');
        oldConfigPath=(Join-Path $taskFixtureRoot 'control\old\config.json');newConfigPath=(Join-Path $taskFixtureRoot 'control\new\config.json');
        proposedXmlPath=(Join-Path $taskFixtureRoot 'control\new\daily-task.xml');expectedOldConfigSha256=('b'*64);
        proposedConfigSha256=('c'*64);proposedXmlSha256=('d'*64);files=@()}
    $taskInputConfig=[pscustomobject]@{pythonExe=(Join-Path $taskFixtureRuntime 'python.exe');
        collectorExe=(Join-Path $taskFixtureRoot 'bin\v2-fixture\DriverCrateCollector.exe');signerExe=(Join-Path $taskFixtureRoot 'bin\v2-fixture\DriverCrateLocalIndexSigner.exe');
        ghExe='C:\Program Files\GitHub CLI\gh.exe';manifestFile=(Join-Path $taskFixtureRoot 'control\manifest.json');manifestSha256=$taskFixtureManifestHash;
        scopeFile=(Join-Path $taskFixtureRoot 'control\scope.json');scopeSha256=('a'*64);publicKeyFile=(Join-Path $taskFixtureRoot 'control\key.blob');fingerprint=('a'*64);
        collectorSha256=('a'*64);signerSha256=('a'*64);pipelineSha256=('a'*64);producerSha256=('a'*64);modulePins=[pscustomobject]@{};
        originalInputs=[pscustomobject]@{};archiveFile=(Join-Path $taskFixtureRoot 'control\archive.zip');archiveSha256=('a'*64);
        legacyMetadata=[pscustomobject]@{fenceReceiptFile=(Join-Path $taskFixtureRoot 'operations\fence.json')};
        legacyReservationFence=[pscustomobject]@{receiptSha256=('a'*64)};outputRoot=(Join-Path $taskFixtureRoot 'operations')}
    $script:taskFakeFileMap=@{}
    $taskFixturePaths=@($taskInputAuthority.registrationScriptPath,$taskFixturePath,$taskInputAuthority.newPipelinePath,$taskInputAuthority.oldPipelinePath,
        $taskInputAuthority.oldConfigPath,$taskInputAuthority.newConfigPath,$taskInputAuthority.proposedXmlPath,
        $taskInputConfig.pythonExe,(Join-Path $taskFixtureRuntime 'pythonw.exe'),(Join-Path $taskFixtureRuntime 'python313.dll'),
        $taskInputConfig.collectorExe,$taskInputConfig.signerExe,$taskInputConfig.ghExe,$taskInputConfig.manifestFile,$taskInputConfig.scopeFile,
        $taskInputConfig.publicKeyFile,$taskInputConfig.archiveFile,$taskInputConfig.legacyMetadata.fenceReceiptFile,$taskFixtureApprovalPath)
    foreach($taskFakeName in $taskFixtureModuleNames){
        $taskInputConfig.modulePins | Add-Member $taskFakeName ('a'*64)
        $taskFixturePaths+=Join-Path $taskFixtureVersion $taskFakeName
    }
    foreach($taskFakeName in @('release','review','script')){
        $taskFakePath=Join-Path $taskFixtureRoot ('control\' + $taskFakeName + '.json')
        $taskInputConfig.originalInputs | Add-Member $taskFakeName ([pscustomobject]@{file=$taskFakePath;sha256=('a'*64)})
        $taskFixturePaths+=$taskFakePath
    }
    foreach($taskFakeName in @('receipt','rawManifest','gzip','envelope')){
        $taskFakePath=Join-Path $taskFixtureRoot ('operations\' + $taskFakeName + '.json')
        $taskInputConfig.legacyMetadata | Add-Member ($taskFakeName+'File') $taskFakePath
        $taskInputConfig.legacyMetadata | Add-Member ($taskFakeName+'Sha256') ('a'*64)
        $taskFixturePaths+=$taskFakePath
    }
    foreach($taskFakePath in $taskFixturePaths){$script:taskFakeFileMap[$taskFakePath]=[pscustomobject]@{path=$taskFakePath;bytes=10;sha256=('a'*64)}}
    $script:taskFakeFileMap[$taskFixturePath].sha256='e'*64
    $script:taskFakeFileMap[$taskInputAuthority.oldConfigPath].sha256='b'*64
    $script:taskFakeFileMap[$taskInputAuthority.newConfigPath].sha256='c'*64
    $script:taskFakeFileMap[$taskInputAuthority.proposedXmlPath].sha256='d'*64
    $script:taskFakeFileMap[$taskInputConfig.manifestFile].sha256=$taskFixtureManifestHash
    # good bundleと長さ境界にも人工原byteのhashを結び、保護位置にはfileを作らない。
    # 1byte正例はpin下限だけの確認であり、record schemaの受入には数えない。
    $taskApprovalCaseText=switch($script:taskInputCase){
        19 {''}
        20 {$taskFixtureApprovalText.PadRight(65537, ' ')}
        27 {$taskFixtureApprovalText.PadRight(65536, ' ')}
        29 {'0'}
        default {$taskFixtureApprovalText}
    }
    $taskApprovalCaseBytes=[Text.Encoding]::UTF8.GetBytes($taskApprovalCaseText)
    $taskApprovalHasher=[Security.Cryptography.SHA256]::Create()
    try {$taskApprovalCaseHash=([BitConverter]::ToString($taskApprovalHasher.ComputeHash($taskApprovalCaseBytes))).Replace('-','').ToLowerInvariant()}
    finally {$taskApprovalHasher.Dispose()}
    $script:taskFakeFileMap[$taskFixtureApprovalPath].bytes=$taskApprovalCaseBytes.Length
    $script:taskFakeFileMap[$taskFixtureApprovalPath].sha256=$taskApprovalCaseHash
    Assert-TestValue ($script:taskInputCase -in @(19,20,27,29) -or $taskApprovalCaseHash -ceq $taskFixtureApprovalHash)
    switch($script:taskInputCase){
        4 {[void]$script:taskFakeFileMap.Remove($taskInputConfig.ghExe)}
        6 {$taskInputConfig.collectorExe=Join-Path $taskFixtureRoot 'bin\wrong\DriverCrateCollector.exe'}
        7 {$taskInputConfig.modulePins.'prepare_daily_index_config.py'='0'*64}
        8 {$taskInputConfig.originalInputs.review.sha256='0'*64}
        9 {$taskInputConfig.legacyReservationFence.receiptSha256='0'*64}
        14 {[void]$script:taskFakeFileMap.Remove($taskFixtureApprovalPath)}
        16 {
            $taskWrongApproval=$script:taskFakeFileMap[$taskFixtureApprovalPath]
            [void]$script:taskFakeFileMap.Remove($taskFixtureApprovalPath)
            $taskWrongApproval.path=Join-Path $taskFixtureRoot 'control\other-approved-workspace.json'
            $script:taskFakeFileMap[$taskWrongApproval.path]=$taskWrongApproval
        }
        19 {$script:taskFakeFileMap[$taskFixtureApprovalPath].bytes=0}
        20 {$script:taskFakeFileMap[$taskFixtureApprovalPath].bytes=65537}
        24 {$script:taskFakeFileMap[$taskFixtureApprovalPath].path=$taskFixtureApprovalPath.ToUpperInvariant()}
        26 {$script:taskFakeFileMap[$taskFixtureApprovalPath].sha256='INVALID'}
        27 {$script:taskFakeFileMap[$taskFixtureApprovalPath].bytes=65536}
        29 {$script:taskFakeFileMap[$taskFixtureApprovalPath].bytes=1}
        31 {
            $taskWrongApproval=$script:taskFakeFileMap[$taskFixtureApprovalPath]
            [void]$script:taskFakeFileMap.Remove($taskFixtureApprovalPath)
            $taskWrongApproval.path='C:\artificial\control\approved-workspace.json'
            $script:taskFakeFileMap[$taskWrongApproval.path]=$taskWrongApproval
        }
    }
    # 新19caseは入力validatorを省略せず、production切替guardと同じ二回の再検査へ接続する。
    if ($script:taskInputCase -ge 13) {
        $taskInputConfig | Add-Member schema 'dc-private-daily-index-config-v2'
        $taskInputConfig | Add-Member purpose 'DISTRIBUTION_ACQUISITION'
        $taskInputConfig | Add-Member repositoryRoot 'C:\artificial\repository'
        $taskInputConfig | Add-Member stateRoot 'C:\artificial\repository\work\state\driver-collector-acceptance-20261013-202'
        $taskInputConfig | Add-Member firstDailyLocal '2026-10-16T15:00:00+09:00'
        $taskInputConfig | Add-Member smokeLocal '2026-10-15T15:00:00+09:00'
        $taskOldInputConfig=($taskInputConfig | ConvertTo-Json -Depth 8 -Compress) | ConvertFrom-Json
        $taskOldInputConfig.schema='dc-private-daily-index-config-v1'
        $taskOldInputText=$taskOldInputConfig | ConvertTo-Json -Depth 8 -Compress
        $taskInputConfig.legacyMetadata | Add-Member configFile $taskInputAuthority.oldConfigPath
        $taskInputConfig.legacyMetadata | Add-Member configSha256 (Get-TaskCutoverHash $taskOldInputText)
        $taskNewInputText=$taskInputConfig | ConvertTo-Json -Depth 8 -Compress
        $taskInputAuthority.expectedOldConfigSha256=Get-TaskCutoverHash $taskOldInputText
        $taskInputAuthority.proposedConfigSha256=Get-TaskCutoverHash $taskNewInputText
        $taskOldInputXml=(New-TestXml ('-I ' + (ConvertTo-TaskCutoverArgument $taskInputAuthority.oldPipelinePath) + ' run ' +
            (ConvertTo-TaskCutoverArgument $taskInputAuthority.oldConfigPath))).Replace('C:\artificial\runtime\pythonw.exe',(Join-Path $taskFixtureRuntime 'pythonw.exe'))
        $taskNewInputXml=(New-TestXml ('-I ' + (ConvertTo-TaskCutoverArgument $taskInputAuthority.newPipelinePath) + ' run ' +
            (ConvertTo-TaskCutoverArgument $taskInputAuthority.newConfigPath))).Replace('C:\artificial\runtime\pythonw.exe',(Join-Path $taskFixtureRuntime 'pythonw.exe'))
        $taskInputAuthority.proposedXmlSha256=Get-TaskCutoverHash $taskNewInputXml
        $taskInputAuthority | Add-Member schema 'dc-private-daily-task-cutover-v1'
        $taskInputAuthority | Add-Member taskName 'DriverCrate.PrivateIndex.Daily229'
        $taskInputAuthority | Add-Member expectedTaskXmlSha256 (Get-TaskCutoverHash $taskOldInputXml)
        $taskInputAuthority | Add-Member expectedSddlSha256 (Get-TaskCutoverHash 'artificial-sddl')
        $taskInputAuthority | Add-Member expectedOldActionSha256 (Get-TaskCutoverHash (Get-TaskCutoverNode (Read-TaskCutoverXml $taskOldInputXml) '/t:Task/t:Actions').OuterXml)
        $script:taskFakeFileMap[$taskInputAuthority.oldConfigPath].sha256=$taskInputAuthority.expectedOldConfigSha256
        $script:taskFakeFileMap[$taskInputAuthority.newConfigPath].sha256=$taskInputAuthority.proposedConfigSha256
        $script:taskFakeFileMap[$taskInputAuthority.proposedXmlPath].sha256=$taskInputAuthority.proposedXmlSha256
        $taskInputContext.Xml=$taskOldInputXml
        $taskInputScheduler=@{
            Read={
                $taskInputContext.Reads++
                [pscustomobject]@{Name='DriverCrate.PrivateIndex.Daily229';Path='\DriverCrate.PrivateIndex.Daily229';
                    Xml=$taskInputContext.Xml;Sddl='artificial-sddl';State=3;Enabled=$true;Instances=0;
                    NextRunUtc=[datetime]'2026-10-18T06:00:00Z'}
            }.GetNewClosure()
            Update={
                param($Xml,$Flags,$Sid)
                $taskInputContext.Updates++
                Assert-TestValue ($Flags -eq 52 -and $Sid -ceq 'S-1-5-21-111-222-333-1001')
                $taskInputContext.Xml=$Xml
            }.GetNewClosure()
        }
        $taskInputValidation={
            param($Authority,$Configuration)
            $taskInputContext.Validations++
            Assert-TaskCutoverInputs $Authority $Configuration
        }.GetNewClosure()
    }
    $taskInputAuthority.files=@($script:taskFakeFileMap.Values | Where-Object path -CNE $taskFixturePath)
    if ($script:taskInputCase -eq 18) {
        $taskInputAuthority.files=@($taskInputAuthority.files | ForEach-Object {
            if ($_.path -ceq $taskFixtureApprovalPath) {[pscustomobject]@{path=$_.path;bytes=($_.bytes+1);sha256=$_.sha256}} else {$_}
        })
    }
    if ($script:taskInputCase -eq 25) {$taskInputAuthority.files+=$script:taskFakeFileMap[$taskFixtureApprovalPath]}
    $taskInputError=''
    try {
        if ($script:taskInputCase -ge 13) {
            $taskInputResult=Invoke-TaskActionCutover $taskInputAuthority 'S-1-5-21-111-222-333-1001' $taskOldInputText $taskNewInputText `
                $taskNewInputXml $taskInputScheduler $taskInputValidation { [datetime]'2026-10-17T15:00:00Z' }
            Assert-TestValue ($taskInputResult -ceq 'TASK_ACTION_UPDATED_NOT_STARTED')
        } else {Assert-TaskCutoverInputs $taskInputAuthority $taskInputConfig}
    } catch {$taskInputError=$_.Exception.Message}
    $taskRow=[pscustomobject]@{case=('P{0:00}' -f $script:taskInputCase);ok=($taskInputError -ceq $taskInputExpected[$script:taskInputCase-1]);
        expected=$taskInputExpected[$script:taskInputCase-1];actual=$taskInputError;update=0;start=0;delete=0;disable=0;native=0;network=0}
    if ($script:taskInputCase -ge 13) {
        $taskExpectedInputUpdates=if($script:taskInputCase -in @(13,27,29)){1}else{0}
        $taskRow.update=$taskInputContext.Updates
        $taskRow.ok=$taskRow.ok -and $taskInputContext.Updates -eq $taskExpectedInputUpdates -and
            $taskInputContext.Starts -eq 0 -and $taskInputContext.Deletes -eq 0 -and $taskInputContext.Disables -eq 0
        $taskRow | Add-Member name $taskApprovalNames[$script:taskInputCase-13]
        $taskRow | Add-Member expectedUpdate $taskExpectedInputUpdates
        $taskRow | Add-Member read $taskInputContext.Reads
        $taskRow | Add-Member inputValidation $taskInputContext.Validations
        $taskRow | Add-Member retry 0
        $taskRow | Add-Member rollback 0
        $taskRow | Add-Member recordReviewedBytes $taskApprovalCaseBytes.Length
        $taskRow | Add-Member recordReviewedSha256 $taskApprovalCaseHash
    }
    $taskTestRows.Add($taskRow);$taskRow|ConvertTo-Json -Compress
}
} finally {
    # fakeのGet-Item等を使わず、CreateNewに成功したexact fileだけを実APIで削除する。
    if ($taskFixtureOwned) {
        [IO.File]::Delete($taskFixturePath)
        $taskFixtureCleaned = -not [IO.File]::Exists($taskFixturePath)
        Assert-TestValue $taskFixtureCleaned
    }
}
$taskFailures=@($taskTestRows | Where-Object { -not $_.ok }).Count
[pscustomobject]@{cases=$taskTestRows.Count;failed=$taskFailures;realTaskOperations=0;native=0;network=0;fixtureCreated=$taskFixtureCreated;fixtureCleaned=$taskFixtureCleaned}|ConvertTo-Json -Compress
$taskExpectedCaseCount=if($InputCasesOnly){31}else{69}
if ($taskTestRows.Count -ne $taskExpectedCaseCount -or $taskFailures -ne 0) { exit 1 }
