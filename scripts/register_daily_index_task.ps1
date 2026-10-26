<#
.SYNOPSIS
ADR0344/0369の現在ユーザーTaskを生成し、手動管理用の登録を行う。
.NOTES
作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
既定は定義生成のみ。既存Action切替は別switchとレビュー済みauthorityを必須にする。
password保存、Task開始、日程延長、global policy変更は行わない。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Python,
    [Parameter(Mandatory = $true)][string]$NewXml,
    [switch]$Smoke,
    [switch]$Register,
    [switch]$UpdateExistingAction,
    [string]$CutoverAuthority,
    [string]$CutoverAuthoritySha256
)
$ErrorActionPreference = 'Stop'
function ConvertTo-TaskRegistrationXml {
    param([Parameter(Mandatory = $true)][string]$XmlText)
    # RegisterTask receives a Unicode BSTR, not the persisted UTF-8 byte stream.
    # Remove only its leading byte-encoding declaration and preserve the reviewed XML body.
    return [regex]::Replace($XmlText, '\A<\?xml\s[^?]*\?>', '',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

# 渡されたACL snapshotでownerをSYSTEM/Administrators/TrustedInstallerに限定する。
# 非INHERIT_ONLYのAllow ACEが対象write maskを許可SID外へ与える場合は拒否し、Denyでは相殺しない。
# ACLや権限を変更せず、読取り時点のこのpolicy検査を完全な実効権限保証とはしない。
function Assert-TaskProtectedAcl {
    param([Parameter(Mandatory = $true)]$Acl, [switch]$Ancestor)
    $taskAllowed = @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $taskOwner = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($taskOwner -notin $taskAllowed) { throw 'TASK_INPUT_OWNER_NOT_PROTECTED' }
    # Ancestor create-file/create-directory alone cannot replace an existing protected child.
    # The actual file and its code-loading directory also forbid content creation/writes.
    $taskWriteMask = if ($Ancestor) { [int64]0x000D0040 } else { [int64]0x000D0156 }
    $taskAccessRules = $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($taskAce in $taskAccessRules) {
        if ($taskAce.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            ($taskAce.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) {
            $taskSid = $taskAce.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if (([int64]$taskAce.FileSystemRights -band $taskWriteMask) -ne 0 -and $taskSid -notin $taskAllowed) {
                throw 'TASK_INPUT_GENERAL_USER_WRITE'
            }
        }
    }
}

function Get-DailyTaskRegistrationMode {
    <# .SYNOPSIS
    暗黙の既存更新とmode混用を拒否し、定義生成・新規登録・明示更新を区別する。
    #>
    param([switch]$Register, [switch]$UpdateExistingAction, [switch]$Smoke)
    # Smokeは元の日次Task切替へ流用しない。
    if ($UpdateExistingAction -and ($Register -or $Smoke)) { throw 'TASK_MODE_CONFLICT' }
    if ($UpdateExistingAction) { return 'ACTION_UPDATE' }
    if ($Register) { return 'CREATE' }
    return 'DEFINITION'
}

function Get-TaskCutoverHash {
    <# .SYNOPSIS
    改行やXML宣言を補正せず、渡された文字列のUTF-8 SHA-256を返す。
    #>
    param([Parameter(Mandatory = $true)][string]$Text)
    $taskHasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($taskHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    } finally { $taskHasher.Dispose() }
}

function Read-TaskCutoverXml {
    <# .SYNOPSIS
    有限長のTask XMLを外部entityとDTDなしで解析し、空白だけを正規化する。
    #>
    param([Parameter(Mandatory = $true)][string]$Text)
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 65536) { throw 'TASK_XML_LIMIT' }
    $taskReaderSettings = [Xml.XmlReaderSettings]::new()
    $taskReaderSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $taskReaderSettings.XmlResolver = $null
    $taskReaderSettings.IgnoreWhitespace = $true
    $taskReaderSettings.MaxCharactersInDocument = 65536
    $taskStringReader = [IO.StringReader]::new($Text)
    $taskReader = [Xml.XmlReader]::Create($taskStringReader, $taskReaderSettings)
    try {
        $taskDocument = [Xml.XmlDocument]::new()
        $taskDocument.XmlResolver = $null
        $taskDocument.Load($taskReader)
        if ($taskDocument.DocumentElement.LocalName -cne 'Task' -or
            $taskDocument.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/windows/2004/02/mit/task') {
            throw 'TASK_XML_NAMESPACE'
        }
        return ,$taskDocument
    } finally { $taskReader.Dispose(); $taskStringReader.Dispose() }
}

function Get-TaskCutoverNode {
    <# .SYNOPSIS
    Task namespaceの一意な要素だけを取得し、欠落や重複を拒否する。
    #>
    param($Document, [string]$Path)
    $taskNamespaces = [Xml.XmlNamespaceManager]::new($Document.NameTable)
    $taskNamespaces.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $taskNodes = $Document.SelectNodes($Path, $taskNamespaces)
    if ($taskNodes.Count -ne 1) { throw 'TASK_XML_NODE_COUNT' }
    return $taskNodes.Item(0)
}

function Get-TaskCutoverNonAction {
    <# .SYNOPSIS
    読戻し比較用にActionsだけを除いた定義を返し、元documentを変更しない。
    #>
    param($Document)
    $taskClone = $Document.CloneNode($true)
    $taskActions = Get-TaskCutoverNode $taskClone '/t:Task/t:Actions'
    [void]$taskActions.ParentNode.RemoveChild($taskActions)
    return $taskClone.OuterXml
}

function ConvertTo-TaskCutoverArgument {
    <# .SYNOPSIS
    quoteと制御文字を持たない固定file pathをWindows command argumentへ変換する。
    #>
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value) -or $Value -match '["\x00-\x1f]' -or $Value.EndsWith('\')) {
        throw 'TASK_ACTION_ARGUMENT'
    }
    if ($Value -match '\s') { return '"' + $Value + '"' }
    return $Value
}

function Assert-TaskCutoverSnapshot {
    <# .SYNOPSIS
    現在定義をレビュー済み旧XML/Action/SDDLと元日程・現在ユーザーへ結合する。
    .NOTES
    この観測はロックやCASではない。NextRunUtcの観測後に時刻やTaskが変わり得る。
    #>
    param($Snapshot, $Authority, [string]$CurrentSid, [datetime]$NowUtc)
    if ($null -eq $Snapshot) { throw 'TASK_EXPECTED_EXISTING_REQUIRED' }
    if ($Snapshot.Name -cne 'DriverCrate.PrivateIndex.Daily229' -or $Snapshot.Path -cne '\DriverCrate.PrivateIndex.Daily229') {
        throw 'TASK_IDENTITY_MISMATCH'
    }
    if ($Snapshot.State -ne 3 -or -not $Snapshot.Enabled -or $Snapshot.Instances -ne 0) { throw 'TASK_NOT_READY' }
    if ($Snapshot.NextRunUtc -le $NowUtc.AddSeconds(120)) { throw 'TASK_NEXT_RUN_TOO_CLOSE' }
    if ((Get-TaskCutoverHash $Snapshot.Xml) -cne $Authority.expectedTaskXmlSha256 -or
        (Get-TaskCutoverHash $Snapshot.Sddl) -cne $Authority.expectedSddlSha256) { throw 'TASK_PRIOR_DEFINITION_PIN' }
    $taskDocument = Read-TaskCutoverXml $Snapshot.Xml
    $taskPrincipalNode = Get-TaskCutoverNode $taskDocument '/t:Task/t:Principals/t:Principal'
    if ($taskPrincipalNode.GetAttribute('id') -cne 'CurrentUser' -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Principals/t:Principal/t:UserId').InnerText -cne $CurrentSid -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Principals/t:Principal/t:LogonType').InnerText -cne 'InteractiveToken' -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Principals/t:Principal/t:RunLevel').InnerText -cne 'HighestAvailable' -or
        $taskPrincipalNode.ChildNodes.Count -ne 3) { throw 'TASK_PRINCIPAL_REJECTED' }
    $taskTriggers = Get-TaskCutoverNode $taskDocument '/t:Task/t:Triggers'
    $taskTriggerEnabled = @($taskTriggers.FirstChild.ChildNodes | Where-Object LocalName -CEQ 'Enabled')
    $taskTriggerChildren = 4
    $taskEnabledValid = $taskTriggerEnabled.Count -eq 1 -and $taskTriggerEnabled[0].InnerText -ceq 'true' -and
        $taskTriggerEnabled[0].NamespaceURI -ceq 'http://schemas.microsoft.com/windows/2004/02/mit/task'
    # 元の単一日次trigger以外は、registration triggerを含めて全て拒否する。
    if ($taskTriggers.ChildNodes.Count -ne 1 -or $taskTriggers.FirstChild.LocalName -cne 'CalendarTrigger' -or
        $taskTriggers.FirstChild.ChildNodes.Count -ne $taskTriggerChildren -or -not $taskEnabledValid -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Triggers/t:CalendarTrigger/t:StartBoundary').InnerText -cne '2026-10-16T15:00:00+09:00' -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Triggers/t:CalendarTrigger/t:EndBoundary').InnerText -cne '2026-10-22T15:31:00+09:00' -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Triggers/t:CalendarTrigger/t:ScheduleByDay/t:DaysInterval').InnerText -cne '1') {
        throw 'TASK_ORIGINAL_TRIGGER_REQUIRED'
    }
    $taskSettings = Get-TaskCutoverNode $taskDocument '/t:Task/t:Settings'
    $taskSettingsEnabled = 'true'
    if ((Get-TaskCutoverNode $taskDocument '/t:Task/t:Settings/t:MultipleInstancesPolicy').InnerText -cne 'IgnoreNew' -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Settings/t:ExecutionTimeLimit').InnerText -cne 'PT30M' -or
        (Get-TaskCutoverNode $taskDocument '/t:Task/t:Settings/t:Enabled').InnerText -cne $taskSettingsEnabled -or
        @($taskSettings.ChildNodes | Where-Object LocalName -EQ 'RestartOnFailure').Count -ne 0) { throw 'TASK_SETTINGS_REJECTED' }
    $taskActions = Get-TaskCutoverNode $taskDocument '/t:Task/t:Actions'
    if ($taskActions.GetAttribute('Context') -cne 'CurrentUser' -or $taskActions.ChildNodes.Count -ne 1 -or
        $taskActions.FirstChild.LocalName -cne 'Exec' -or
        (Get-TaskCutoverHash $taskActions.OuterXml) -cne $Authority.expectedOldActionSha256) { throw 'TASK_OLD_ACTION_REJECTED' }
    return ,$taskDocument
}

function Invoke-TaskActionCutover {
    <# .SYNOPSIS
    productionとfakeで共用するAction限定guardを実行し、一回の更新後に読戻す。
    .NOTES
    Scheduler.Read/UpdateとValidateInputsは同期注入境界。拒否前は更新0、更新例外と読戻し
    不一致は結果不明として止める。自動retry/rollback/start/deleteは呼び出さない。
    #>
    param($Authority, [string]$CurrentSid, [string]$OldConfigText, [string]$NewConfigText,
        [string]$ProposedXml, $Scheduler, [scriptblock]$ValidateInputs, [scriptblock]$Clock)
    if ($Authority.schema -cne 'dc-private-daily-task-cutover-v1' -or
        $Authority.taskName -cne 'DriverCrate.PrivateIndex.Daily229' -or
        $CurrentSid -cnotmatch '^S-1-5-21-(?:[0-9]+-){2}[0-9]+-[0-9]+$') { throw 'TASK_CUTOVER_AUTHORITY' }
    if ((Get-TaskCutoverHash $OldConfigText) -cne $Authority.expectedOldConfigSha256 -or
        (Get-TaskCutoverHash $NewConfigText) -cne $Authority.proposedConfigSha256 -or
        (Get-TaskCutoverHash $ProposedXml) -cne $Authority.proposedXmlSha256) { throw 'TASK_CONFIG_OR_XML_PIN' }
    $taskOldConfig = $OldConfigText | ConvertFrom-Json
    $taskNewConfig = $NewConfigText | ConvertFrom-Json
    if ($taskOldConfig.schema -cne 'dc-private-daily-index-config-v1' -or
        $taskNewConfig.schema -cne 'dc-private-daily-index-config-v2' -or
        $taskNewConfig.purpose -cne 'DISTRIBUTION_ACQUISITION' -or
        $taskNewConfig.legacyMetadata.configFile -cne $Authority.oldConfigPath -or
        $taskNewConfig.legacyMetadata.configSha256 -cne $Authority.expectedOldConfigSha256) { throw 'TASK_CONFIG_INHERITANCE' }
    # 同一日の再実行や別state/outputへ切り替えるauthorityを受理しない。
    foreach ($taskField in @('repositoryRoot', 'stateRoot', 'outputRoot', 'firstDailyLocal', 'smokeLocal',
        'pythonExe', 'manifestFile', 'manifestSha256', 'publicKeyFile', 'fingerprint', 'ghExe')) {
        if ($taskNewConfig.$taskField -cne $taskOldConfig.$taskField) { throw 'TASK_INHERITED_FIELD_CHANGED' }
    }
    if ($taskNewConfig.firstDailyLocal -cne '2026-10-16T15:00:00+09:00') { throw 'TASK_CONFIG_SCHEDULE' }
    & $ValidateInputs $Authority $taskNewConfig
    $taskBefore = & $Scheduler.Read
    $taskOldDocument = Assert-TaskCutoverSnapshot $taskBefore $Authority $CurrentSid (& $Clock)
    $taskProposed = Read-TaskCutoverXml $ProposedXml
    # 新生成XMLの説明等は採用せず、Principal/Triggers/Settingsだけを旧定義と比較する。
    foreach ($taskSection in @('Principals', 'Triggers', 'Settings')) {
        if ((Get-TaskCutoverNode $taskOldDocument ('/t:Task/t:' + $taskSection)).OuterXml -cne
            (Get-TaskCutoverNode $taskProposed ('/t:Task/t:' + $taskSection)).OuterXml) { throw 'TASK_PROPOSED_BOUNDARY_CHANGED' }
    }
    $taskNewActions = Get-TaskCutoverNode $taskProposed '/t:Task/t:Actions'
    $taskOldActions = Get-TaskCutoverNode $taskOldDocument '/t:Task/t:Actions'
    if ($taskNewActions.GetAttribute('Context') -cne 'CurrentUser' -or $taskNewActions.ChildNodes.Count -ne 1 -or
        $taskNewActions.FirstChild.LocalName -cne 'Exec' -or $taskNewActions.FirstChild.ChildNodes.Count -ne 3) { throw 'TASK_PROPOSED_ACTION_REJECTED' }
    $taskPythonw = Join-Path (Split-Path -Parent $taskNewConfig.pythonExe) 'pythonw.exe'
    $taskExpectedArguments = '-I ' + (ConvertTo-TaskCutoverArgument $Authority.newPipelinePath) + ' run ' +
        (ConvertTo-TaskCutoverArgument $Authority.newConfigPath)
    $taskOldExpectedArguments = '-I ' + (ConvertTo-TaskCutoverArgument $Authority.oldPipelinePath) + ' run ' +
        (ConvertTo-TaskCutoverArgument $Authority.oldConfigPath)
    if ((Get-TaskCutoverNode $taskProposed '/t:Task/t:Actions/t:Exec/t:Command').InnerText -cne $taskPythonw -or
        (Get-TaskCutoverNode $taskProposed '/t:Task/t:Actions/t:Exec/t:Arguments').InnerText -cne $taskExpectedArguments -or
        (Get-TaskCutoverNode $taskProposed '/t:Task/t:Actions/t:Exec/t:WorkingDirectory').InnerText -cne $taskNewConfig.repositoryRoot -or
        (Get-TaskCutoverNode $taskOldDocument '/t:Task/t:Actions/t:Exec/t:Command').InnerText -cne $taskPythonw -or
        (Get-TaskCutoverNode $taskOldDocument '/t:Task/t:Actions/t:Exec/t:Arguments').InnerText -cne $taskOldExpectedArguments -or
        (Get-TaskCutoverNode $taskOldDocument '/t:Task/t:Actions/t:Exec/t:WorkingDirectory').InnerText -cne $taskOldConfig.repositoryRoot) {
        throw 'TASK_ACTION_CONFIG_BINDING'
    }
    $taskReplacement = $taskOldDocument.ImportNode($taskNewActions, $true)
    [void]$taskOldActions.ParentNode.ReplaceChild($taskReplacement, $taskOldActions)
    # 入力と現在Taskを直前にもう一度読み、観測できたdriftだけを更新前に拒否する。
    & $ValidateInputs $Authority $taskNewConfig
    $taskRecheck = & $Scheduler.Read
    [void](Assert-TaskCutoverSnapshot $taskRecheck $Authority $CurrentSid (& $Clock))
    if ($taskRecheck.NextRunUtc -ne $taskBefore.NextRunUtc) { throw 'TASK_RECHECK_DRIFT' }
    try {
        # TASK_UPDATE|DONT_ADD_PRINCIPAL_ACE|IGNORE_REGISTRATION_TRIGGERS。CREATE_OR_UPDATEは使わない。
        & $Scheduler.Update $taskOldDocument.OuterXml 52 $CurrentSid
    } catch { throw 'TASK_CUTOVER_UPDATE_OUTCOME_UNKNOWN' }
    try {
        $taskAfter = & $Scheduler.Read
        $taskAfterDocument = Read-TaskCutoverXml $taskAfter.Xml
        if ($taskAfter.Name -cne $taskBefore.Name -or $taskAfter.Path -cne $taskBefore.Path -or
            $taskAfter.Sddl -cne $taskBefore.Sddl -or -not $taskAfter.Enabled -or
            $taskAfter.State -ne 3 -or $taskAfter.Instances -ne 0 -or $taskAfter.NextRunUtc -ne $taskBefore.NextRunUtc -or
            (Get-TaskCutoverNonAction $taskAfterDocument) -cne (Get-TaskCutoverNonAction $taskOldDocument) -or
            (Get-TaskCutoverNode $taskAfterDocument '/t:Task/t:Actions').OuterXml -cne $taskNewActions.OuterXml) {
            throw 'TASK_READBACK_DRIFT'
        }
    } catch { throw 'TASK_CUTOVER_READBACK_UNKNOWN' }
    return 'TASK_ACTION_UPDATED_NOT_STARTED'
}

function Assert-TaskCutoverProtectedPath {
    <# .SYNOPSIS
    既存ACL規則を再利用し、対象と全ancestorのreparse/owner/write権限を検査する。
    #>
    param([string]$Path)
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or
        $Path -match '\.\.|["\x00-\x1f]' -or $Path.Substring(2).Contains(':')) { throw 'TASK_INPUT_PATH' }
    $taskResolved = (Resolve-Path -LiteralPath $Path).Path
    $taskDepth = 0
    # 元のfile、直属directory、上位ancestorを順に検査し、drive rootで終える。
    while ($taskResolved) {
        $taskItem = Get-Item -LiteralPath $taskResolved -Force
        if (($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'TASK_INPUT_REPARSE' }
        Assert-TaskProtectedAcl -Acl (Get-Acl -LiteralPath $taskResolved) -Ancestor:($taskDepth -ge 2)
        $taskParent = Split-Path -Parent $taskResolved
        if ($taskParent -eq $taskResolved) { break }
        $taskResolved = $taskParent
        $taskDepth++
    }
}

function Read-TaskCutoverText {
    <# .SYNOPSIS
    ACL検査後に有限のUTF-8入力を読み、期待hashへ結合する。
    #>
    param([string]$Path, [string]$Sha256)
    Assert-TaskCutoverProtectedPath $Path
    $taskItem = Get-Item -LiteralPath $Path -Force
    if ($taskItem.PSIsContainer -or $taskItem.Length -gt 65536 -or $Sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) { throw 'TASK_INPUT_PIN' }
    return Read-TaskCutoverUtf8 $Path
}

function Read-TaskCutoverUtf8 {
    <# .SYNOPSIS
    検査後のUTF-8読取りI/O境界。testはこの境界だけを人工fileへ写像する。
    #>
    param([string]$Path)
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
}

function Assert-TaskCutoverInputs {
    <# .SYNOPSIS
    レビュー済み全file pin、固定承認record、四module、新bin、全Python runtimeの閉包と保護ACLを検査する。
    .NOTES
    承認recordのJSON/schema/configの意味は解釈せず、同じ原byteのレビュー済みbinding proofを別途必要とする。
    読取り時点の検査であり、各OS I/Oのhard deadlineや実行時の完全な不変性は保証しない。
    #>
    param($Authority, $Configuration)
    # レビュー済みauthority自身も再照合し、初回読取り後の変更を更新直前に拒否する。
    [void](Read-TaskCutoverText $Authority.authorityPath $Authority.authoritySha256)
    $taskProtectedRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DriverCrate\PrivateIndex229'
    $taskApprovedWorkspacePath = Join-Path $taskProtectedRoot 'control\approved-workspace.json'
    $taskPins = @($Authority.files)
    if ($taskPins.Count -lt 10 -or $taskPins.Count -gt 4096) { throw 'TASK_INPUT_CLOSURE' }
    $taskPinMap = @{}
    # 各pinを実体と照合し、重複・有限上限・非保護ACLを一件でも検出すれば拒否する。
    foreach ($taskPin in $taskPins) {
        if ($taskPinMap.ContainsKey($taskPin.path) -or $taskPin.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'TASK_INPUT_CLOSURE' }
        Assert-TaskCutoverProtectedPath $taskPin.path
        $taskItem = Get-Item -LiteralPath $taskPin.path -Force
        # 固定承認recordはhash読取り前に有限長へ限定し、空の承認fileも受理しない。
        if ($taskPin.path -ceq $taskApprovedWorkspacePath -and -not $taskItem.PSIsContainer -and
            ($taskItem.Length -le 0 -or $taskItem.Length -gt 65536)) { throw 'TASK_WORKSPACE_APPROVAL_SIZE' }
        if ($taskItem.PSIsContainer -or $taskItem.Length -ne $taskPin.bytes -or $taskItem.Length -gt 268435456 -or
            (Get-FileHash -LiteralPath $taskPin.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskPin.sha256) { throw 'TASK_INPUT_PIN' }
        $taskPinMap[$taskPin.path] = $taskPin.sha256
    }
    # 呼出し側の別pathや通常configを承認元にせず、OS固定recordの完全一致pinを必須にする。
    if (@($taskPins | Where-Object path -CEQ $taskApprovedWorkspacePath).Count -ne 1) { throw 'TASK_WORKSPACE_APPROVAL_PIN_REQUIRED' }
    $taskVersion = Split-Path -Parent $Authority.newPipelinePath
    if ((Split-Path -Parent $taskVersion) -cne (Join-Path $taskProtectedRoot 'scripts') -or
        (Split-Path -Leaf $taskVersion) -cnotmatch '^v2-[a-z0-9-]{1,64}$' -or
        $Authority.newPipelinePath -cne (Join-Path $taskVersion 'daily_index_pipeline.py') -or
        (Split-Path -Parent $Authority.newConfigPath) -cnotlike (Join-Path $taskProtectedRoot 'control\*') -or
        $Configuration.pythonExe -cne (Join-Path $taskProtectedRoot 'runtime\python.exe')) { throw 'TASK_PROTECTED_VERSION_REQUIRED' }
    $taskBinaryRoot = Join-Path (Join-Path $taskProtectedRoot 'bin') (Split-Path -Leaf $taskVersion)
    if ($Configuration.collectorExe -cne (Join-Path $taskBinaryRoot 'DriverCrateCollector.exe') -or
        $Configuration.signerExe -cne (Join-Path $taskBinaryRoot 'DriverCrateLocalIndexSigner.exe') -or
        $Configuration.ghExe -cne 'C:\Program Files\GitHub CLI\gh.exe') { throw 'TASK_PROTECTED_VERSIONED_BIN' }
    $taskModules = @('daily_index_pipeline.py', 'project_collected_native_index.py', 'collector_registry.py', 'prepare_daily_index_config.py')
    $taskModuleNames = (@(Get-ChildItem -LiteralPath $taskVersion -File -Filter '*.py').Name | Sort-Object) -join '|'
    if (@($Configuration.modulePins.PSObject.Properties).Count -ne 4 -or
        $taskModuleNames -cne (($taskModules | Sort-Object) -join '|')) { throw 'TASK_MODULE_CLOSURE' }
    foreach ($taskModule in $taskModules) {
        if (-not $taskPinMap.ContainsKey((Join-Path $taskVersion $taskModule)) -or
            $Configuration.modulePins.$taskModule -cnotmatch '^[0-9a-f]{64}$' -or
            $taskPinMap[(Join-Path $taskVersion $taskModule)] -cne $Configuration.modulePins.$taskModule) { throw 'TASK_MODULE_PIN' }
    }
    if ($taskPinMap[$Authority.newPipelinePath] -cne $Configuration.pipelineSha256 -or
        $taskPinMap[(Join-Path $taskVersion 'project_collected_native_index.py')] -cne $Configuration.producerSha256 -or
        $taskPinMap[$Authority.oldConfigPath] -cne $Authority.expectedOldConfigSha256 -or
        $taskPinMap[$Authority.newConfigPath] -cne $Authority.proposedConfigSha256 -or
        $taskPinMap[$Authority.proposedXmlPath] -cne $Authority.proposedXmlSha256) { throw 'TASK_INPUT_PIN_BINDING' }
    $taskRequired = @($Authority.registrationScriptPath, $Authority.oldConfigPath, $Authority.newConfigPath, $Authority.oldPipelinePath,
        $Authority.newPipelinePath, $Authority.proposedXmlPath, $Authority.authorityPath, $taskApprovedWorkspacePath,
        $Configuration.pythonExe, (Join-Path (Split-Path -Parent $Configuration.pythonExe) 'pythonw.exe'),
        $Configuration.collectorExe, $Configuration.signerExe, $Configuration.ghExe,
        $Configuration.manifestFile, $Configuration.scopeFile, $Configuration.publicKeyFile)
    # authority自身はCLI hashで結合し、自己参照するfile pinからは除く。
    foreach ($taskRequiredPath in $taskRequired) {
        if ($taskRequiredPath -cne $Authority.authorityPath -and -not $taskPinMap.ContainsKey($taskRequiredPath)) { throw 'TASK_INPUT_CLOSURE' }
    }
    foreach ($taskPair in @(@('collectorExe', 'collectorSha256'), @('signerExe', 'signerSha256'),
        @('manifestFile', 'manifestSha256'), @('scopeFile', 'scopeSha256'), @('publicKeyFile', 'fingerprint'))) {
        if ($taskPinMap[$Configuration.($taskPair[0])] -cne $Configuration.($taskPair[1])) { throw 'TASK_CONFIG_PIN' }
    }
    # 手動参考三入力、cache archive、旧metadata/fenceもレビュー済みfile集合へ結合する。
    if (@($Configuration.originalInputs.PSObject.Properties).Count -ne 3) { throw 'TASK_ORIGINAL_INPUT_CLOSURE' }
    foreach ($taskReferenceName in @('release', 'review', 'script')) {
        $taskReference = $Configuration.originalInputs.$taskReferenceName
        if ($null -eq $taskReference -or -not $taskPinMap.ContainsKey($taskReference.file) -or
            $taskPinMap[$taskReference.file] -cne $taskReference.sha256) { throw 'TASK_ORIGINAL_INPUT_PIN' }
    }
    if (-not $taskPinMap.ContainsKey($Configuration.archiveFile) -or
        $taskPinMap[$Configuration.archiveFile] -cne $Configuration.archiveSha256) { throw 'TASK_ARCHIVE_PIN' }
    foreach ($taskLegacyName in @('receipt', 'rawManifest', 'gzip', 'envelope')) {
        $taskLegacyPath = $Configuration.legacyMetadata.($taskLegacyName + 'File')
        if (-not $taskPinMap.ContainsKey($taskLegacyPath) -or
            $taskPinMap[$taskLegacyPath] -cne $Configuration.legacyMetadata.($taskLegacyName + 'Sha256')) { throw 'TASK_LEGACY_INPUT_PIN' }
    }
    if (-not $taskPinMap.ContainsKey($Configuration.legacyMetadata.fenceReceiptFile) -or
        $taskPinMap[$Configuration.legacyMetadata.fenceReceiptFile] -cne $Configuration.legacyReservationFence.receiptSha256) { throw 'TASK_LEGACY_FENCE_PIN' }
    $taskRuntime = Split-Path -Parent $Configuration.pythonExe
    if (-not (Get-Acl -LiteralPath $taskRuntime).AreAccessRulesProtected) { throw 'TASK_PYTHON_RUNTIME_PROTECTED_INSTALL_REQUIRED' }
    $taskRuntimeEntries = 0
    $taskRuntimeDeadline = [DateTime]::UtcNow.AddSeconds(20)
    Get-ChildItem -LiteralPath $taskRuntime -Recurse -Force -ErrorAction Stop | ForEach-Object {
        $taskRuntimeEntries++
        if ($taskRuntimeEntries -gt 4096 -or [DateTime]::UtcNow -gt $taskRuntimeDeadline) { throw 'TASK_RUNTIME_AUDIT_LIMIT' }
        Assert-TaskCutoverProtectedPath $_.FullName
        if (-not $_.PSIsContainer -and -not $taskPinMap.ContainsKey($_.FullName)) { throw 'TASK_RUNTIME_PIN_MISSING' }
    }
    Assert-TaskCutoverProtectedPath $Configuration.outputRoot
}

$taskMode = Get-DailyTaskRegistrationMode -Register:$Register -UpdateExistingAction:$UpdateExistingAction -Smoke:$Smoke
if ($taskMode -eq 'ACTION_UPDATE') {
    # 明示切替だけで現在ユーザー昇格・authorityを検査し、既定生成経路を実Taskへ接続しない。
    $taskCutoverIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $taskCutoverPrincipal = [Security.Principal.WindowsPrincipal]::new($taskCutoverIdentity)
    if (-not $taskCutoverPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ELEVATED_CURRENT_USER_REGISTRATION_REQUIRED' }
    $taskAuthority = (Read-TaskCutoverText $CutoverAuthority $CutoverAuthoritySha256) | ConvertFrom-Json
    if ($taskAuthority.newConfigPath -cne $Config -or $taskAuthority.proposedXmlPath -cne $NewXml -or
        $taskAuthority.registrationScriptPath -cne $PSCommandPath) { throw 'TASK_CUTOVER_CLI_BINDING' }
    $taskAuthority | Add-Member -NotePropertyName authorityPath -NotePropertyValue $CutoverAuthority -Force
    $taskAuthority | Add-Member -NotePropertyName authoritySha256 -NotePropertyValue $CutoverAuthoritySha256 -Force
    $taskOldText = Read-TaskCutoverText $taskAuthority.oldConfigPath $taskAuthority.expectedOldConfigSha256
    $taskNewText = Read-TaskCutoverText $Config $taskAuthority.proposedConfigSha256
    $taskExpectedPython = ($taskNewText | ConvertFrom-Json).pythonExe
    if ($taskExpectedPython -cne $Python) { throw 'TASK_PYTHON_CONFIG_MISMATCH' }
    $taskProposedText = Read-TaskCutoverText $NewXml $taskAuthority.proposedXmlSha256
    $taskCutoverService = New-Object -ComObject 'Schedule.Service'
    $taskCutoverService.Connect()
    $taskCutoverFolder = $taskCutoverService.GetFolder('\')
    $taskCutoverScheduler = @{
        Read = {
            $taskObserved = $taskCutoverFolder.GetTask('DriverCrate.PrivateIndex.Daily229')
            [pscustomobject]@{ Name = $taskObserved.Name; Path = $taskObserved.Path; Xml = $taskObserved.Xml;
                Sddl = $taskObserved.GetSecurityDescriptor(7); State = [int]$taskObserved.State;
                Enabled = [bool]$taskObserved.Enabled; Instances = $taskObserved.GetInstances(0).Count;
                NextRunUtc = $taskObserved.NextRunTime.ToUniversalTime() }
        }
        Update = {
            param($Xml, $Flags, $Sid)
            $null = $taskCutoverFolder.RegisterTask('DriverCrate.PrivateIndex.Daily229',
                (ConvertTo-TaskRegistrationXml $Xml), $Flags, $Sid, $null, 3, $null)
        }
    }
    $taskInputValidator = ${function:Assert-TaskCutoverInputs}
    Invoke-TaskActionCutover $taskAuthority $taskCutoverIdentity.User.Value $taskOldText $taskNewText $taskProposedText `
        $taskCutoverScheduler $taskInputValidator { [DateTime]::UtcNow }
    return
}
# 切替authorityの指定を既定生成や新規登録へ暗黙に流用しない。
if ($CutoverAuthority -or $CutoverAuthoritySha256) { throw 'TASK_CUTOVER_SWITCH_REQUIRED' }

$taskRoot = Split-Path -Parent $PSScriptRoot
$taskConfigPath = (Resolve-Path -LiteralPath $Config).Path
$taskPythonPath = (Resolve-Path -LiteralPath $Python).Path
# NewXmlは絶対pathの新規fileだけを受け付け、既存XMLの上書きを拒否する。
if (-not [System.IO.Path]::IsPathRooted($NewXml) -or (Test-Path -LiteralPath $NewXml)) {
    throw 'NEW_XML_REQUIRED'
}
# Task XMLの保存先をconfigと同じcontrol directoryへ限定して、別場所のXMLを登録対象にしない。
if ((Resolve-Path -LiteralPath (Split-Path -Parent $NewXml)).Path -ne (Split-Path -Parent $taskConfigPath)) {
    throw 'TASK_XML_CONTROL_DIRECTORY_REQUIRED'
}
$taskIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$taskPrincipal = [System.Security.Principal.WindowsPrincipal]::new($taskIdentity)
$taskName = if ($Smoke) { 'DriverCrate.PrivateIndex.Smoke229' } else { 'DriverCrate.PrivateIndex.Daily229' }
# Register指定時だけ現在ユーザーの管理者roleを必須にし、非昇格の登録を拒否する。
if ($Register -and -not $taskPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'ELEVATED_CURRENT_USER_REGISTRATION_REQUIRED'
}
$taskConfiguration = Get-Content -LiteralPath $taskConfigPath -Raw | ConvertFrom-Json
$taskRoot = (Resolve-Path -LiteralPath $taskConfiguration.repositoryRoot).Path
# configが指すPythonと明示引数Pythonを同じ正規pathへ結合し、登録commandの差替えを拒否する。
if ((Resolve-Path -LiteralPath $taskConfiguration.pythonExe).Path -ne $taskPythonPath) {
    throw 'TASK_PYTHON_CONFIG_MISMATCH'
}
$taskProtectedPaths = @($PSCommandPath, (Join-Path $PSScriptRoot 'daily_index_pipeline.py'),
    (Join-Path $PSScriptRoot 'project_collected_native_index.py'), (Join-Path $PSScriptRoot 'collector_registry.py'),
    $taskConfigPath, $taskPythonPath, (Join-Path (Split-Path -Parent $taskPythonPath) 'pythonw.exe'),
    $taskConfiguration.collectorExe, $taskConfiguration.signerExe, $taskConfiguration.ghExe,
    $taskConfiguration.manifestFile, $taskConfiguration.scopeFile, $taskConfiguration.publicKeyFile,
    $taskConfiguration.outputRoot)
$taskChecked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# 固定Task入力一覧の全実体とancestorを検査し、重複検査を抑えつつreparseと非保護ACLを拒否する。
foreach ($taskInput in $taskProtectedPaths) {
    $taskResolved = (Resolve-Path -LiteralPath $taskInput).Path
    $taskDepth = 0
    # 各入力から親へ上り、file/直属directoryと上位ancestorでwrite maskを分け、親なしまたは自己parentで停止する。
    while ($taskResolved) {
        $taskAncestor = $taskDepth -ge 2
        if ($taskChecked.Add($taskResolved + ':' + $taskAncestor)) {
            $taskItem = Get-Item -LiteralPath $taskResolved -Force
            # Task入力またはancestorのreparseを拒否し、ACL確認先と実行時code-loading先の迂回を避ける。
            if (($taskItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'TASK_INPUT_REPARSE'
            }
            Assert-TaskProtectedAcl -Acl (Get-Acl -LiteralPath $taskResolved) -Ancestor:$taskAncestor
        }
        $taskParent = Split-Path -Parent $taskResolved
        if ($taskParent -eq $taskResolved) { break }
        $taskResolved = $taskParent
        $taskDepth++
    }
}
# A per-user Python runtime also loads writable DLL/stdlib files. Its whole installation must be
# protected by inheritance; checking only pythonw.exe would leave an elevated code-loading path.
$taskPythonDirectory = Split-Path -Parent $taskPythonPath
$taskPythonDirectoryAcl = Get-Acl -LiteralPath $taskPythonDirectory
if (-not $taskPythonDirectoryAcl.AreAccessRulesProtected) { throw 'TASK_PYTHON_RUNTIME_PROTECTED_INSTALL_REQUIRED' }
$taskRuntimeCount = 0
$taskRuntimeDeadline = [DateTime]::UtcNow.AddSeconds(20)
# Python installationの全childでACLとreparseを検査し、entry間の判定で4096件または20秒を超えれば拒否する。各I/Oや列挙全体のhard deadlineではなく、途中検査を全runtime保護の合格にしない。
Get-ChildItem -LiteralPath $taskPythonDirectory -Recurse -Force -ErrorAction Stop | ForEach-Object {
    $taskChild = $_
    $taskRuntimeCount++
    if ($taskRuntimeCount -gt 4096 -or [DateTime]::UtcNow -gt $taskRuntimeDeadline) { throw 'TASK_RUNTIME_AUDIT_LIMIT' }
    if (($taskChild.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'TASK_RUNTIME_REPARSE' }
    Assert-TaskProtectedAcl (Get-Acl -LiteralPath $taskChild.FullName)
}
$taskArguments = @('-I', (Join-Path $PSScriptRoot 'daily_index_pipeline.py'), 'task', $taskConfigPath,
    '--output', $NewXml, '--user-sid', $taskIdentity.User.Value)
if ($Smoke) { $taskArguments += '--smoke' }
Push-Location -LiteralPath $taskRoot
try {
    & $taskPythonPath @taskArguments
    # Task定義生成が失敗した場合はXML登録へ進ませず例外にする。
    if ($LASTEXITCODE -ne 0) { throw 'TASK_DEFINITION_REJECTED' }
} finally {
    Pop-Location
}
$taskNewXmlItem = Get-Item -LiteralPath $NewXml -Force
# 新XMLがreparseであれば登録前に拒否し、検査と登録に使うfileを迂回させない。
if (($taskNewXmlItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'TASK_XML_REPARSE' }
Assert-TaskProtectedAcl -Acl (Get-Acl -LiteralPath $NewXml)
if ($Register) {
    # COM TASK_CREATE=2 is atomic and rejects a concurrently-created same-name Task.
    $taskService = New-Object -ComObject 'Schedule.Service'
    $taskService.Connect()
    $taskFolder = $taskService.GetFolder('\')
    $taskXmlText = [System.IO.File]::ReadAllText($NewXml, [System.Text.Encoding]::UTF8)
    $taskRegistrationXmlText = ConvertTo-TaskRegistrationXml -XmlText $taskXmlText
    $null = $taskFolder.RegisterTask($taskName, $taskRegistrationXmlText, 2, $taskIdentity.User.Value, $null, 3, $null)
    Write-Output 'TASK_REGISTERED_NOT_STARTED'
} else {
    Write-Output 'TASK_DEFINITION_ONLY_NO_REGISTRATION'
}
