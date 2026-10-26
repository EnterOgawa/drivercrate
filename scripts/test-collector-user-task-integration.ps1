#requires -Version 7.0
<#
.SYNOPSIS
現行v7のnative/単体EXEから新規所有Task最大二件だけの有限導入・解除を確認する。
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
defaultはNOT_RUN。実行には-AllowTaskRegistrationが必須。旧Task、全Task列挙、Run/Stop、
HTTP、driver、鍵、署名、GitHubに触れない。fixtureは保持し、失敗時もTaskを名前だけで削除しない。
製品のActionは正規native --onceのまま。自然dueに余裕のある時間帯でだけ開始し、
Task管理を同時に変更しない。timeout/UNKNOWNでは自動cleanupや再実行をしない。
#>
[CmdletBinding()]
param([string] $PackageDirectory, [string] $InstallerExecutable, [string] $FixtureRoot,
    [switch] $AllowTaskRegistration)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AllowTaskRegistration) {
    [pscustomobject]@{ result = 'NOT_RUN'; reason = 'EXPLICIT_ALLOW_TASK_REGISTRATION_REQUIRED'
        taskQueries = 0; taskChanges = 0; http = 0 } | ConvertTo-Json -Compress
    return
}
if (-not $PackageDirectory -or -not $FixtureRoot) { throw 'INTEGRATION_PACKAGE_AND_FRESH_ROOT_REQUIRED' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $repo 'packaging/collector/collector-setup.psm1') -Force -DisableNameChecking
. (Join-Path $repo 'scripts/index_build_profile.ps1')
$bundle = Read-CollectorBundle $PackageDirectory
if ($bundle.Manifest.schema -cne 'dc-collector-package-v7') { throw 'INTEGRATION_CURRENT_PACKAGE_REQUIRED' }
$root = Assert-CollectorSetupPath $FixtureRoot
if (Test-Path -LiteralPath $root) { throw 'INTEGRATION_FRESH_ROOT_REQUIRED' }
$now = [DateTime]::Now
$today = $now.Date.AddHours(15)
# 二fixtureと20分の全体予算が自然dueを跨がない余裕を、Task接続より前に確定する。
if ($today -gt $now -and ($today - $now).TotalMinutes -lt 30) { throw 'INTEGRATION_TOO_CLOSE_TO_1500' }
$deadline = [DateTime]::UtcNow.AddMinutes(20)
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $currentIdentity.User.Value
$currentName = $currentIdentity.Name
if ($sid -notmatch '^S-1-(5-21|12-1)-') { throw 'INTEGRATION_NORMAL_USER_REQUIRED' }
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$sha = [Security.Cryptography.SHA256]::Create()
function Hash-Text([string] $Text) {
    return [Convert]::ToHexString($sha.ComputeHash($utf8.GetBytes($Text))).ToLowerInvariant()
}
function Check([bool] $Condition, [string] $Stage) {
    if (-not $Condition) { throw ('INTEGRATION_' + $Stage) }
    if ([DateTime]::UtcNow -ge $deadline) { throw 'INTEGRATION_BUDGET_EXHAUSTED' }
}
function Test-CurrentUserPrincipal([string] $RawXml, [string] $TypedUserId,
    [int] $LogonType, [int] $RunLevel, [string] $CurrentSid, [string] $CurrentName) {
    if ($RawXml.Length -gt 65536 -or -not $CurrentName -or $LogonType -ne 3 -or $RunLevel -ne 0) { return $false }
    $shortName = $CurrentName.Substring($CurrentName.LastIndexOf('\') + 1)
    if ($TypedUserId -cnotin @($CurrentSid, $CurrentName, $shortName)) { return $false }
    $readerSettings = [Xml.XmlReaderSettings]::new()
    $readerSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $readerSettings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($RawXml), $readerSettings)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        $namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespaces.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
        $principals = $document.SelectNodes('/t:Task/t:Principals/t:Principal', $namespaces)
        if ($principals.Count -ne 1 -or $principals[0].GetAttribute('id') -cne 'Collector') { return $false }
        $users = $principals[0].SelectNodes('t:UserId', $namespaces)
        $logons = $principals[0].SelectNodes('t:LogonType', $namespaces)
        $levels = $principals[0].SelectNodes('t:RunLevel', $namespaces)
        return $users.Count -eq 1 -and $users[0].InnerText -ceq $CurrentSid -and
            $logons.Count -eq 1 -and $logons[0].InnerText -ceq 'InteractiveToken' -and
            ($levels.Count -eq 0 -or ($levels.Count -eq 1 -and $levels[0].InnerText -ceq 'LeastPrivilege'))
    } catch { return $false } finally { $reader.Dispose() }
}
$fixtures = @([ordered]@{ kind = 'native'; root = (Join-Path $root 'native 収集 fixture')
    executable = (Join-Path $bundle.Root 'DriverCrateCollectorSetup.exe') })
if ($InstallerExecutable) {
    $installer = Assert-IndexPackagePath -Path $InstallerExecutable
    Assert-CollectorX64Executable $installer
    $fixtures += [ordered]@{ kind = 'embedded-exe'; root = (Join-Path $root 'embedded 収集 fixture')
        executable = $installer }
}
foreach ($fixture in $fixtures) {
    $material = $sid + "`n" + $fixture.root.Replace('/', '\').ToUpperInvariant()
    $fixture.taskPath = '\DriverCrate.Collector.Daily.' + (Hash-Text $material)
}
Check ($fixtures.Count -le 2 -and @($fixtures.taskPath | Select-Object -Unique).Count -eq $fixtures.Count) 'FINITE_TASK_NAMES'
[void][IO.Directory]::CreateDirectory($root)
$plan = [ordered]@{ schema = 'dc-collector-user-task-integration-v1'; fixtures = $fixtures
    startedUtc = [DateTime]::UtcNow.ToString('o'); deadlineUtc = $deadline.ToString('o')
    taskMaximum = 2; taskRun = 0; taskStop = 0; http = 0; oldTaskQueries = 0 }
[IO.File]::WriteAllText((Join-Path $root 'fixed-plan.json'), ($plan | ConvertTo-Json -Depth 8), $utf8)
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$script:queries = 0
$script:calls = 0
$script:readbackEvidence = 0
function Read-FixedTask([string] $Path) {
    Check ($Path -cin $fixtures.taskPath) 'NAME_OUTSIDE_FIXED_SET'
    ++$script:queries
    try { return $folder.GetTask($Path) }
    catch {
        $taskReadError = $_.Exception
        while ($taskReadError.InnerException) { $taskReadError = $taskReadError.InnerException }
        if ($taskReadError.HResult -eq -2147024894) { return $null }
        throw
    }
}
function Native([string] $Executable, [string[]] $Arguments, [string] $WorkingDirectory) {
    Check ($true) 'BEFORE_NATIVE'
    $info = [Diagnostics.ProcessStartInfo]::new($Executable)
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    [void]$process.Start()
    $out = $process.StandardOutput.ReadToEndAsync()
    $err = $process.StandardError.ReadToEndAsync()
    # timeoutでTask状態を推測せず、子を強制停止・Taskを削除しない。
    if (-not $process.WaitForExit(180000)) { throw 'INTEGRATION_NATIVE_TIMEOUT_UNKNOWN_RETAINED' }
    $stdout = $out.GetAwaiter().GetResult()
    $stderr = $err.GetAwaiter().GetResult()
    $call = [ordered]@{ executable = $Executable; argv = $Arguments; cwd = $WorkingDirectory
        timeoutSeconds = 180; exitCode = $process.ExitCode; stdout = $stdout; stderr = $stderr
        stdoutEof = $true; stderrEof = $true; streamRepresentation = 'DECODED_STREAMREADER_TEXT_NOT_RAW_BYTES' }
    [IO.File]::WriteAllText((Join-Path $root ('native-' + $script:calls++ + '.json')),
        ($call | ConvertTo-Json -Depth 5), $utf8)
    Check ($process.ExitCode -eq 0 -and $stdout.Length -lt 65536 -and $stderr.Length -lt 65536) 'NATIVE_RESULT'
    return $stdout
}
function Read-Enabled([object] $Fixture, [DateTime] $BeforeInstall) {
    $task = Read-FixedTask $Fixture.taskPath
    Check ($null -ne $task -and $task.Enabled -and $task.State -eq 3 -and $task.GetInstances(0).Count -eq 0) 'ENABLED_READY'
    $definition = $task.Definition
    $raw = $task.Xml
    # rawの唯一SIDを必須にし、typed名は現在token由来の三表記だけを認める。
    Check (Test-CurrentUserPrincipal $raw $definition.Principal.UserId $definition.Principal.LogonType `
        $definition.Principal.RunLevel $sid $currentName) 'CURRENT_USER_PRINCIPAL'
    Check ($definition.Actions.Count -eq 1 -and $definition.Triggers.Count -eq 1) 'UNIQUE_ACTION_TRIGGER'
    $action = $definition.Actions.Item(1)
    $expectedArguments = '--once "' + (Join-Path $Fixture.root 'config/targets.json') + '" "' +
        (Join-Path $Fixture.root 'work/state/collector') + '"'
    Check ($action.Type -eq 0 -and $action.Path -ceq (Join-Path $Fixture.root 'bin/DriverCrateCollector.exe') -and
        $action.Arguments -ceq $expectedArguments -and $action.WorkingDirectory -ceq $Fixture.root) 'NATIVE_ACTION_CWD'
    $trigger = $definition.Triggers.Item(1)
    $due = [DateTime]::ParseExact($trigger.StartBoundary, 'yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    Check ($trigger.Type -eq 2 -and $trigger.DaysInterval -eq 1 -and $trigger.Enabled -and
        $trigger.StartBoundary.EndsWith('T15:00:00') -and $due -ge $BeforeInstall.AddMinutes(5) -and
        $due -gt [DateTime]::Now.AddMinutes(1)) 'FUTURE_DAILY'
    $settings = $definition.Settings
    Check ($settings.MultipleInstances -eq 2 -and -not $settings.StartWhenAvailable -and
        -not $settings.RunOnlyIfIdle -and -not $settings.WakeToRun -and -not $settings.DisallowStartIfOnBatteries -and
        -not $settings.StopIfGoingOnBatteries -and -not $settings.AllowHardTerminate -and
        $settings.ExecutionTimeLimit -ceq 'PT1H10M' -and -not $settings.Hidden -and -not $settings.AllowDemandStart) 'SETTINGS'
    $ownership = Get-Content -LiteralPath (Join-Path $Fixture.root 'collector-user-task-ownership.json') -Raw | ConvertFrom-Json
    $pending = Get-Content -LiteralPath (Join-Path $Fixture.root 'collector-user-task-plan.json') -Raw | ConvertFrom-Json
    $receipt = Get-Content -LiteralPath (Join-Path $Fixture.root 'install-receipt.json') -Raw | ConvertFrom-Json
    Check ($receipt.schema -ceq 'dc-collector-install-receipt-v3' -and
        $receipt.packageManifestSha256 -ceq $bundle.ManifestHash -and
        $ownership.schema -ceq 'dc-collector-user-task-ownership-v1' -and
        $ownership.plan.taskPath -ceq $Fixture.taskPath -and $ownership.plan.principalSid -ceq $sid -and
        $ownership.plan.packageRoot -ceq $Fixture.root -and $ownership.plan.packageManifestSha256 -ceq $bundle.ManifestHash -and
        $pending.transactionNonce -ceq $ownership.plan.transactionNonce -and
        $pending.startBoundary -ceq $trigger.StartBoundary -and
        $ownership.plan.startBoundary -ceq $trigger.StartBoundary -and
        $pending.previousOwnershipSha256 -ceq $ownership.plan.previousOwnershipSha256 -and
        $definition.RegistrationInfo.Description -ceq ('DriverCrate collector transaction ' + $pending.transactionNonce)) 'OWNERSHIP_BINDING'
    $settingsXml = [regex]::Match($raw, '(?s)<Settings>(.*?)</Settings>')
    Check $settingsXml.Success 'RAW_SETTINGS'
    $explicitEnabled = [regex]::Matches($settingsXml.Groups[1].Value, '<Enabled>true</Enabled>')
    $enabledOmitted = $explicitEnabled.Count -eq 0
    $onWitness = $raw
    if ($enabledOmitted) {
        # 実OSの既知直接子行へ一行だけを挿入する独立witness。実原XMLは保持する。
        Check (-not $settingsXml.Groups[1].Value.Contains('<Enabled') -and
            [regex]::Matches($settingsXml.Groups[1].Value, '(?m)^    <ExecutionTimeLimit>').Count -eq 1) 'OMITTED_ENABLED_FORMAT'
        $slot = $raw.IndexOf('    <ExecutionTimeLimit>', $settingsXml.Index, [StringComparison]::Ordinal)
        Check ($slot -gt 1 -and $raw.Substring($slot - 2, 2) -ceq "`r`n") 'OMITTED_ENABLED_CRLF'
        $onWitness = $raw.Insert($slot, "    <Enabled>true</Enabled>`r`n")
    } else {
        Check ($explicitEnabled.Count -eq 1) 'EXPLICIT_ENABLED_UNIQUE'
    }
    $off = [regex]::Replace($onWitness, '(?s)(<Settings>.*?<Enabled>)true(</Enabled>)', '${1}false${2}')
    $sddl = $task.GetSecurityDescriptor(7)
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $allowed = @($sid, 'S-1-5-18', 'S-1-5-32-544')
    Check ($descriptor.Owner.Value -ceq $sid -and $descriptor.Group.Value -ceq $sid -and
        ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0 -and
        $descriptor.DiscretionaryAcl.Count -eq 3) 'SDDL_BOUNDARY'
    $seen = @()
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        Check ($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed -and
            $ace.AceFlags -eq [Security.AccessControl.AceFlags]::None -and
            $ace.AccessMask -in @(0x10000000, 0x1f01ff) -and $ace.SecurityIdentifier.Value -cin $allowed -and
            $ace.SecurityIdentifier.Value -cnotin $seen) 'SDDL_ACE'
        $seen += $ace.SecurityIdentifier.Value
    }
    Check ($ownership.enabledTaskXmlSha256 -ceq (Hash-Text $onWitness) -and
        $ownership.disabledTaskXmlSha256 -ceq (Hash-Text $off) -and
        $ownership.taskSddlSha256 -ceq (Hash-Text $sddl)) 'RAW_XML_SDDL_PINS'
    # 既に照合した値をlocal fixtureへ保存し、Taskへの照会・変更を追加しない。
    $readbackEvidence = [ordered]@{ kind = $Fixture.kind; taskPath = $Fixture.taskPath
        observedUtc = [DateTime]::UtcNow.ToString('o'); xml = $raw; sddl = $sddl
        actualXmlSha256 = Hash-Text $raw; enabledOmitted = $enabledOmitted
        enabledWitnessSha256 = Hash-Text $onWitness; disabledWitnessSha256 = Hash-Text $off
        witnessIsActualXml = -not $enabledOmitted; candidateWrittenToTaskOrMetadata = $false
        ownership = $ownership; plan = $pending; installReceipt = $receipt
        futureDue = $due.ToString('o'); checkedEnabledReady = $true
        checks = 'EXISTING_READ_ENABLED_CHECKS_PASS' }
    [IO.File]::WriteAllText((Join-Path $root ('readback-' + $script:readbackEvidence++ + '.json')),
        ($readbackEvidence | ConvertTo-Json -Depth 12), $utf8)
    return $due
}
# 固定した最大二名すべての正常不存在を、最初の製品install前に確認する。
$initialAbsence = @()
foreach ($fixture in $fixtures) {
    $initialTask = Read-FixedTask $fixture.taskPath
    $initialAbsence += [ordered]@{ taskPath = $fixture.taskPath; absent = $null -eq $initialTask
        observedUtc = [DateTime]::UtcNow.ToString('o') }
    [IO.File]::WriteAllText((Join-Path $root 'initial-absence.json'),
        ($initialAbsence | ConvertTo-Json -Depth 5), $utf8)
    Check ($null -eq $initialTask) 'PREEXISTING_TASK_REJECTED'
}
$results = @()
foreach ($fixture in $fixtures) {
    $beforeInstall = [DateTime]::Now
    $poison = Join-Path $root ('untrusted-python-' + $fixture.kind)
    [void][IO.Directory]::CreateDirectory($poison)
    [IO.File]::WriteAllText((Join-Path $poison 'sitecustomize.py'), 'raise SystemExit(99)', $utf8)
    [IO.File]::WriteAllText((Join-Path $poison 'collector_workspace.py'), 'raise SystemExit(99)', $utf8)
    $oldPath = $env:PATH
    $oldPython = $env:PYTHONPATH
    try {
        $env:PATH = Join-Path $root 'no-external-runtime'
        $env:PYTHONPATH = $poison
        [void](Native $fixture.executable @('--install', $fixture.root, '--yes') $bundle.Root)
    } finally { $env:PATH = $oldPath; $env:PYTHONPATH = $oldPython }
    $due = Read-Enabled $fixture $beforeInstall
    $setup = Join-Path $fixture.root 'DriverCrateCollectorSetup.exe'
    [void](Read-CollectorBundle $fixture.root -Installed)
    # 新配置の基本または参考つきpayloadとmanifestの全file pinを元bundleへ照合する。
    $installedPins = @()
    foreach ($relative in @($bundle.Manifest.files.path) + @('package-manifest.json')) {
        $installedHash = Get-CollectorSetupHash (Join-Path $fixture.root $relative)
        $bundleHash = Get-CollectorSetupHash (Join-Path $bundle.Root $relative)
        $installedPins += [ordered]@{ path = $relative; installedSha256 = $installedHash; bundleSha256 = $bundleHash }
        Check ($installedHash -ceq $bundleHash) 'ALL_75_INSTALLED_BYTES'
    }
    [IO.File]::WriteAllText((Join-Path $root ($fixture.kind + '-installed-pins.json')),
        ($installedPins | ConvertTo-Json -Depth 5), $utf8)
    $collectorState = Join-Path $fixture.root 'work/state/collector'
    Check (-not (Test-Path -LiteralPath $collectorState)) 'VALIDATE_STATE_ABSENT_BEFORE'
    $validation = Native (Join-Path $fixture.root 'bin/DriverCrateCollector.exe') @('--validate',
        (Join-Path $fixture.root 'config/targets.json'), $collectorState) $fixture.root
    Check ($validation.Contains('acquired=0 installed=0') -and -not (Test-Path -LiteralPath $collectorState)) 'NONCOMMUNICATING_NATIVE_VALIDATE'
    $retained = @('DriverCrateCollectorSetup.exe', 'Uninstall.cmd') +
        @($bundle.Manifest.files.path | Where-Object { $_.StartsWith('seed/') -or $_.StartsWith('config/') })
    $sentinel = Join-Path $fixture.root 'work/retained-fixture.json'
    [IO.File]::WriteAllText($sentinel, '{"synthetic":true,"keep":true}', $utf8)
    $retained += 'work/retained-fixture.json'
    [IO.File]::WriteAllText((Join-Path $fixture.root 'retained-unknown.txt'), 'unknown synthetic data', $utf8)
    [IO.File]::WriteAllText((Join-Path $fixture.root 'work/state/retained-test.dat'), 'synthetic cooldown sentinel', $utf8)
    $retained += @('retained-unknown.txt', 'work/state/retained-test.dat')
    $hashes = @{}
    foreach ($relative in $retained) { $hashes[$relative] = Get-CollectorSetupHash (Join-Path $fixture.root $relative) }
    [IO.File]::WriteAllText((Join-Path $root ($fixture.kind + '-retained-before-repair.json')),
        ($hashes | ConvertTo-Json -Depth 5), $utf8)
    [void](Native $setup @('--install', $fixture.root, '--yes') $fixture.root)
    [void](Read-Enabled $fixture $beforeInstall)
    $repairHashes = @{}
    foreach ($relative in $retained) {
        $repairHashes[$relative] = Get-CollectorSetupHash (Join-Path $fixture.root $relative)
        Check ($repairHashes[$relative] -ceq $hashes[$relative]) 'REPAIR_DATA_BYTES'
    }
    [IO.File]::WriteAllText((Join-Path $root ($fixture.kind + '-retained-after-repair.json')),
        ($repairHashes | ConvertTo-Json -Depth 5), $utf8)
    Check ($due -gt [DateTime]::Now.AddMinutes(1)) 'UNINSTALL_BEFORE_DUE'
    # 編集configの不正JSONもTask所有証明に使わず、原byteを保持して解除できることを検査する。
    [IO.File]::WriteAllText((Join-Path $fixture.root 'config/targets.json'), '{', $utf8)
    $hashes['config/targets.json'] = Get-CollectorSetupHash (Join-Path $fixture.root 'config/targets.json')
    [IO.File]::WriteAllText((Join-Path $root ($fixture.kind + '-retained-before-uninstall.json')),
        ($hashes | ConvertTo-Json -Depth 5), $utf8)
    # Uninstall.cmdと同じ導入先setupの通常--uninstallへ非対話同意を渡す。
    [void](Native $setup @('--uninstall', $fixture.root, '--yes') $fixture.root)
    $remainingTask = Read-FixedTask $fixture.taskPath
    [IO.File]::WriteAllText((Join-Path $root ($fixture.kind + '-final-absence.json')),
        ([ordered]@{taskPath=$fixture.taskPath;absent=$null -eq $remainingTask
            observedUtc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 5), $utf8)
    Check ($null -eq $remainingTask) 'POST_UNINSTALL_ABSENCE'
    $uninstallHashes = @{}
    foreach ($relative in $retained) {
        $uninstallHashes[$relative] = Get-CollectorSetupHash (Join-Path $fixture.root $relative)
        Check ($uninstallHashes[$relative] -ceq $hashes[$relative]) 'UNINSTALL_DATA_BYTES'
    }
    [IO.File]::WriteAllText((Join-Path $root ($fixture.kind + '-retained-after-uninstall.json')),
        ($uninstallHashes | ConvertTo-Json -Depth 5), $utf8)
    Check (-not (Test-Path -LiteralPath (Join-Path $fixture.root 'bin/DriverCrateCollector.exe'))) 'PROGRAM_REMOVED_AFTER_ABSENCE'
    $results += [ordered]@{ kind = $fixture.kind; enabledReadback = 'PASS'; idempotent = 'PASS'
        taskAbsent = 'PASS'; dataHashes = 'PASS'; malformedConfigRetained = 'PASS'; installed75Bytes = 'PASS'
        poisonedExternalRuntime = 'PASS'; taskPath = $fixture.taskPath; run = 0; stop = 0; http = 0 }
}
$summary = [ordered]@{ result = 'PASS_FINITE_INTEGRATION'; fixtures = $results
    taskQueries = $script:queries; nativeCalls = $script:calls; oldTaskQueries = 0; taskRun = 0; taskStop = 0
    http = 0; driverInstall = 0; naturalDaily = 'NOT_RUN'; singleExe = [bool]$InstallerExecutable }
[IO.File]::WriteAllText((Join-Path $root 'result.json'), ($summary | ConvertTo-Json -Depth 8), $utf8)
$summary | ConvertTo-Json -Depth 8
