#requires -Version 5.1
<#
.SYNOPSIS
Verifies retired AI options cannot enable targets or remain enabled in CMake.
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Uses CMake script mode only. Does not configure a new build tree or run inference/network.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskGuard = Join-Path $taskRoot 'cmake\RejectRetiredAiOptions.cmake'
$taskOptions = @(
    'DRIVERCRATE_BUILD_LOCAL_AI_PROTOTYPE',
    'DRIVERCRATE_BUILD_LOCAL_AI_CUDA_S0',
    'DRIVERCRATE_BUILD_LOCAL_AI_CUDA_S0_REGISTRY_READ',
    'DRIVERCRATE_BUILD_LOCAL_AI_CUDA_COMPATIBLE',
    'DRIVERCRATE_BUILD_LOCAL_AI_CUDA_MODEL',
    'DRIVERCRATE_GGML_CUDA_EXPLICIT_REGISTRATION',
    'GGML_CUDA'
)
$taskRejected = 0
foreach ($taskOption in $taskOptions) {
    # Expected native failure is captured as evidence, not a terminating PowerShell error.
    $ErrorActionPreference = 'Continue'
    $taskResult = @(& cmake ('-D' + $taskOption + '=ON') -P $taskGuard 2>&1)
    $taskCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($taskCode -eq 0 -or ($taskResult -join "`n") -notmatch 'AI support was removed') {
        throw ('RETIRED_OPTION_NOT_REJECTED: ' + $taskOption)
    }
    $taskRejected++
}
$taskOffArguments = @($taskOptions | ForEach-Object { '-D' + $_ + '=OFF' })
& cmake @taskOffArguments -P $taskGuard
if ($LASTEXITCODE -ne 0) { throw 'OLD_OFF_SETTINGS_REJECTED' }
$taskBuild = [IO.File]::ReadAllText((Join-Path $taskRoot 'CMakeLists.txt'))
if ($taskBuild -match '(?im)^\s*(add_library|add_executable|FetchContent_Declare)\([^\r\n]*(local_ai|LocalAi|llama)' -or
    $taskBuild -match '(?im)^\s*(src|tests)/[^\r\n]*local_ai') {
    throw 'AI_TARGET_OR_SOURCE_REINTRODUCED'
}
[pscustomobject]@{RejectedOn=$taskRejected; AcceptedOff=1; AiTargetDeclarations=0} | ConvertTo-Json -Compress
