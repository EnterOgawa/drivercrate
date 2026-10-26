#requires -Version 7.0
<#
.SYNOPSIS
現在のseed/runtimeを持つv7 packageの非通信検査へ委譲する。
.NOTES
Author: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
旧seed-only配置fixtureは廃止。Task/通信/通常配置は開始しない。
#>
param([Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][string] $FixtureRoot)
& (Join-Path $PSScriptRoot 'test-collector-setup.ps1') -PackageDirectory $PackageDirectory -FixtureRoot $FixtureRoot
