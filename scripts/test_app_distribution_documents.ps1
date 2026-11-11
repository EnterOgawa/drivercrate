#requires -Version 7.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'app_distribution_documents.ps1')
$sample = '<img src="src/app/icon.png">' + "`n" +
    '![画面](docs/images/main.png)' + "`n" + '[ガイド](docs/user-guide.md#起動)' + "`n" +
    '[ライセンス](LICENSE) [公式](https://github.com/EnterOgawa/drivercrate/releases)'
$converted = ConvertTo-AppDistributionReadme -Readme $sample -Version '1.0.5'
$expected = '<img src="https://raw.githubusercontent.com/EnterOgawa/drivercrate/v1.0.5/src/app/icon.png">' + "`n" +
    '![画面](https://raw.githubusercontent.com/EnterOgawa/drivercrate/v1.0.5/docs/images/main.png)' + "`n" +
    '[ガイド](https://github.com/EnterOgawa/drivercrate/blob/v1.0.5/docs/user-guide.md#起動)' + "`n" +
    '[ライセンス](LICENSE) [公式](https://github.com/EnterOgawa/drivercrate/releases)'
if ($converted -cne $expected) { throw 'DISTRIBUTION_LINKS_MISMATCH' }
if ((ConvertTo-AppDistributionReadme -Readme '' -Version '1.0.5') -cne '') { throw 'EMPTY_README_MISMATCH' }
foreach ($version in @('01.0.5','1.0.5-beta','1.0.5/evil','65536.0.0','1.0','1.0.0.0')) {
    $rejected = $false
    try { $null = ConvertTo-AppDistributionReadme -Readme $sample -Version $version } catch {
        if ($_.Exception.Message -cne 'APP_DISTRIBUTION_VERSION_REJECTED') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'INVALID_VERSION_ACCEPTED' }
}
Write-Output 'App distribution documents: 8 assertions, failures: 0'
