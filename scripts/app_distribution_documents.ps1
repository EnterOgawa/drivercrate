#requires -Version 7.0
<#
.SYNOPSIS
Resolves source-relative README images and guides for the same App release.
.DESCRIPTION
Keeps the five-file distribution usable without copying the source docs tree.
No network, version lookup or release creation is performed.
#>
function ConvertTo-AppDistributionReadme {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Readme,
        [Parameter(Mandatory)][string]$Version
    )
    if ($Version -cnotmatch '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$' -or
        @($Version.Split('.') | Where-Object { [uint32]$_ -gt 65535 }).Count -ne 0) {
        throw 'APP_DISTRIBUTION_VERSION_REJECTED'
    }
    $raw = 'https://raw.githubusercontent.com/EnterOgawa/drivercrate/v' + $Version + '/'
    $page = 'https://github.com/EnterOgawa/drivercrate/blob/v' + $Version + '/'
    $content = [regex]::Replace($Readme, '(?<label>!?\[[^\]]*\])\((?<path>(?:docs|src)/[^)]+)\)', {
        param($match)
        $route = if ($match.Groups['label'].Value.StartsWith('!')) { $raw } else { $page }
        $match.Groups['label'].Value + '(' + $route + $match.Groups['path'].Value + ')'
    })
    [regex]::Replace($content, 'src="(?<path>(?:docs|src)/[^"]+)"', {
        param($match)
        'src="' + $raw + $match.Groups['path'].Value + '"'
    })
}
