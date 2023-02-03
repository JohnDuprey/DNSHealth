function Get-DomainMacros {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$MacroExpand
    )

    $Macros = @{
        '%{d}' = $Domain
        '%{o}' = $Domain
        '%{h}' = $Domain
        '%{l}' = 'postmaster'
        '%{s}' = 'postmaster@{0}' -f $Domain
        '%{i}' = '1.2.3.4'
    }

    foreach ($Macro in $Macros.Keys) {
        $MacroExpand = $MacroExpand -replace $Macro, $Macros.$Macro
    }

    $MacroExpand
}
