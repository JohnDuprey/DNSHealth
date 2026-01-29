function Initialize-MailProviders {
    <#
    .SYNOPSIS
    Initializes the custom mail providers dictionary if it doesn't exist

    .DESCRIPTION
    Internal function to ensure the CustomMailProviders script variable exists.
    Called by mail provider management functions.
    #>
    [CmdletBinding()]
    param()

    if (-not (Get-Variable -Name 'CustomMailProviders' -Scope Script -ErrorAction SilentlyContinue)) {
        Set-Variable -Name 'CustomMailProviders' -Value ([System.Collections.Generic.Dictionary[string, object]]::new()) -Scope Script
        Write-Verbose 'Initialized CustomMailProviders dictionary in script scope'
    }
}
