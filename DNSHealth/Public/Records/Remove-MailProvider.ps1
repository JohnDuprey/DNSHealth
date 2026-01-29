function Remove-MailProvider {
    <#
    .SYNOPSIS
    Removes a custom mail provider configuration

    .DESCRIPTION
    Removes a custom mail provider configuration from module scope.
    Built-in providers cannot be removed using this function.

    .PARAMETER Name
    The name of the custom mail provider to remove

    .PARAMETER Force
    Bypasses confirmation prompts

    .EXAMPLE
    PS> Remove-MailProvider -Name "Custom Provider"

    Removes the custom mail provider named "Custom Provider".

    .EXAMPLE
    PS> Remove-MailProvider -Name "Custom Provider" -Force

    Removes the custom provider without confirmation.

    .NOTES
    This only removes custom providers from module scope.
    Built-in providers cannot be removed.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    process {
        # Ensure CustomMailProviders is initialized
        Initialize-MailProviders
        if (-not $script:CustomMailProviders.ContainsKey($Name)) {
            Write-Error "Custom mail provider '$Name' not found."
            return
        }

        if ($Force -or $PSCmdlet.ShouldProcess($Name, 'Remove custom mail provider')) {
            $script:CustomMailProviders.Remove($Name) | Out-Null
            Write-Verbose "Custom mail provider '$Name' has been removed from module scope."
        }
    }
}
