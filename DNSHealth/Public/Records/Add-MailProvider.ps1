function Add-MailProvider {
    <#
    .SYNOPSIS
    Adds a custom mail provider configuration

    .DESCRIPTION
    Adds or updates a custom mail provider configuration that can be used for mail provider detection.
    Custom providers are stored in module scope and take precedence over built-in providers.

    .PARAMETER Name
    The name of the mail provider

    .PARAMETER MxMatch
    Regular expression pattern to match against MX record hostnames. Can use named capture groups for dynamic SPF includes.

    .PARAMETER SpfInclude
    The SPF include domain for this provider. Use {0}, {1}, etc. for string formatting with SpfReplace values.

    .PARAMETER SpfReplace
    Array of variable names to replace in SpfInclude. Can reference named capture groups from MxMatch or reserved variables like 'DomainNameDashNotation'.

    .PARAMETER Selectors
    Array of default DKIM selector names for this provider

    .PARAMETER MinimumSelectorPass
    Minimum number of DKIM selectors that must pass validation

    .PARAMETER MxComment
    URL to documentation for MX record configuration

    .PARAMETER SpfComment
    URL to documentation for SPF configuration

    .PARAMETER DkimComment
    URL to documentation for DKIM configuration

    .PARAMETER Force
    Overwrites an existing custom provider with the same name

    .EXAMPLE
    PS> Add-MailProvider -Name "Custom Provider" -MxMatch "mail\.customprovider\.com" -SpfInclude "spf.customprovider.com" -Selectors @("selector1", "selector2")

    Adds a simple custom mail provider configuration.

    .EXAMPLE
    PS> Add-MailProvider -Name "Custom Provider" -MxMatch "(?<Prefix>[a-z]{2})-mail\.customprovider\.com" -SpfInclude "{0}.spf.customprovider.com" -SpfReplace @("Prefix") -Selectors @("default")

    Adds a custom provider with dynamic SPF include based on a regex capture group.

    .EXAMPLE
    PS> @{ Name = "Provider1"; MxMatch = "mx\.provider1\.com"; SpfInclude = "spf.provider1.com"; Selectors = @("default") } | Add-MailProvider

    Adds a provider using pipeline input from a hashtable.

    .NOTES
    Custom providers are stored in module scope for the current session.
    They take precedence over built-in providers and work in serverless environments.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$MxMatch,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$SpfInclude = '',

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string[]]$SpfReplace = @(),

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Selectors = @(),

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$MinimumSelectorPass = 1,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$MxComment = '',

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$SpfComment = '',

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$DkimComment = '',

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    begin {
        # Ensure CustomMailProviders is initialized
        Initialize-MailProviders
    }

    process {
        # Check if provider already exists
        if ($script:CustomMailProviders.ContainsKey($Name) -and -not $Force) {
            Write-Error "A custom provider named '$Name' already exists. Use -Force to overwrite."
            return
        }

        $Provider = [PSCustomObject]@{
            Name                = $Name
            MxMatch             = $MxMatch
            SpfInclude          = $SpfInclude
            SpfReplace          = $SpfReplace
            Selectors           = $Selectors
            MinimumSelectorPass = $MinimumSelectorPass
            _MxComment          = $MxComment
            _SpfComment         = $SpfComment
            _DkimComment        = $DkimComment
        }

        if ($PSCmdlet.ShouldProcess($Name, 'Add custom mail provider')) {
            $script:CustomMailProviders[$Name] = $Provider
            Write-Verbose "Custom mail provider '$Name' added to module scope"
            return $Provider
        }
    }
}
