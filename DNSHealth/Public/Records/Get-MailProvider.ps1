function Get-MailProvider {
    <#
    .SYNOPSIS
    Gets mail provider configurations

    .DESCRIPTION
    Retrieves mail provider configurations including both built-in and custom providers.
    Custom providers from module scope take precedence over built-in providers with the same name.

    .PARAMETER Name
    Optional name filter to retrieve a specific mail provider

    .EXAMPLE
    PS> Get-MailProvider

    Lists all available mail providers (built-in and custom).

    .EXAMPLE
    PS> Get-MailProvider -Name "Microsoft 365"

    Gets the configuration for Microsoft 365 mail provider.

    .NOTES
    Custom providers are stored in module scope for the current session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name = ''
    )

    # Ensure CustomMailProviders is initialized
    Initialize-MailProviders

    $Providers = [System.Collections.Generic.List[object]]::new()

    # Load custom providers first (they take precedence)
    if ($script:CustomMailProviders.Count -gt 0) {
        foreach ($ProviderName in $script:CustomMailProviders.Keys) {
            $Provider = $script:CustomMailProviders[$ProviderName]
            $Provider | Add-Member -NotePropertyName 'Source' -NotePropertyValue 'Custom' -Force
            $Providers.Add($Provider) | Out-Null
        }
    }

    # Load built-in providers
    $ModuleBase = $MyInvocation.MyCommand.Module.ModuleBase
    if (-not $ModuleBase) {
        # Fallback: try to get module base from the loaded module
        $Module = Get-Module DNSHealth
        if ($Module) {
            $ModuleBase = $Module.ModuleBase
        }
    }

    if ($ModuleBase) {
        $BuiltInPath = Join-Path $ModuleBase 'MailProviders'
        Write-Verbose "Looking for providers in: $BuiltInPath"

        if (Test-Path $BuiltInPath) {
            $Files = Get-ChildItem -Path $BuiltInPath -Filter '*.json' | Where-Object { $_.Name -ne '_template.json' }
            Write-Verbose "Found $($Files.Count) provider files"

            $Files | ForEach-Object {
                Write-Verbose "Loading provider from: $($_.Name)"
                try {
                    $Provider = Get-Content $_.FullName | ConvertFrom-Json -ErrorAction Stop

                    # Only add if not already in list (custom providers take precedence)
                    if ($Providers.Name -notcontains $Provider.Name) {
                        $Provider | Add-Member -NotePropertyName 'Source' -NotePropertyValue 'BuiltIn' -Force
                        $Providers.Add($Provider) | Out-Null
                        Write-Verbose "Added provider: $($Provider.Name)"
                    } else {
                        Write-Verbose "Skipped provider: $($Provider.Name) (already exists)"
                    }
                } catch {
                    Write-Warning "Failed to load built-in provider from $($_.FullName): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "MailProviders directory not found at: $BuiltInPath"
        }
    } else {
        Write-Warning 'Could not determine module base path'
    }

    # Filter by name if specified
    if ($Name -ne '') {
        $Providers = $Providers | Where-Object { $_.Name -like $Name }
    }

    return $Providers
}
