function Read-MXRecord {
    <#
    .SYNOPSIS
    Reads MX records for domain

    .DESCRIPTION
    Queries DNS servers to get MX records and returns in PSCustomObject list with Preference and Hostname

    .PARAMETER Domain
    Domain to query

    .EXAMPLE
    PS> Read-MXRecord -Domain gmail.com

    Preference Hostname
    ---------- --------
       5 gmail-smtp-in.l.google.com.
      10 alt1.gmail-smtp-in.l.google.com.
      20 alt2.gmail-smtp-in.l.google.com.
      30 alt3.gmail-smtp-in.l.google.com.
      40 alt4.gmail-smtp-in.l.google.com.

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )
    $MXResults = [PSCustomObject]@{
        Domain           = ''
        Records          = [System.Collections.Generic.List[object]]::new()
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
        MailProvider     = ''
        ExpectedInclude  = ''
        Selectors        = ''
    }
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    $DnsQuery = @{
        RecordType = 'mx'
        Domain     = $Domain
    }

    $NoMxValidation = 'There are no mail exchanger records for this domain. If you do not want to receive mail for this domain use a Null MX record of . with a priority 0 (RFC 7505).'

    $MXResults.Domain = $Domain

    try {
        $Result = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop
    }

    catch { $Result = $null }
    if ($Result.Status -eq 2 -and $Result.AD -eq $false) {
        $ValidationFails.Add('DNSSEC validation failed.') | Out-Null
    }

    elseif ($Result.Status -ne 0 -or -not ($Result.Answer)) {
        if ($Result.Status -eq 3) {
            $ValidationFails.Add($NoMxValidation) | Out-Null
            $MXResults.MailProvider = Get-Content "$($MyInvocation.MyCommand.Module.ModuleBase)\MailProviders\Null.json" | ConvertFrom-Json
            $MXResults.Selectors = $MXRecords.MailProvider.Selectors
        }

        else {
            $ValidationFails.Add($NoMxValidation) | Out-Null
            $MXResults.MailProvider = Get-Content "$($MyInvocation.MyCommand.Module.ModuleBase)\MailProviders\Null.json" | ConvertFrom-Json
            $MXResults.Selectors = $MXRecords.MailProvider.Selectors
        }
        $MXRecords = $null
    }

    else {
        $MXRecords = $Result.Answer | ForEach-Object {
            $Priority, $Hostname = $_.Data.Split(' ')
            try {
                [PSCustomObject]@{
                    Priority = [int]$Priority
                    Hostname = $Hostname
                }
            }

            catch { Write-Verbose $_.Exception.Message }
        }
        $ValidationPasses.Add('Mail exchanger records record(s) are present for this domain.') | Out-Null
        $MXRecords = $MXRecords | Sort-Object -Property Priority

        # Attempt to identify mail provider based on MX record
        if (Test-Path "$($MyInvocation.MyCommand.Module.ModuleBase)\MailProviders") {
            $ReservedVariables = @{
                'DomainNameDashNotation' = $Domain -replace '\.', '-'
            }
            if ($MXRecords.Hostname -eq '') {
                $ValidationFails.Add($NoMxValidation) | Out-Null
                $MXResults.MailProvider = Get-Content "$($MyInvocation.MyCommand.Module.ModuleBase)\MailProviders\Null.json" | ConvertFrom-Json
            }

            else {
                $ProviderList = Get-ChildItem "$($MyInvocation.MyCommand.Module.ModuleBase)\MailProviders" -Exclude '_template.json' | ForEach-Object {
                    try { Get-Content $_ | ConvertFrom-Json -ErrorAction Stop }
                    catch { Write-Verbose $_.Exception.Message }
                }
                foreach ($Record in $MXRecords) {
                    $ProviderMatched = $false
                    foreach ($Provider in $ProviderList) {
                        try {
                            if ($Record.Hostname -match $Provider.MxMatch) {
                                $MXResults.MailProvider = $Provider
                                if (($Provider.SpfReplace | Measure-Object | Select-Object -ExpandProperty Count) -gt 0) {
                                    $ReplaceList = [System.Collections.Generic.List[string]]::new()
                                    foreach ($Var in $Provider.SpfReplace) {
                                        if ($ReservedVariables.Keys -contains $Var) {
                                            $ReplaceList.Add($ReservedVariables.$Var) | Out-Null
                                        }

                                        else {
                                            $ReplaceList.Add($Matches.$Var) | Out-Null
                                        }
                                    }

                                    $ExpectedInclude = $Provider.SpfInclude -f ($ReplaceList -join ', ')
                                }

                                else {
                                    $ExpectedInclude = $Provider.SpfInclude
                                }

                                # Set ExpectedInclude and Selector fields based on provider details
                                $MXResults.ExpectedInclude = $ExpectedInclude
                                $MXResults.Selectors = $Provider.Selectors
                                $ProviderMatched = $true
                                break
                            }
                        }

                        catch { Write-Verbose $_.Exception.Message }
                    }
                    if ($ProviderMatched) {
                        break
                    }
                }
            }
        }
        $MXResults.Records = $MXRecords
    }
    $MXResults.ValidationPasses = @($ValidationPasses)
    $MXResults.ValidationFails = @($ValidationFails)
    $MXResults.Records = @($MXResults.Records)
    $MXResults
}
