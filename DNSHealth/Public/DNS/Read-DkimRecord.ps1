function Read-DkimRecord {
    <#
    .SYNOPSIS
    Read DKIM record from DNS

    .DESCRIPTION
    Validates DKIM records on a domain a selector

    .PARAMETER Domain
    Domain to check

    .PARAMETER Selectors
    Selector records to check

    .PARAMETER MxLookup
    Lookup record based on MX

    .EXAMPLE
    PS> Read-DkimRecord -Domain example.com -Selector test

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter()]
        [System.Collections.Generic.List[string]]$Selectors = @()
    )

    $MXRecord = $null
    $MinimumSelectorPass = 0
    $SelectorPasses = 0

    $DkimAnalysis = [PSCustomObject]@{
        Domain           = $Domain
        Selectors        = $Selectors
        MailProvider     = ''
        Records          = [System.Collections.Generic.List[object]]::new()
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
    }

    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    # MX lookup, check for defined selectors
    try {
        $MXRecord = Read-MXRecord -Domain $Domain
        foreach ($Selector in $MXRecord.Selectors) {
            try {
                $Selectors.Add($Selector) | Out-Null
            }

            catch { Write-Verbose $_.Exception.Message }
        }
        $DkimAnalysis.MailProvider = $MXRecord.MailProvider
        if ($MXRecord.MailProvider.PSObject.Properties.Name -contains 'MinimumSelectorPass') {
            $MinimumSelectorPass = $MXRecord.MailProvider.MinimumSelectorPass
        }
        $DkimAnalysis.Selectors = $Selectors
    }

    catch { Write-Verbose $_.Exception.Message }

    # Get unique selectors
    $Selectors = $Selectors | Sort-Object -Unique

    if (($Selectors | Measure-Object | Select-Object -ExpandProperty Count) -gt 0) {
        foreach ($Selector in $Selectors) {
            if (![string]::IsNullOrEmpty($Selector)) {
                # Initialize object
                $DkimRecord = [PSCustomObject]@{
                    Selector         = ''
                    Record           = ''
                    Version          = ''
                    PublicKey        = ''
                    PublicKeyInfo    = ''
                    KeyType          = ''
                    Flags            = ''
                    Notes            = ''
                    HashAlgorithms   = ''
                    ServiceType      = ''
                    Granularity      = ''
                    UnrecognizedTags = [System.Collections.Generic.List[object]]::new()
                }

                $DnsQuery = @{
                    RecordType = 'TXT'
                    Domain     = "$Selector._domainkey.$Domain"
                }

                try {
                    $QueryResults = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop
                }

                catch {
                    $Message = "{0}`r`n{1}" -f $_.Exception.Message, ($DnsQuery | ConvertTo-Json)
                    throw $Message
                }
                if ([string]::IsNullOrEmpty($Selector)) { continue }

                if ($QueryResults.Status -eq 2 -and $QueryResults.AD -eq $false) {
                    $ValidationFails.Add('DNSSEC validation failed.') | Out-Null
                }
                if ($QueryResults -eq '' -or $QueryResults.Status -ne 0) {
                    if ($QueryResults.Status -eq 3) {
                        if ($MinimumSelectorPass -eq 0) {
                            $ValidationFails.Add("$Selector - The selector record does not exist for this domain.") | Out-Null
                        }
                    }

                    else {
                        $ValidationFails.Add("$Selector - DKIM record is missing, check the selector and try again") | Out-Null
                    }
                    $Record = ''
                }

                else {
                    $QueryData = ($QueryResults.Answer).data | Where-Object { $_ -match '(v=|k=|t=|p=)' }
                    if (( $QueryData | Measure-Object).Count -gt 1) {
                        $Record = $QueryData[-1]
                    }

                    else {
                        $Record = $QueryData
                    }
                }
                $DkimRecord.Selector = $Selector

                if ($null -eq $Record) { $Record = '' }
                $DkimRecord.Record = $Record

                # Split DKIM record into name/value pairs
                $TagList = [System.Collections.Generic.List[object]]::new()
                Foreach ($Element in ($Record -split ';')) {
                    if ($Element -ne '') {
                        $Name, $Value = $Element.trim() -split '='
                        $TagList.Add(
                            [PSCustomObject]@{
                                Name  = $Name
                                Value = $Value
                            }
                        ) | Out-Null
                    }
                }

                # Loop through name/value pairs and set object properties
                $x = 0
                foreach ($Tag in $TagList) {
                    if ($x -eq 0 -and $Tag.Value -ne 'DKIM1') { $ValidationFails.Add("$Selector - The record must being with 'v=DKIM1'.") | Out-Null }

                    switch ($Tag.Name) {
                        'v' {
                            # REQUIRED: Version
                            if ($x -ne 0) { $ValidationFails.Add("$Selector - The record must being with 'v=DKIM1'.") | Out-Null }
                            $DkimRecord.Version = $Tag.Value
                        }
                        'p' {
                            # REQUIRED: Public Key
                            if ($Tag.Value -ne '') {
                                $DkimRecord.PublicKey = "-----BEGIN PUBLIC KEY-----`n {0}`n-----END PUBLIC KEY-----" -f $Tag.Value
                                $DkimRecord.PublicKeyInfo = Get-RsaPublicKeyInfo -EncodedString $Tag.Value
                            }

                            else {
                                if ($MXRecord.MailProvider.Name -eq 'Null') {
                                    $ValidationPasses.Add("$Selector - DKIM configuration is valid for a Null MX record configuration.") | Out-Null
                                }

                                else {
                                    $ValidationFails.Add("$Selector - There is no public key specified for this DKIM record or the key is revoked.") | Out-Null
                                }
                            }
                        }
                        'k' {
                            $DkimRecord.KeyType = $Tag.Value
                        }
                        't' {
                            $DkimRecord.Flags = $Tag.Value
                        }
                        'n' {
                            $DkimRecord.Notes = $Tag.Value
                        }
                        'h' {
                            $DkimRecord.HashAlgorithms = $Tag.Value
                        }
                        's' {
                            $DkimRecord.ServiceType = $Tag.Value
                        }
                        'g' {
                            $DkimRecord.Granularity = $Tag.Value
                        }
                        default {
                            $DkimRecord.UnrecognizedTags.Add($Tag) | Out-Null
                        }
                    }
                    $x++
                }

                if ($Record -ne '') {
                    if ($DkimRecord.KeyType -eq '') { $DkimRecord.KeyType = 'rsa' }

                    if ($DkimRecord.HashAlgorithms -eq '') { $DkimRecord.HashAlgorithms = 'all' }

                    $UnrecognizedTagCount = $UnrecognizedTags | Measure-Object | Select-Object -ExpandProperty Count
                    if ($UnrecognizedTagCount -gt 0) {
                        $TagString = ($UnrecognizedTags | ForEach-Object { '{0}={1}' -f $_.Tag, $_.Value }) -join ', '
                        $ValidationWarns.Add("$Selector - $UnrecognizedTagCount urecognized tag(s) were detected in the DKIM record. This can cause issues with some mailbox providers. Tags: $TagString")
                    }
                    if ($DkimRecord.Flags -eq 'y') {
                        $ValidationWarns.Add("$Selector - The flag 't=y' indicates that this domain is testing mode currently. If DKIM is fully deployed, this flag should be changed to t=s unless subdomaining is required.") | Out-Null
                    }

                    if ($DkimRecord.PublicKeyInfo.SignatureAlgorithm -ne $DkimRecord.KeyType -and $MXRecord.MailProvider.Name -ne 'Null') {
                        $ValidationWarns.Add("$Selector - Key signature algorithm $($DkimRecord.PublicKeyInfo.SignatureAlgorithm) does not match $($DkimRecord.KeyType)") | Out-Null
                    }

                    if ($DkimRecord.PublicKeyInfo.KeySize -lt 1024 -and $MXRecord.MailProvider.Name -ne 'Null') {
                        $ValidationFails.Add("$Selector - Key size is less than 1024 bit, found $($DkimRecord.PublicKeyInfo.KeySize).") | Out-Null
                    }

                    else {
                        if ($MXRecord.MailProvider.Name -ne 'Null') {
                            $ValidationPasses.Add("$Selector - DKIM key validation succeeded.") | Out-Null
                        }
                        $SelectorPasses++
                    }

                    if (($ValidationFails | Measure-Object | Select-Object -ExpandProperty Count) -eq 0) {
                        $ValidationPasses.Add("$Selector - No errors detected with DKIM record.") | Out-Null
                    }
                }
            ($DkimAnalysis.Records).Add($DkimRecord) | Out-Null
            }
        }
    }
    if (($DkimAnalysis.Records | Measure-Object | Select-Object -ExpandProperty Count) -eq 0 -and [string]::IsNullOrEmpty($DkimAnalysis.Selectors)) {
        $ValidationWarns.Add('No DKIM selectors provided, set them in the domain options.') | Out-Null
    }

    if ($MinimumSelectorPass -gt 0 -and $SelectorPasses -eq 0) {
        $ValidationFails.Add(('{0} DKIM record(s) found. The minimum number of valid records ({1}) was not met.' -f $SelectorPasses, $MinimumSelectorPass)) | Out-Null
    }

    elseif ($MinimumSelectorPass -gt 0 -and $SelectorPasses -ge $MinimumSelectorPass) {
        $ValidationPasses.Add(('Minimum number of valid DKIM records were met {0}/{1}.' -f $SelectorPasses, $MinimumSelectorPass))
    }

    # Collect validation results
    $DkimAnalysis.ValidationPasses = @($ValidationPasses)
    $DkimAnalysis.ValidationWarns = @($ValidationWarns)
    $DkimAnalysis.ValidationFails = @($ValidationFails)

    # Return analysis
    $DkimAnalysis
}
