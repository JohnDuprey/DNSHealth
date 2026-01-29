function Read-SpfRecord {
    <#
    .SYNOPSIS
    Reads SPF record for specified domain

    .DESCRIPTION
    Uses Get-GoogleDNSQuery to obtain TXT records for domain, searching for v=spf1 at the beginning of the record
    Also parses include records and obtains their SPF as well

    .PARAMETER Domain
    Domain to obtain SPF record for

    .EXAMPLE
    PS> Read-SpfRecord -Domain gmail.com

    Domain           : gmail.com
    Record           : v=spf1 redirect=_spf.google.com
    RecordCount      : 1
    LookupCount      : 4
    AllMechanism     : ~
    ValidationPasses : {Expected SPF record was included, No PermError detected in SPF record}
    ValidationWarns  : {}
    ValidationFails  : {SPF record should end in -all to prevent spamming}
    RecordList       : {@{Domain=_spf.google.com; Record=v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all;           RecordCount=1; LookupCount=4; AllMechanism=~; ValidationPasses=System.Collections.ArrayList; ValidationWarns=System.Collections.ArrayList; ValidationFails=System.Collections.ArrayList; RecordList=System.Collections.ArrayList; TypeLookups=System.Collections.ArrayList; IPAddresses=System.Collections.ArrayList; PermError=False}}
    TypeLookups      : {}
    IPAddresses      : {}
    PermError        : False

    .NOTES
    Author: John Duprey
    #>
    [CmdletBinding(DefaultParameterSetName = 'Lookup')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Lookup')]
        [Parameter(ParameterSetName = 'Manual')]
        [string]$Domain,

        [Parameter(Mandatory = $true, ParameterSetName = 'Manual')]
        [string]$Record,

        [Parameter(ParameterSetName = 'Lookup')]
        [Parameter(ParameterSetName = 'Manual')]
        [string]$Level = 'Parent',

        [Parameter(ParameterSetName = 'Lookup')]
        [Parameter(ParameterSetName = 'Manual')]
        [string]$ExpectedInclude = ''
    )
    $SpfResults = [PSCustomObject]@{
        Domain            = ''
        Record            = ''
        RecordCount       = 0
        LookupCount       = 0
        AllMechanism      = ''
        ValidationPasses  = [System.Collections.Generic.List[string]]::new()
        ValidationWarns   = [System.Collections.Generic.List[string]]::new()
        ValidationFails   = [System.Collections.Generic.List[string]]::new()
        RecordList        = [System.Collections.Generic.List[object]]::new()
        TypeLookups       = [System.Collections.Generic.List[object]]::new()
        Recommendations   = [System.Collections.Generic.List[object]]::new()
        RecommendedRecord = ''
        IPAddresses       = [System.Collections.Generic.List[string]]::new()
        MailProvider      = ''
        Explanation       = ''
        Status            = ''

    }



    # Initialize lists to hold all records
    $RecordList = [System.Collections.Generic.List[object]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $Recommendations = [System.Collections.Generic.List[object]]::new()
    $LookupCount = 0
    $AllMechanism = ''
    $Status = ''
    $RecommendedRecord = ''

    $TypeLookups = [System.Collections.Generic.List[object]]::new()
    $IPAddresses = [System.Collections.Generic.List[string]]::new()

    $DnsQuery = @{
        RecordType = 'TXT'
        Domain     = $Domain
    }

    $NoSpfValidation = 'No SPF record was detected for this domain.'

    # Query DNS for SPF Record
    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Lookup' {
                if ($Domain -eq 'Not Specified') {
                    # don't perform lookup if domain is not specified
                }

                else {
                    $Query = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop
                    if ($Query.Status -eq 2 -and $Query.AD -eq $false) {
                        $ValidationFails.Add('DNSSEC validation failed.') | Out-Null
                    }

                    elseif ($Query.Status -ne 0) {
                        if ($Query.Status -eq 3) {
                            $ValidationFails.Add($NoSpfValidation) | Out-Null
                            $Status = 'permerror'
                        }

                        else {
                            #Write-Host $Query
                            $ValidationFails.Add($NoSpfValidation) | Out-Null
                            $Status = 'temperror'
                        }
                    }

                    else {

                        $Answer = ($Query.answer | Where-Object { $_.data -match '^v=spf1' })
                        $RecordCount = ($Answer.data | Measure-Object).count
                        $Record = $Answer.data
                        if ($RecordCount -eq 0) {
                            $ValidationFails.Add($NoSpfValidation) | Out-Null
                            $Status = 'permerror'
                        }
                        # Check for the correct number of records
                        elseif ($RecordCount -gt 1 -and $Level -eq 'Parent') {
                            $ValidationFails.Add("There must only be one SPF record per domain, we found $RecordCount.") | Out-Null
                            $Recommendations.Add([pscustomobject]@{
                                    Message = 'Delete one of the records beginning with v=spf1'
                                    Match   = ''
                                }) | Out-Null
                            $Status = 'permerror'
                            $Record = $Answer.data[0]
                        }
                    }
                }
            }
            'Manual' {
                if ([string]::IsNullOrEmpty($Domain)) { $Domain = 'Not Specified' }
                $RecordCount = 1
            }
        }
        $SpfResults.Domain = $Domain

        if ($Record -ne '' -and $RecordCount -gt 0) {
            # Split records and parse
            if ($Record -match '^v=spf1(:?\s+(?<Terms>(?![+-~?]all).+?))?(:?\s+(?<AllMechanism>[+-~?]all)(:?\s+(?<Discard>(?!all).+))?)?$') {
                if ($Matches.Terms) {
                    $RecordTerms = $Matches.Terms -split '\s+'
                }

                else {
                    $RecordTerms = @()
                }
                Write-Verbose "########### RECORD: $Record"

                if ($Level -eq 'Parent' -or $Level -eq 'Redirect') {
                    $AllMechanism = $Matches.AllMechanism
                }

                if ($null -ne $Matches.Discard) {
                    if ($Matches.Discard -notmatch '^exp=(?<Domain>.+)$') {
                        $ValidationWarns.Add("The terms '$($Matches.Discard)' are past the all mechanism and will be discarded.") | Out-Null
                        $Recommendations.Add([pscustomobject]@{
                                Message = 'Remove entries following all';
                                Match   = $Matches.Discard
                                Replace = ''
                            }) | Out-Null
                    }

                }

                foreach ($Term in $RecordTerms) {
                    Write-Verbose "TERM $Term"
                    # Redirect modifier
                    if ($Term -match 'redirect=(?<Domain>.+)') {
                        Write-Verbose '-----REDIRECT-----'
                        $LookupCount++
                        if ($Record -match '(?<Qualifier>[+-~?])all') {
                            $ValidationFails.Add('A record with a redirect modifier must not contain an all mechanism. This will result in a failure.') | Out-Null
                            $Status = 'permerror'
                            $Recommendations.Add([pscustomobject]@{
                                    Message = "Remove the 'all' mechanism from this record.";
                                    Match   = '{0}all' -f $Matches.Qualifier
                                    Replace = ''
                                }) | Out-Null
                        }

                        else {
                            # Follow redirect modifier
                            $RedirectedLookup = Read-SpfRecord -Domain $Matches.Domain -Level 'Redirect'
                            if (($RedirectedLookup | Measure-Object).Count -eq 0) {
                                $ValidationFails.Add("$Domain Redirected lookup does not contain a SPF record, this will result in a failure.") | Out-Null
                                $Status = 'permerror'
                            }

                            else {
                                $RecordList.Add($RedirectedLookup) | Out-Null
                                $AllMechanism = $RedirectedLookup.AllMechanism
                                $ValidationFails.AddRange([string[]]$RedirectedLookup.ValidationFails) | Out-Null
                                $ValidationWarns.AddRange([string[]]$RedirectedLookup.ValidationWarns) | Out-Null
                                $ValidationPasses.AddRange([string[]]$RedirectedLookup.ValidationPasses) | Out-Null
                                $IPAddresses.AddRange([string[]]$RedirectedLookup.IPAddresses) | Out-Null
                            }
                        }
                        # Record has been redirected, stop evaluating terms
                        break
                    }

                    # Include mechanism
                    elseif ($Term -match '^(?<Qualifier>[+-~?])?include:(?<Value>.+)$') {
                        if ($Matches.Value -ne $Domain) {
                            $LookupCount++
                            Write-Verbose '-----INCLUDE-----'
                            Write-Verbose "Looking up include $($Matches.Value)"
                            $IncludeLookup = Read-SpfRecord -Domain $Matches.Value -Level 'Include'

                            if ([string]::IsNullOrEmpty($IncludeLookup.Record) -and $Level -eq 'Parent') {
                                Write-Verbose '-----END INCLUDE (SPF MISSING)-----'
                                $ValidationFails.Add("Include lookup for $($Matches.Value) does not contain a SPF record, this will result in a failure.") | Out-Null
                                $Status = 'permerror'
                            } else {
                                Write-Verbose '-----END INCLUDE (SPF FOUND)-----'
                                $RecordList.Add($IncludeLookup) | Out-Null
                                $ValidationFails.AddRange([string[]]$IncludeLookup.ValidationFails) | Out-Null
                                $ValidationWarns.AddRange([string[]]$IncludeLookup.ValidationWarns) | Out-Null
                                $ValidationPasses.AddRange([string[]]$IncludeLookup.ValidationPasses) | Out-Null
                                $IPAddresses.AddRange([string[]]$IncludeLookup.IPAddresses) | Out-Null
                            }
                        } else {
                            Write-Verbose "-----END INCLUDE (INFINITE LOOP -> $Domain SHOULD NOT INCLUDE ITSELF)-----"
                            $ValidationFails.Add("Include lookup for $($Matches.Value) should not exist. It will cause an infinite loop.") | Out-Null
                            $Status = 'permerror'
                        }
                    }

                    # Exists mechanism
                    elseif ($Term -match '^(?<Qualifier>[+-~?])?exists:(?<Value>.+)$') {
                        $LookupCount++
                    }

                    # ip4/ip6 mechanism
                    elseif ($Term -match '^(?<Qualifier>[+-~?])?ip[4,6]:(?<Value>.+)$') {
                        if (-not ($Matches.Qualifier) -or $Matches.Qualifier -eq '+') {
                            $IPAddresses.Add($Matches.Value) | Out-Null
                        }
                    }

                    # Remaining type mechanisms a,mx,ptr
                    elseif ($Term -match '^(?<Qualifier>[+-~?])?(?<RecordType>(?:a|mx|ptr))(?:[:](?<TypeDomain>.+))?$') {
                        $LookupCount++

                        if ($Matches.TypeDomain) {
                            $TypeDomain = $Matches.TypeDomain
                        }

                        else {
                            $TypeDomain = $Domain
                        }

                        if ($TypeDomain -ne 'Not Specified') {
                            try {
                                $TypeQuery = @{ Domain = $TypeDomain; RecordType = $Matches.RecordType }
                                Write-Verbose "Looking up $($TypeQuery.Domain)"
                                $TypeResult = Resolve-DnsHttpsQuery @TypeQuery -ErrorAction Stop
                                if ($Matches.RecordType -eq 'mx') {
                                    $MxCount = 0
                                    if ($TypeResult.Answer) {
                                        foreach ($mx in $TypeResult.Answer.data) {
                                            $MxCount++
                                            $Preference, $MxDomain = $mx -replace '\.$' -split '\s+'
                                            try {
                                                Write-Verbose "MX: Lookup $MxDomain"
                                                $MxQuery = Resolve-DnsHttpsQuery -Domain $MxDomain -ErrorAction Stop
                                                $MxIps = $MxQuery.Answer.data

                                                foreach ($MxIp in $MxIps) {
                                                    $IPAddresses.Add($MxIp) | Out-Null
                                                }

                                                if ($MxCount -gt 10) {
                                                    $ValidationWarns.Add("$Domain - Mechanism 'mx' lookup for $MxDomain has exceeded the 10 A or AAAA record lookup limit (RFC 7208, Section 4.6.4).") | Out-Null
                                                    $TypeResult = $null
                                                    break
                                                }
                                            }

                                            catch {
                                                Write-Verbose $_.Exception.Message
                                                $TypeResult = $null
                                            }
                                        }
                                    }

                                    else {
                                        $ValidationWarns.Add("$Domain - Mechanism 'mx' lookup for $($TypeQuery.Domain) did not have any records") | Out-Null
                                    }
                                }

                                elseif ($Matches.RecordType -eq 'ptr') {
                                    $ValidationWarns.Add("$Domain - The mechanism 'ptr' should not be published in an SPF record (RFC 7208, Section 5.5)")
                                }
                            }

                            catch {
                                $TypeResult = $null
                            }

                            if ($null -eq $TypeResult -or $TypeResult.Status -ne 0) {
                                $Message = "$Domain - Type lookup for the mechanism '$($TypeQuery.RecordType)' did not return any results."
                                switch ($Level) {
                                    'Parent' {
                                        $ValidationFails.Add("$Message") | Out-Null
                                        $Status = 'permerror'
                                    }
                                    'Include' { $ValidationWarns.Add("$Message") | Out-Null }
                                }
                                $Result = $false
                            }

                            else {
                                if ($TypeResult.Answer) {
                                    if ($TypeQuery.RecordType -match 'mx') {

                                        $Result = $TypeResult.Answer | ForEach-Object {
                                            #$LookupCount++
                                            $_.Data.Split(' ')[1]
                                        }
                                    }

                                    else {
                                        $Result = $TypeResult.answer.data
                                    }
                                }
                            }
                            $TypeLookups.Add(
                                [PSCustomObject]@{
                                    Domain     = $TypeQuery.Domain
                                    RecordType = $TypeQuery.RecordType
                                    Result     = $Result
                                }
                            ) | Out-Null

                        }

                        else {
                            $ValidationWarns.Add("No domain was specified and mechanism '$Term' does not have one defined. Specify a domain to perform a lookup on this record.") | Out-Null
                        }

                    }

                    elseif ($null -ne $Term) {
                        $ValidationWarns.Add("$Domain - Unknown term specified '$Term'") | Out-Null
                    }
                }

                # Explanation modifier
                if ($Record -match 'exp=(?<MacroExpand>.+)$') {
                    Write-Verbose '-----EXPLAIN-----'
                    $ExpQuery = @{ Domain = $Domain; MacroExpand = $Matches.MacroExpand; RecordType = 'TXT' }
                    $ExpResult = Resolve-DnsHttpsQuery @ExpQuery -ErrorAction Stop
                    if ($ExpResult.Status -eq 0 -and $ExpResult.Answer.Type -eq 16) {
                        $Explain = @{
                            Record  = $ExpResult.Answer.data
                            Example = Get-DomainMacros -Domain $Domain -MacroExpand $ExpResult.Answer.data
                        }
                    }
                }

                else {
                    $Explain = @{ Example = ''; Record = '' }
                }
            }
        }
    }

    catch {
        Write-Verbose "EXCEPTION: $($_.InvocationInfo.ScriptLineNumber) $($_.Exception.Message)"
    }

    # Lookup MX record for expected include information if not supplied
    if ($Level -eq 'Parent' -and $ExpectedInclude -eq '') {
        try {
            #Write-Information $Domain
            $MXRecord = Read-MXRecord -Domain $Domain
            $SpfResults.MailProvider = $MXRecord.MailProvider
            if ($MXRecord.ExpectedInclude -ne '') {
                $ExpectedInclude = $MXRecord.ExpectedInclude
            }

            if ($MXRecord.MailProvider.Name -eq 'Null') {
                if ($Record -eq 'v=spf1 -all') {
                    $ValidationPasses.Add('This SPF record is valid for a Null MX configuration') | Out-Null
                }

                else {
                    $ValidationFails.Add('This SPF record is not valid for a Null MX configuration. Expected record: "v=spf1 -all"') | Out-Null
                }
            }

            if ($TypeLookups.RecordType -contains 'mx') {
                $Recommendations.Add([pscustomobject]@{
                        Message = "Remove the 'mx' modifier from your record. Check the mail provider documentation for the correct SPF include.";
                        Match   = '\s*([+-~?]?mx)\s+'
                        Replace = ' '
                    }) | Out-Null
            }
        }

        catch { Write-Verbose $_.Exception.Message }
    }

    # Look for expected include record and report pass or fail
    if ($ExpectedInclude -ne '') {
        if ($RecordList.Domain -notcontains $ExpectedInclude) {
            $ExpectedIncludeSpf = Read-SpfRecord -Domain $ExpectedInclude -Level ExpectedInclude
            $ExpectedIPCount = $ExpectedIncludeSpf.IPAddresses | Measure-Object | Select-Object -ExpandProperty Count
            $FoundIPCount = Compare-Object $IPAddresses $ExpectedIncludeSpf.IPAddresses -IncludeEqual | Where-Object -Property SideIndicator -EQ '==' | Measure-Object | Select-Object -ExpandProperty Count
            if ($ExpectedIPCount -eq $FoundIPCount) {
                $ValidationPasses.Add('The expected mail provider IP address ranges were found.') | Out-Null
            }

            else {
                $ValidationFails.Add('The expected mail provider entry was not found in the record.') | Out-Null
                $Recommendations.Add([pscustomobject]@{
                        Message = ("Add 'include:{0} to your record." -f $ExpectedInclude)
                        Match   = '^v=spf1 (.+?)([-~?+]all)?$'
                        Replace = "v=spf1 include:$ExpectedInclude `$1 `$2"
                    }) | Out-Null
            }
        }

        else {
            $ValidationPasses.Add('The expected mail provider entry is part of the record.') | Out-Null
        }
    }

    # Count total lookups
    $LookupCount = $LookupCount + ($RecordList | Measure-Object -Property LookupCount -Sum).Sum

    if ($Domain -ne 'Not Specified') {
        # Check legacy SPF type
        $LegacySpfType = Resolve-DnsHttpsQuery -Domain $Domain -RecordType 'SPF' -ErrorAction Stop
        if ($null -ne $LegacySpfType -and $LegacySpfType -eq 0) {
            $ValidationWarns.Add("The record type 'SPF' was detected, this is legacy and should not be used. It is recommeded to delete this record (RFC 7208 Section 14.1).") | Out-Null
        }
    }
    if ($Level -eq 'Parent' -and $RecordCount -gt 0) {
        # Check for the correct all mechanism
        if ($AllMechanism -eq '' -and $Record -ne '') {
            $ValidationFails.Add("The 'all' mechanism is missing from SPF record, the default is a neutral qualifier (?all).") | Out-Null
            $AllMechanism = '?all'
        }

        if ($AllMechanism -eq '-all') {
            $ValidationPasses.Add('The SPF record ends with a hard fail qualifier (-all). This is best practice and will instruct recipients to discard unauthorized senders.') | Out-Null
        }

        elseif ($AllMechanism -eq '~all') {
            # Check DMARC policy for soft fail
            $DmarcRejectPolicy = $false
            try {
                $DmarcPolicy = Read-DmarcPolicy -Domain $Domain -ErrorAction Stop
                if ($DmarcPolicy.Policy -eq 'reject' -and ($DmarcPolicy.Percent -eq 100 -or $null -eq $DmarcPolicy.Percent)) {
                    $DmarcRejectPolicy = $true
                }
            } catch {
                Write-Verbose "Unable to read DMARC policy: $($_.Exception.Message)"
            }

            if ($DmarcRejectPolicy) {
                $ValidationPasses.Add('The SPF record ends with a soft fail qualifier (~all). With DMARC p=reject at 100%, this is acceptable as DMARC will enforce rejection.') | Out-Null
            } else {
                $ValidationFails.Add('The SPF record should end in -all to prevent spamming.') | Out-Null
                $Recommendations.Add([PSCustomObject]@{
                        Message = "Replace '~all' with '-all' to make a SPF failure result in a hard fail."
                        Match   = '~all'
                        Replace = '-all'
                    }) | Out-Null
            }
        }

        elseif ($Record -ne '') {
            $ValidationFails.Add('The SPF record should end in -all to prevent spamming.') | Out-Null
            $Recommendations.Add([PSCustomObject]@{
                    Message = "Replace '{0}' with '-all' to make a SPF failure result in a hard fail." -f $AllMechanism
                    Match   = [regex]::escape($AllMechanism)
                    Replace = '-all'
                }) | Out-Null
        }

        # SPF lookup count
        if ($LookupCount -ge 9) {
            $SpecificLookupsFound = $false
            foreach ($SpfRecord in $RecordList) {
                if ($SpfRecord.LookupCount -ge 5) {
                    $SpecificLookupsFound = $true
                    $IncludeLookupCount = $SpfRecord.LookupCount + 1
                    $Match = ('[+-~?]?include:{0}' -f $SpfRecord.Domain)
                    $Recommendations.Add([PSCustomObject]@{
                            Message = ("Remove the include modifier for domain '{0}', this adds {1} lookups towards the max of 10. Alternatively, reduce the number of lookups inside this record if you are able to." -f $SpfRecord.Domain, $IncludeLookupCount)
                            Match   = $Match
                            Replace = ''
                        }) | Out-Null
                }
            }
            if (!($SpecificLookupsFound)) {
                $Recommendations.Add([PSCustomObject]@{
                        Message = 'Review include modifiers to ensure that your lookup count stays below 10.'
                        Match   = ''
                    }) | Out-Null
            }
        }

        if ($LookupCount -gt 10) {
            $ValidationFails.Add("Lookup count: $LookupCount/10. The SPF evaluation will fail with a permanent error (RFC 7208 Section 4.6.4).") | Out-Null
            $Status = 'permerror'
        }

        elseif ($LookupCount -ge 9 -and $LookupCount -le 10) {
            $ValidationWarns.Add("Lookup count: $LookupCount/10. Excessive lookups can cause the SPF evaluation to fail (RFC 7208 Section 4.6.4).") | Out-Null
        }

        else {
            $ValidationPasses.Add("Lookup count: $LookupCount/10.") | Out-Null
        }

        # Report pass if no PermErrors are found
        if ($Status -ne 'permerror') {
            $ValidationPasses.Add('No permanent errors detected in the SPF record.') | Out-Null
        }

        # Report pass if no errors are found
        if (($ValidationFails | Measure-Object | Select-Object -ExpandProperty Count) -eq 0) {
            $ValidationPasses.Add('All validation checks passed.') | Out-Null
        }
    }

    # Check recommendations for replacement regexes
    if (($Recommendations | Measure-Object).Count -gt 0) {
        $RecommendedRecord = $Record
        foreach ($Rec in $Recommendations) {
            if ($Rec.Match -ne '') {
                # Replace item in record with recommended
                $RecommendedRecord = $RecommendedRecord -replace $Rec.Match, $Rec.Replace
            }
        }
        # Cleanup extra spaces
        $RecommendedRecord = $RecommendedRecord -replace '\s+', ' '
    }

    # Set SPF result object
    $SpfResults.Record = $Record
    $SpfResults.RecordCount = $RecordCount
    $SpfResults.LookupCount = $LookupCount
    $SpfResults.AllMechanism = $AllMechanism
    $SpfResults.ValidationPasses = @($ValidationPasses)
    $SpfResults.ValidationWarns = @($ValidationWarns)
    $SpfResults.ValidationFails = @($ValidationFails)
    $SpfResults.RecordList = @($RecordList)
    $SpfResults.Recommendations = @($Recommendations)
    $SpfResults.RecommendedRecord = $RecommendedRecord
    $SpfResults.TypeLookups = @($TypeLookups)
    $SpfResults.IPAddresses = @($IPAddresses)
    $SpfResults.Explanation = $Explain
    $SpfResults.Status = $Status


    Write-Verbose "-----END SPF RECORD ($Level)-----"

    # Output SpfResults object
    $SpfResults
}