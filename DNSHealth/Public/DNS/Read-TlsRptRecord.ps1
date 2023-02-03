function Read-TlsRptRecord {
    <#
    .SYNOPSIS
    Resolve and validate TLSRPT record
    
    .DESCRIPTION
    Query domain for TLSRPT record (_smtp._tls.domain.com) and parse results. Record is checked for issues.
    
    .PARAMETER Domain
    Domain to process TLSRPT record
    
    .EXAMPLE
    PS> Read-TlsRptRecord -Domain gmail.com

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # Initialize object
    $TlsRptAnalysis = [PSCustomObject]@{
        Domain           = $Domain
        Record           = ''
        Version          = ''
        RuaEntries       = [System.Collections.Generic.List[string]]::new()
        IsValid          = $false
        HasWarnings      = $false
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
    }

    $ValidRuaProtocols = @(
        '^(?<Rua>https:.+)$'
        '^mailto:(?<Rua>.+)$'
    )

    # Validation lists
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    # Validation ranges

    $RecordCount = 0

    $DnsQuery = @{
        RecordType = 'TXT'
        Domain     = "_smtp._tls.$Domain"
    }
    
    # Resolve DMARC record

    $Query = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop

    $RecordCount = 0
    $Query.Answer | Where-Object { $_.data -match '^v=TLSRPTv1' } | ForEach-Object {
        $TlsRtpRecord = $_.data
        $TlsRptAnalysis.Record = $TlsRtpRecord
        $RecordCount++  
    }
    if ($Query.Status -eq 2 -and $Query.AD -eq $false) {
        $ValidationFails.Add('DNSSEC validation failed.') | Out-Null
    }
    if ($Query.Status -ne 0 -or $RecordCount -eq 0) {
        if ($Query.Status -eq 3) {
            $ValidationFails.Add('Record does not exist (NXDOMAIN)') | Out-Null
        }

        else {
            $ValidationFails.Add("$Domain does not have an TLSRPT record") | Out-Null
        }
    }

    elseif ($RecordCount -gt 1) {
        $ValidationFails.Add("$Domain has multiple TLSRPT records") | Out-Null
    }

    # Split DMARC record into name/value pairs
    $TagList = [System.Collections.Generic.List[object]]::new()
    Foreach ($Element in ($TlsRtpRecord -split ';').trim()) {
        $Name, $Value = $Element -split '='
        $TagList.Add(
            [PSCustomObject]@{
                Name  = $Name
                Value = $Value
            }
        ) | Out-Null
    }

    # Loop through name/value pairs and set object properties
    $x = 0
    foreach ($Tag in $TagList) {
        switch ($Tag.Name) {
            'v' {
                # REQUIRED: Version
                if ($x -ne 0) { $ValidationFails.Add('v=TLSRPTv1 must be at the beginning of the record') | Out-Null }
                if ($Tag.Value -ne 'TLSRPTv1') { $ValidationFails.Add("Version must be TLSRPTv1 - found $($Tag.Value)") | Out-Null }
                $TlsRptAnalysis.Version = $Tag.Value
            }
            'rua' {
                $RuaMatched = $false
                $RuaEntries = $Tag.Value -split ','
                foreach ($RuaEntry in $RuaEntries) {
                    foreach ($Protocol in $ValidRuaProtocols) {
                        if ($RuaEntry -match $Protocol) {
                            $TlsRptAnalysis.RuaEntries.Add($Matches.Rua) | Out-Null
                            $RuaMatched = $true
                        }
                    }
                }
                if ($RuaMatched) {
                    $ValidationPasses.Add('Aggregate reports are being sent') | Out-Null
                }
                
                else {
                    $ValidationWarns.Add('Aggregate reports are not being sent') | Out-Null
                    $TlsRptAnalysis.HasWarnings = $true
                }
            }
        }
        $x++
    }

    if ($RecordCount -gt 0) {
        # Check for missing record tags and set defaults
            
        if ($RecordCount -gt 1) {
            $ValidationWarns.Add('Multiple TLSRPT records detected, this may cause unexpected behavior.') | Out-Null
            $TlsRptAnalysis.HasWarnings = $true
        }
        
        $ValidationWarnCount = ($Test.ValidationWarns | Measure-Object).Count
        $ValidationFailCount = ($Test.ValidationFails | Measure-Object).Count
        if ($ValidationFailCount -eq 0 -and $ValidationWarnCount -eq 0) {
            $ValidationPasses.Add('TLSRPT record is valid') | Out-Null
            $TlsRptAnalysis.IsValid = $true
        }
    }

    # Add the validation lists
    $TlsRptAnalysis.ValidationPasses = $ValidationPasses
    $TlsRptAnalysis.ValidationWarns = $ValidationWarns
    $TlsRptAnalysis.ValidationFails = $ValidationFails

    # Return MTA-STS analysis
    $TlsRptAnalysis
}
