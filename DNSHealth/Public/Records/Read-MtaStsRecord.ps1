function Read-MtaStsRecord {
    <#
    .SYNOPSIS
    Resolve and validate MTA-STS record
    
    .DESCRIPTION
    Query domain for DMARC policy (_mta-sts.domain.com) and parse results. Record is checked for issues.
    
    .PARAMETER Domain
    Domain to process MTA-STS record
    
    .EXAMPLE
    PS> Read-MtaStsRecord -Domain gmail.com

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # Initialize object
    $StsAnalysis = [PSCustomObject]@{
        Domain           = $Domain
        Record           = ''
        Version          = ''
        Id               = ''
        IsValid          = $false
        HasWarnings      = $false
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
    }

    # Validation lists
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    # Validation ranges

    $RecordCount = 0

    $DnsQuery = @{
        RecordType = 'TXT'
        Domain     = "_mta-sts.$Domain"
    }
    
    # Resolve DMARC record

    $Query = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop

    $RecordCount = 0
    $Query.Answer | Where-Object { $_.data -match '^v=STSv1' } | ForEach-Object {
        $StsRecord = $_.data
        $StsAnalysis.Record = $StsRecord
        $RecordCount++  
    }
    if ($Query.Status -eq 2 -and $Query.AD -eq $false) {
        $ValidationFails.Add('DNSSEC validation failed.') | Out-Null
    }
    elseif ($Query.Status -ne 0 -or $RecordCount -eq 0) {
        if ($Query.Status -eq 3) {
            $ValidationFails.Add('Record does not exist (NXDOMAIN)') | Out-Null
        }
        else {
            $ValidationFails.Add("$Domain does not have an MTA-STS record") | Out-Null
        }
    }
    elseif ($RecordCount -gt 1) {
        $ValidationFails.Add("$Domain has multiple MTA-STS records") | Out-Null
    }

    # Split DMARC record into name/value pairs
    $TagList = [System.Collections.Generic.List[object]]::new()
    Foreach ($Element in ($StsRecord -split ';').trim()) {
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
                if ($x -ne 0) { $ValidationFails.Add('v=STSv1 must be at the beginning of the record') | Out-Null }
                if ($Tag.Value -ne 'STSv1') { $ValidationFails.Add("Version must be STSv1 - found $($Tag.Value)") | Out-Null }
                $StsAnalysis.Version = $Tag.Value
            }
            'id' {
                # REQUIRED: Id
                $StsAnalysis.Id = $Tag.Value
            }

        }
        $x++
    }

    if ($RecordCount -gt 0) {
        # Check for missing record tags and set defaults
        if ($StsAnalysis.Id -eq '') { $ValidationFails.Add('Id record is missing') | Out-Null }
        elseif ($StsAnalysis.Id -notmatch '^[A-Za-z0-9]+$') {
            $ValidationFails.Add('STS Record ID must be alphanumeric') | Out-Null 
        }
            
        if ($RecordCount -gt 1) {
            $ValidationWarns.Add('Multiple MTA-STS records detected, this may cause unexpected behavior.') | Out-Null
            $StsAnalysis.HasWarnings = $true
        }
        
        $ValidationWarnCount = ($Test.ValidationWarns | Measure-Object).Count
        $ValidationFailCount = ($Test.ValidationFails | Measure-Object).Count
        if ($ValidationFailCount -eq 0 -and $ValidationWarnCount -eq 0) {
            $ValidationPasses.Add('MTA-STS record is valid') | Out-Null
            $StsAnalysis.IsValid = $true
        }
    }

    # Add the validation lists
    $StsAnalysis.ValidationPasses = @($ValidationPasses)
    $StsAnalysis.ValidationWarns = @($ValidationWarns)
    $StsAnalysis.ValidationFails = @($ValidationFails)

    # Return MTA-STS analysis
    $StsAnalysis
}
