function Test-MtaSts {
    <#
    .SYNOPSIS
    Perform MTA-STS and TLSRPT checks

    .DESCRIPTION
    Retrieve MTA-STS record, policy and TLSRPT record

    .PARAMETER Domain
    Domain to process

    .EXAMPLE
    PS> Test-MtaSts -Domain gmail.com

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # MTA-STS test object
    $MtaSts = [PSCustomObject]@{
        Domain           = $Domain
        StsRecord        = (Read-MtaStsRecord -Domain $Domain)
        StsPolicy        = (Read-MtaStsPolicy -Domain $Domain)
        TlsRptRecord     = (Read-TlsRptRecord -Domain $Domain)
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
    }

    # Validation lists
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    # Check results for each test
    if ($MtaSts.StsRecord.IsValid) { $ValidationPasses.Add('MTA-STS Record is valid') | Out-Null }
    else { $ValidationFails.Add('MTA-STS Record is not valid') | Out-Null }
    if ($MtaSts.StsRecord.HasWarnings) { $ValidationWarns.Add('MTA-STS Record has warnings') | Out-Null }

    if ($MtaSts.StsPolicy.IsValid) { $ValidationPasses.Add('MTA-STS Policy is valid') | Out-Null }
    else { $ValidationFails.Add('MTA-STS Policy is not valid') | Out-Null }
    if ($MtaSts.StsPolicy.HasWarnings) { $ValidationWarns.Add('MTA-STS Policy has warnings') | Out-Null }

    if ($MtaSts.TlsRptRecord.IsValid) { $ValidationPasses.Add('TLSRPT Record is valid') | Out-Null }
    else { $ValidationFails.Add('TLSRPT Record is not valid') | Out-Null }
    if ($MtaSts.TlsRptRecord.HasWarnings) { $ValidationWarns.Add('TLSRPT Record has warnings') | Out-Null }

    # Aggregate validation results
    $MtaSts.ValidationPasses = $ValidationPasses
    $MtaSts.ValidationWarns = $ValidationWarns
    $MtaSts.ValidationFails = $ValidationFails

    $MtaSts
}
