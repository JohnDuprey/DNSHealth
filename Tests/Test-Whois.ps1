Param(
    $Count = 100
)

$DomainList = (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt') -split "`n"
$RandomDomains = $DomainList | Where-Object { $_ } | Get-Random -Count $Count


$Jobs = $RandomDomains | ForEach-Object -Parallel {
    Import-Module '..\Output\DNSHealth\DNSHealth.psd1'
    $Start = Get-Date
    try {
        $Result = Read-WhoisRecord $_
        $Success = $true
    }

    catch {
        $Result = $_.Exception
        $Success = $false
    }
    $End = Get-Date
    $TimeSpan = New-TimeSpan -Start $Start -End $End

    [pscustomobject]@{
        Domain   = $_
        Result   = $Result
        Success  = $Success
        TimeSpan = $TimeSpan
    }

} -ThrottleLimit 10 -AsJob

$Results = $Jobs | Wait-Job | Receive-Job
$Results