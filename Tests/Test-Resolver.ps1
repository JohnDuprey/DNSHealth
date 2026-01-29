param(
    $Count = 1000
)

$DomainList = (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt') -split "`n"
$RandomDomains = $DomainList | Where-Object { $_ } | Get-Random -Count $Count


$Jobs = $RandomDomains | ForEach-Object -Parallel {
    Import-Module '..\Output\DNSHealth\DNSHealth.psd1'
    $Resolvers = @('Google', 'Cloudflare')
    foreach ($Resolver in $Resolvers) {
        $Start = Get-Date
        try {
            Set-DnsResolver -Resolver $Resolver
            $Result = Resolve-DnsHttpsQuery -Domain $_
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
            Resolver = $Resolver
            Result   = $Result
            Success  = $Success
            TimeSpan = $TimeSpan
        }
    }
} -ThrottleLimit 10 -AsJob

$Results = $Jobs | Wait-Job | Receive-Job

$Groups = $Results | Group-Object -Property Resolver

foreach ($Group in $Groups) {
    $ResolverResult = $Group.Group
    $Status = $ResolverResult | Group-Object -Property Success
    $Total = $Group.Count
    $SuccessCount = ($Status | Where-Object { $_.Name -eq $true }).Count
    $FailCount = ($Status | Where-Object { $_.Name -eq $false }).Count
    $AverageSeconds = ($ResolverResult.TimeSpan | Measure-Object -Average TotalSeconds).Average

    [PSCustomObject]@{
        Resolver       = $Group.Name
        Total          = $Total
        Success        = $SuccessCount
        Failure        = $FailCount
        AverageSeconds = $AverageSeconds
    }
}
