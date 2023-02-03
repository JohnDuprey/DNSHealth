function Resolve-DnsHttpsQuery {
    <#
    .SYNOPSIS
    Resolves DNS record using DoH JSON query
    
    .DESCRIPTION
    This function uses Google or Cloudflare DoH REST APIs to resolve DNS records
    
    .PARAMETER Domain
    Domain to query
    
    .PARAMETER RecordType
    Type of record - Examples: A, CNAME, MX, TXT
    
    .EXAMPLE
    PS> Resolve-DnsHttpsQuery -Domain google.com -RecordType A
    
    name        type TTL data
    ----        ---- --- ----
    google.com.    1  30 142.250.80.110
    
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [string]$MacroExpand,
        
        [Parameter()]
        [string]$RecordType = 'A'
    )

    if (!$script:DnsResolver) {
        Set-DnsResolver
    }
    
    $BaseUri = $script:DnsResolver.BaseUri
    $QueryTemplate = $script:DnsResolver.QueryTemplate

    $Headers = @{
        'accept' = 'application/dns-json'
    }

    if ($MacroExpand) {
        $Domain = Get-DomainMacros -MacroExpand $MacroExpand -Domain $Domain
        Write-Verbose "Macro expand: $Domain"
    }

    $Uri = $QueryTemplate -f $BaseUri, $Domain, $RecordType

    $Results = Invoke-RestMethod -Uri $Uri -Headers $Headers -ErrorAction Stop
    
    if ($Resolver -eq 'Cloudflare' -or $Resolver -eq 'Quad9' -and $RecordType -eq 'txt' -and $Results.Answer) {
        $Results.Answer | ForEach-Object {
            $_.data = $_.data -replace '"' -replace '\s+', ' '
        }
        $Results.Answer = $Results.Answer | Where-Object { $_.type -eq 16 } 
    }
    
    return $Results
}
