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
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [string]$MacroExpand,

        [Parameter()]
        [string]$RecordType = 'A'
    )

    if (!$script:DnsResolver) {
        Set-DnsResolver
    }

    $Resolver = $script:DnsResolver.Resolver
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

    $x = 0
    $Exception = $null
    do {
        $x++
        try {
            $Results = Invoke-RestMethod -Uri $Uri -Headers $Headers -ErrorAction Stop
        } catch {
            $Exception = $_
            Start-Sleep -Milliseconds 300
        }
    }
    while (-not $Results -and $x -le 3)
    if (!$Results) { throw 'Exception querying resolver {0}: {1}' -f $Resolver.Resolver, $Exception.Exception.Message }

    if ($RecordType -eq 'txt' -and $Results.Answer) {
        if ($Resolver -eq 'Cloudflare' -or $Resolver -eq 'Quad9') {
            $Results.Answer | ForEach-Object {
                $_.data = $_.data -replace '" "'
            }
        }
        $Results.Answer = $Results.Answer | Where-Object { $_.type -eq 16 }
    }

    return $Results
}
