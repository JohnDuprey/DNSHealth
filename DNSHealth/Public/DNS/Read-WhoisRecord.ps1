function Read-WhoisRecord {
    <#
    .SYNOPSIS
    Reads Whois record data for queried information
    
    .DESCRIPTION
    Connects to top level registrar servers (IANA, ARIN) and performs recursion to find Whois data
    
    .PARAMETER Query
    Whois query to perform (e.g. microsoft.com)
    
    .PARAMETER Server
    Whois server to query, defaults to whois.iana.org
    
    .PARAMETER Port
    Whois server port, default 43
    
    .EXAMPLE
    PS> Read-WhoisRecord -Query microsoft.com
    
    #>
    [CmdletBinding()]
    param (
        [Parameter (Position = 0, Mandatory = $true)]
        [String]$Query,
        [String]$Server = 'whois.iana.org',
        $Port = 43
    )
    $HasReferral = $false

    # Top level referring servers, IANA, ARIN and AUDA
    $TopLevelReferrers = @('whois.iana.org', 'whois.arin.net', 'whois.auda.org.au')

    # Record Pattern Matching
    $ServerPortRegex = '(?<refsvr>[^:\r\n]+)(:(?<port>\d+))?'
    $ReferralMatch = @{
        'ReferralServer'         = "whois://$ServerPortRegex"
        'Whois Server'           = $ServerPortRegex
        'Registrar Whois Server' = $ServerPortRegex
        'refer'                  = $ServerPortRegex
        'remarks'                = '(?<refsvr>whois\.[0-9a-z\-\.]+\.[a-z]{2,})(:(?<port>\d+))?'
    }

    # List of properties for Registrars
    $RegistrarProps = @(
        'Registrar', 'Registrar Name'
    )

    # Whois parser, generic Property: Value format with some multi-line support and comment handlers
    $WhoisRegex = '^(?!(?:%|>>>|-+|#|[*]))[^\S\n]*(?<PropName>.+?):(?:[\r\n]+)?(:?(?!([0-9]|[/]{2}))[^\S\r\n]*(?<PropValue>.+))?$'

    # TCP Client for Whois
    $Client = New-Object System.Net.Sockets.TcpClient($Server, 43)
    try {
        # Open TCP connection and send query
        $Stream = $Client.GetStream()
        $ReferralServers = [System.Collections.Generic.List[string]]::new()
        $ReferralServers.Add($Server) | Out-Null

        # WHOIS query to send
        $Data = [System.Text.Encoding]::Ascii.GetBytes("$Query`r`n")
        $Stream.Write($Data, 0, $data.length)

        # Read response from stream
        $Reader = New-Object System.IO.StreamReader $Stream, [System.Text.Encoding]::ASCII
        $Raw = $Reader.ReadToEnd()
        
        # Split comments and parse raw whois results
        $data, $comment = $Raw -split '(>>>|\n\s+--)'
        $PropMatches = [regex]::Matches($data, $WhoisRegex, ([System.Text.RegularExpressions.RegexOptions]::MultiLine, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))

        # Hold property count in hashtable for auto increment
        $PropertyCounts = @{}

        # Create ordered list for properties
        $Results = [ordered]@{}
        foreach ($PropMatch in $PropMatches) { 
            $PropName = $PropMatch.Groups['PropName'].value
            if ($Results.Contains($PropName)) {
                $PropertyCounts.$PropName++
                $PropName = '{0}{1}' -f $PropName, $PropertyCounts.$PropName
                $Results[$PropName] = $PropMatch.Groups['PropValue'].value.trim()
            }

            else {
                $Results[$PropName] = $PropMatch.Groups['PropValue'].value.trim()
                $PropertyCounts.$PropName = 0
            }
        }

        foreach ($RegistrarProp in $RegistrarProps) {
            if ($Results.Contains($RegistrarProp)) {
                $Results._Registrar = $Results.$RegistrarProp
                if ($Results.$RegistrarProp -eq 'Registrar') {
                    break  # Means we always favour Registrar if it exists, or keep looking
                }
            }
        }

        # Store raw results and query metadata
        $Results._Raw = $Raw
        $Results._ReferralServers = [System.Collections.Generic.List[string]]::new()
        $Results._Query = $Query
        $LastResult = $Results

        # Loop through keys looking for referral server match
        foreach ($Key in $ReferralMatch.Keys) {
            if ([bool]($Results.Keys -match $Key)) {
                if ($Results.$Key -match $ReferralMatch.$Key) {
                    $ReferralServer = $Matches.refsvr
                    if ($Server -ne $ReferralServer) {
                        if ($Matches.port) { $Port = $Matches.port }
                        else { $Port = 43 }
                        $HasReferral = $true
                        break
                    }
                }
            }
        }

        # Recurse through referrals
        if ($HasReferral) {    
            if ($Server -ne $ReferralServer) {
                $LastResult = $Results
                $Results = Read-WhoisRecord -Query $Query -Server $ReferralServer -Port $Port
                if ($Results._Raw -Match '(No match|Not Found|No Data|The queried object does not exist)' -and $TopLevelReferrers -notcontains $Server) { 
                    $Results = $LastResult 
                }

                else {
                    foreach ($s in $Results._ReferralServers) {
                        $ReferralServers.Add($s) | Out-Null
                    }
                }
                
            }
        } 

        else {
            if ($Results._Raw -Match '(No match|Not Found|No Data)') {
                $first, $newquery = ($Query -split '\.')
                if (($newquery | Measure-Object).Count -gt 1) {
                    $Query = $newquery -join '.'
                    $Results = Read-WhoisRecord -Query $Query -Server $Server -Port $Port
                    foreach ($s in $Results._ReferralServers) {
                        $ReferralServers.Add($s) | Out-Null
                    }
                }
            }
        }
    }

    catch {
        Write-Error $_.Exception.Message
    }
    
    finally {
        IF ($Stream) {
            $Stream.Close()
            $Stream.Dispose()
        }
    }

    # Collect referral server list
    $Results._ReferralServers = $ReferralServers
    
    # Convert to json and back to preserve object order
    $WhoisResults = $Results | ConvertTo-Json | ConvertFrom-Json

    # Return Whois results as PSObject
    $WhoisResults
}
