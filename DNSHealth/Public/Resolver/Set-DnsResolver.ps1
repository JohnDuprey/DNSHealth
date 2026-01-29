function Set-DnsResolver {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [ValidateSet('Google', 'Cloudflare')]
        [string]$Resolver = 'Google'
    )

    if ($PSCmdlet.ShouldProcess($Resolver)) {
        $script:DnsResolver = switch ($Resolver) {
            'Google' {
                [PSCustomObject]@{
                    Resolver      = $Resolver
                    BaseUri       = 'https://dns.google/resolve'
                    QueryTemplate = '{0}?name={1}&type={2}'
                }
            }
            'CloudFlare' {
                [PSCustomObject]@{
                    Resolver      = $Resolver
                    BaseUri       = 'https://cloudflare-dns.com/dns-query'
                    QueryTemplate = '{0}?name={1}&type={2}'
                }
            }
        }
    }
}
