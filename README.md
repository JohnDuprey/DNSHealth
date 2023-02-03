# DNSHealth Module
[![Downloads]][Gallery] ![Build] ![Publish]

<!-- References -->
[Downloads]: https://img.shields.io/powershellgallery/dt/DNSHealth
[Gallery]: https://www.powershellgallery.com/packages/DNSHealth/
[Build]: https://img.shields.io/github/actions/workflow/status/johnduprey/DNSHealth/psscriptanalyzer.yml?branch=main&label=PSScriptAnalyzer
[Publish]: https://img.shields.io/github/actions/workflow/status/johnduprey/DNSHealth/psscriptanalyzer.yml?label=PSGallery

This is the PowerShell module for the CyberDrain Improved Partner Portal DNS checks

For more information about CIPP, check out the website https://cipp.app

# Instructions

### Prerequisites

- PowerShell 7 or later

#### Module Installation ([PowerShell Gallery](https://www.powershellgallery.com/packages/DNSHealth))
```powershell
Install-Module DNSHealth
```

# Cmdlet Help
## Policies
- [Read-DmarcPolicy](./Docs/Read-DmarcPolicy.md)
- [Read-MtaStsPolicy](./Docs/Read-MtaStsPolicy.md)
## Records
- [Read-DkimRecord](./Docs/Read-DkimRecord.md)
- [Read-MtaStsRecord](./Docs/Read-MtaStsRecord.md)
- [Read-MXRecord](./Docs/Read-MXRecord.md)
- [Read-NSRecord](./Docs/Read-NSRecord.md)
- [Read-SpfRecord](./Docs/Read-SpfRecord.md)
- [Read-TlsRptRecord](./Docs/Read-TlsRptRecord.md)
- [Read-WhoisRecord](./Docs/Read-WhoisRecord.md)
## Resolver
- [Resolve-DnsHttpsQuery](./Docs/Resolve-DnsHttpsQuery.md)
- [Set-DnsResolver](./Docs/Set-DnsResolver.md)
## Tests
- [Test-DNSSEC](./Docs/Test-DNSSEC.md)
- [Test-HttpsCertificate](./Docs/Test-HttpsCertificate.md)
- [Test-MtaSts](./Docs/Test-MtaSts.md)
