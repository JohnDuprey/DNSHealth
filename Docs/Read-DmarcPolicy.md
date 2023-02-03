---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-DmarcPolicy

## SYNOPSIS
Resolve and validate DMARC policy

## SYNTAX

```
Read-DmarcPolicy [-Domain] <String> [<CommonParameters>]
```

## DESCRIPTION
Query domain for DMARC policy (_dmarc.domain.com) and parse results.
Record is checked for issues.

## EXAMPLES

### EXAMPLE 1
```
Read-DmarcPolicy -Domain gmail.com
```

Domain           : gmail.com
Record           : v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com
Version          : DMARC1
Policy           : none
SubdomainPolicy  : quarantine
Percent          : 100
DkimAlignment    : r
SpfAlignment     : r
ReportFormat     : afrf
ReportInterval   : 86400
ReportingEmails  : {mailauth-reports@google.com}
ForensicEmails   : {}
FailureReport    : 0
ValidationPasses : {Aggregate reports are being sent}
ValidationWarns  : {Policy is not being enforced, Subdomain policy is only partially enforced with quarantine, Failure report option 0 will only generate a report on both SPF and DKIM misalignment.
It is recommended to set this value to 1}
ValidationFails  : {}

## PARAMETERS

### -Domain
Domain to process DMARC policy

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
