---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Test-HttpsCertificate

## SYNOPSIS
Test HTTPS certificate for Domain

## SYNTAX

```
Test-HttpsCertificate [-Domain] <String> [[-Subdomains] <String[]>] [<CommonParameters>]
```

## DESCRIPTION
This function aggregates test results for a domain and subdomains in regards to
HTTPS certificates

## EXAMPLES

### EXAMPLE 1
```
Test-HttpsCertificate -Domain badssl.com -Subdomains expired, revoked
```

## PARAMETERS

### -Domain
Domain to check

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

### -Subdomains
List of subdomains

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: @()
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
