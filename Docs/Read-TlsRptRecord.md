---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-TlsRptRecord

## SYNOPSIS
Resolve and validate TLSRPT record

## SYNTAX

```
Read-TlsRptRecord [-Domain] <String> [<CommonParameters>]
```

## DESCRIPTION
Query domain for TLSRPT record (_smtp._tls.domain.com) and parse results.
Record is checked for issues.

## EXAMPLES

### EXAMPLE 1
```
Read-TlsRptRecord -Domain gmail.com
```

## PARAMETERS

### -Domain
Domain to process TLSRPT record

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
