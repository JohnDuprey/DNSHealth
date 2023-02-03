---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-MtaStsRecord

## SYNOPSIS
Resolve and validate MTA-STS record

## SYNTAX

```
Read-MtaStsRecord [-Domain] <String> [<CommonParameters>]
```

## DESCRIPTION
Query domain for DMARC policy (_mta-sts.domain.com) and parse results.
Record is checked for issues.

## EXAMPLES

### EXAMPLE 1
```
Read-MtaStsRecord -Domain gmail.com
```

## PARAMETERS

### -Domain
Domain to process MTA-STS record

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
