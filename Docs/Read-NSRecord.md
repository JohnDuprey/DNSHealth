---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-NSRecord

## SYNOPSIS
Reads NS records for domain

## SYNTAX

```
Read-NSRecord [-Domain] <String> [<CommonParameters>]
```

## DESCRIPTION
Queries DNS servers to get NS records and returns in PSCustomObject list

## EXAMPLES

### EXAMPLE 1
```
Read-NSRecord -Domain gmail.com
```

## PARAMETERS

### -Domain
Domain to query

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
