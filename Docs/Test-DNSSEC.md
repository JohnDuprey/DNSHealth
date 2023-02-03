---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Test-DNSSEC

## SYNOPSIS
Test Domain for DNSSEC validation

## SYNTAX

```
Test-DNSSEC [-Domain] <String> [<CommonParameters>]
```

## DESCRIPTION
Requests dnskey record from DNS and checks response validation (AD=True)

## EXAMPLES

### EXAMPLE 1
```
Test-DNSSEC -Domain example.com
```

Domain           : example.com
ValidationPasses : {example.com - DNSSEC enabled and validated}
ValidationFails  : {}
Keys             : {...}

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
