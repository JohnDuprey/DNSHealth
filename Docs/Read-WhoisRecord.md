---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-WhoisRecord

## SYNOPSIS
Reads Whois record data for queried information

## SYNTAX

```
Read-WhoisRecord [-Query] <String> [-Server <String>] [-Port <Object>] [<CommonParameters>]
```

## DESCRIPTION
Connects to top level registrar servers (IANA, ARIN) and performs recursion to find Whois data

## EXAMPLES

### EXAMPLE 1
```
Read-WhoisRecord -Query microsoft.com
```

## PARAMETERS

### -Query
Whois query to perform (e.g.
microsoft.com)

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

### -Server
Whois server to query, defaults to whois.iana.org

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Whois.iana.org
Accept pipeline input: False
Accept wildcard characters: False
```

### -Port
Whois server port, default 43

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 43
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
