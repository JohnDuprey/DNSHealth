---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Resolve-DnsHttpsQuery

## SYNOPSIS
Resolves DNS record using DoH JSON query

## SYNTAX

```
Resolve-DnsHttpsQuery [-Domain] <String> [[-MacroExpand] <String>] [[-RecordType] <String>]
 [<CommonParameters>]
```

## DESCRIPTION
This function uses Google or Cloudflare DoH REST APIs to resolve DNS records

## EXAMPLES

### EXAMPLE 1
```
Resolve-DnsHttpsQuery -Domain google.com -RecordType A
```

name        type TTL data
----        ---- --- ----
google.com. 
1  30 142.250.80.110

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

### -MacroExpand
{{ Fill MacroExpand Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RecordType
Type of record - Examples: A, CNAME, MX, TXT

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: A
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
