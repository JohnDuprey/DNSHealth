---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-SpfRecord

## SYNOPSIS
Reads SPF record for specified domain

## SYNTAX

### Lookup (Default)
```
Read-SpfRecord -Domain <String> [-Level <String>] [-ExpectedInclude <String>] [<CommonParameters>]
```

### Manual
```
Read-SpfRecord [-Domain <String>] -Record <String> [-Level <String>] [-ExpectedInclude <String>]
 [<CommonParameters>]
```

## DESCRIPTION
Uses Get-GoogleDNSQuery to obtain TXT records for domain, searching for v=spf1 at the beginning of the record
Also parses include records and obtains their SPF as well

## EXAMPLES

### EXAMPLE 1
```
Read-SpfRecord -Domain gmail.com
```

Domain           : gmail.com
Record           : v=spf1 redirect=_spf.google.com
RecordCount      : 1
LookupCount      : 4
AllMechanism     : ~
ValidationPasses : {Expected SPF record was included, No PermError detected in SPF record}
ValidationWarns  : {}
ValidationFails  : {SPF record should end in -all to prevent spamming}
RecordList       : {@{Domain=_spf.google.com; Record=v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all;           RecordCount=1; LookupCount=4; AllMechanism=~; ValidationPasses=System.Collections.ArrayList; ValidationWarns=System.Collections.ArrayList; ValidationFails=System.Collections.ArrayList; RecordList=System.Collections.ArrayList; TypeLookups=System.Collections.ArrayList; IPAddresses=System.Collections.ArrayList; PermError=False}}
TypeLookups      : {}
IPAddresses      : {}
PermError        : False

## PARAMETERS

### -Domain
Domain to obtain SPF record for

```yaml
Type: String
Parameter Sets: Lookup
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: String
Parameter Sets: Manual
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Record
{{ Fill Record Description }}

```yaml
Type: String
Parameter Sets: Manual
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Level
{{ Fill Level Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Parent
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExpectedInclude
{{ Fill ExpectedInclude Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Author: John Duprey

## RELATED LINKS
