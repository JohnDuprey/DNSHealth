# Add-MailProvider

## SYNOPSIS
Adds a custom mail provider configuration.

## SYNTAX

```powershell
Add-MailProvider [-Name] <String> [-MxMatch] <String> [[-SpfInclude] <String>] [[-SpfReplace] <String[]>]
 [[-Selectors] <String[]>] [[-MinimumSelectorPass] <Int32>] [[-MxComment] <String>] [[-SpfComment] <String>]
 [[-DkimComment] <String>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Adds or updates a custom mail provider configuration that can be used for mail provider detection.
Custom providers are stored in the user's profile and take precedence over built-in providers.

## PARAMETERS

### -Name
The name of the mail provider.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MxMatch
Regular expression pattern to match against MX record hostnames. Can use named capture groups for dynamic SPF includes.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SpfInclude
The SPF include domain for this provider. Use {0}, {1}, etc. for string formatting with SpfReplace values.

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

### -SpfReplace
Array of variable names to replace in SpfInclude. Can reference named capture groups from MxMatch or reserved variables like 'DomainNameDashNotation'.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: @()
Accept pipeline input: False
Accept wildcard characters: False
```

### -Selectors
Array of default DKIM selector names for this provider.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: @()
Accept pipeline input: False
Accept wildcard characters: False
```

### -MinimumSelectorPass
Minimum number of DKIM selectors that must pass validation.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 1
Accept pipeline input: False
Accept wildcard characters: False
```

### -MxComment
URL to documentation for MX record configuration.

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

### -SpfComment
URL to documentation for SPF configuration.

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

### -DkimComment
URL to documentation for DKIM configuration.

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

### -Force
Overwrites an existing custom provider with the same name.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## EXAMPLES

### Example 1
```powershell
PS> Add-MailProvider -Name "Custom Provider" -MxMatch "mail\.customprovider\.com" -SpfInclude "spf.customprovider.com" -Selectors @("selector1", "selector2")
```

Adds a simple custom mail provider configuration.

### Example 2
```powershell
PS> Add-MailProvider -Name "Custom Provider" -MxMatch "(?<Prefix>[a-z]{2})-mail\.customprovider\.com" -SpfInclude "{0}.spf.customprovider.com" -SpfReplace @("Prefix") -Selectors @("default")
```

Adds a custom provider with dynamic SPF include based on a regex capture group.

### Example 3
```powershell
PS> Add-MailProvider -Name "Regional Provider" -MxMatch "(?<Region>[a-z]{2})\.mx\.regionalprovider\.com" -SpfInclude "spf-{0}.regionalprovider.com" -SpfReplace @("Region") -Selectors @("mail") -MxComment "https://docs.regionalprovider.com/mx" -SpfComment "https://docs.regionalprovider.com/spf"
```

Adds a provider with regional variations and documentation links.

## NOTES
Custom providers are stored in: `$HOME/.dnshealth/mailproviders/`

Custom providers take precedence over built-in providers with the same name.

## RELATED LINKS
- Get-MailProvider
- Remove-MailProvider
- Read-MXRecord
