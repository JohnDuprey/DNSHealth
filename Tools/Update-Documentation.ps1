Remove-Module DNSHealth
Build-Module
Import-Module .\Output\DNSHealth\DNSHealth.psd1
New-MarkdownHelp -Module DNSHealth -OutputFolder .\Docs\ -Force