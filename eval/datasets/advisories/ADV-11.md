MyCERT-style ADVISORY ADV-11
Title: WinRAR spoofed-extension exploit sent to trading desks
Sectors affected: stock brokerages and investment firms in Malaysia and Singapore

1.0 Overview
Emails promising "Q4 trading strategies" carry a RAR archive (Strategies_Q4.rar). It exploits CVE-2023-38831 in
RARLAB WinRAR before 6.23: opening what looks like a JPG runs a script with the same name inside a folder.

2.0 Indicators
Sender: research@aseantrade-insights[.]com
Archive MD5: 85451a6ecb9877c8941affbd97a80422
Payload SHA256: 9b1372ffc5947f648bbfea030838e3fa4ecfafe8c8c9bd3317c93787882c7859
C2: hxxps://update[.]tradeview-cdn[.]top/api/beacon

3.0 Recommendation
Update WinRAR to 6.23 or later on all workstations and block .rar attachments at the mail gateway.
