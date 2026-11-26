MyCERT-style ADVISORY ADV-08
Title: ScreenConnect authentication bypass used to deploy ransomware

1.0 Overview
CVE-2024-1709 is an authentication bypass in ConnectWise ScreenConnect 23.9.7 and earlier. Attackers
create a new administrator account through the setup wizard, then use the remote-support tool itself
to push ransomware to every managed endpoint. Encryption is preceded by deleting volume shadow copies.

2.0 Indicators
- Source: 198.51.100[.]66
- Payload: hxxp://files-sc-support[.]online/agent.exe
- Ransomware SHA256: f0d00baff0ffa23576958677193c1ee6f89bf289c4f7d01ff38d31c01e9090d5
- Ransom note: README_RESTORE.txt (filename only)

3.0 Recommendation
Upgrade on-premises ScreenConnect to 23.9.8 or later immediately and audit administrator accounts.
