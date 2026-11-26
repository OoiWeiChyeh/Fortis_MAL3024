MyCERT-style ADVISORY ADV-03
Title: Invoice-themed spear-phishing against Malaysian finance teams

1.0 Overview
Since early November, accounts-payable staff at Malaysian financial institutions have received emails
that appear to come from a logistics supplier. The message carries an attachment named Invoice_Nov.zip that
contains a shortcut file. When the user opens it, a hidden PowerShell command downloads a loader and adds a
Run key so it starts at every logon. The loader beacons over HTTPS.

2.0 Indicators
Sender address: billing[@]lintas-freight[.]online
Download URL: hxxps://cdn-lintasfreight[.]site/inv/download.php
C2: telemetry-mx[.]icu (203.0.113[.]200)
Invoice_Nov.zip  MD5 6a75e62e689aff660a2f142cbfd22402
loader.dll       SHA1 63464bb3c69d6008c611bab82884eb354162328b
loader.dll       SHA256 22d4b42456ee671664f7a11c5508986dd882721bc31b0085dd220401012ce0b0
Note: the loader version string is 4.2.0.1 and it reads its config from config.json; neither is an indicator.

3.0 Recommendations
Block the domains and hashes, search mailboxes for the sender, and alert finance staff.
