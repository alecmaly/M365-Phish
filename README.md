# Overview

This repo houses my unpolished notes and POCs for bugs I reported to Microsoft regarding Power Platform Priviledge Escalation. 

I have written a blog post with high level details and POC videos @ https://alecmaly.com/blog/2024/02/29/M365-Phish-Power-Platform-Pivoting-and-Privilege-Escalation.html

# POCs
## Internal POC (manual)


Requires:
- 2 M365 user accounts with Power Platform license (E3/E5/etc.): 1 malicious, 1 victim

[malicious user]
1. Download [M365PhishWithDirectoryTraversalPowerApp+Flows.zip](./M365PhishWithDirectoryTraversalPowerApp+Flows.zip)
2. Navigate to https://make.powerapps.com/ with account 1
3. "Import canvas app" + Import the .zip from step (1)  (this may take a couple of minutes)
4. Create new app + new flows + connect account for all connectors
5. Once imported, share the PowerApp with target or Everyone
6. Navigate to https://powerautomate.microsoft.com/ and enable the 2 workflows that were imported
7. Get URL of newly uploaded PowerApp

[victim]
1. Navigate to url of newly created PowerApp (step 7 from 'malicious user')
2. Allow all connections + open the app
3. Validate malicious activity:
- newly created mail rules in Outlook
- sent emails
- Newly created OneDrive file based on POC video. (https://www.youtube.com/watch?v=BP0roo8O0No&t=950s)

[malicious user]
Validate workflow run in https://powerautomate.microsoft.com/ + look at outputs for private teams chats + other flow run details.


## External POC (automated/scripted)

### POC 1: Only upload app

Requires:
- PowerApps open in msedge (or target browser)

```powershell
powershell.exe -ep bypass .\M365_Phish_POC_User_Upload_PowerApp.ps1
```


### POC 2: Upload app & hijack running instances of Teams + Outlook

```powershell
powershell.exe -ep bypass .\M365_Phish_POC_User_PowerApp+Hijack_Outlook+Teams.ps1
```

## [Extra POCs](./extra_POCs) Folder

These scripts are trimmed down to each hijack method to reduce code complexity for individualized use cases.

## Additional Notes:
> Search tokens in the following locations

- Local files can be used instead of hooking the browser:
    - MS Edge:
    ```
    C:\Users\<username>\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb\...
    ```
