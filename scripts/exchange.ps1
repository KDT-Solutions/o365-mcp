# Long-lived Exchange Online worker for one customer organization.
# Line 1 on stdin: connection settings. Every further line: one request.
# Replies are single lines prefixed with the marker; anything else on stdout is ignored by the caller.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$marker = '@@M365@@'

function Send-Reply($reply) {
    [Console]::Out.WriteLine($marker + (ConvertTo-Json -InputObject $reply -Depth 6 -Compress))
}

# Mailboxes are addressed by Entra object ID or by SMTP address; both are validated by the caller and again here.
function Resolve-Mailbox($p) {
    if ($p.target) {
        return Get-EXOMailbox -ExternalDirectoryObjectId ([guid]::Parse($p.target)).ToString() -Properties RecipientTypeDetails,ExternalDirectoryObjectId
    }
    if ($p.mailbox -notmatch '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$') { throw 'Invalid mailbox' }
    return Get-EXOMailbox -Identity $p.mailbox -Properties RecipientTypeDetails,ExternalDirectoryObjectId
}

function Get-CalendarFolder($address) {
    # The default calendar folder name is localized ("Kalender", "Calendar", ...), so look it up by type.
    $folder = Get-EXOMailboxFolderStatistics -Identity $address -FolderScope Calendar | Where-Object { $_.FolderType -eq 'Calendar' } | Select-Object -First 1
    if (-not $folder) { throw 'Calendar folder not found' }
    return $address + ':' + ($folder.FolderPath -replace '/', '\')
}

$connected = $false
try {
    $settings = [Console]::In.ReadLine() | ConvertFrom-Json
    Import-Module ExchangeOnlineManagement
    $password = ConvertTo-SecureString ([IO.File]::ReadAllText($settings.password_file).TrimEnd("`r", "`n")) -AsPlainText -Force
    Connect-ExchangeOnline -AppId $settings.client_id -Organization $settings.organization -CertificateFilePath $settings.certificate -CertificatePassword $password -ShowBanner:$false | Out-Null
    $connected = $true
    Send-Reply @{ ok = $true }

    while ($null -ne ($line = [Console]::In.ReadLine())) {
        try {
            $p = $line | ConvertFrom-Json
            if ($p.target) { $target = ([guid]::Parse($p.target)).ToString() }
            switch ($p.action) {
                'list_mailboxes' {
                    $result = @(Get-EXOMailbox -ResultSize 100 -Properties RecipientTypeDetails,ExternalDirectoryObjectId |
                        Select-Object DisplayName,PrimarySmtpAddress,RecipientTypeDetails,ExternalDirectoryObjectId)
                }
                'get_mailbox' {
                    $result = Resolve-Mailbox $p | Select-Object DisplayName,PrimarySmtpAddress,RecipientTypeDetails,ExternalDirectoryObjectId
                }
                'mailbox_permissions' {
                    $mbx = Resolve-Mailbox $p
                    $address = $mbx.PrimarySmtpAddress.ToString()
                    $full = @(Get-EXOMailboxPermission -Identity $address | Where-Object {
                            -not $_.IsInherited -and $_.User -notlike 'NT AUTHORITY\*' -and $_.User -notlike 'S-1-5-*' } |
                        Select-Object @{n='User';e={$_.User.ToString()}}, @{n='AccessRights';e={($_.AccessRights | ForEach-Object { $_.ToString() }) -join ','}})
                    $sendAs = @(Get-EXORecipientPermission -Identity $address | Where-Object { $_.Trustee -notlike 'NT AUTHORITY\*' } |
                        Select-Object @{n='Trustee';e={$_.Trustee.ToString()}}, @{n='AccessRights';e={($_.AccessRights | ForEach-Object { $_.ToString() }) -join ','}})
                    $calendar = Get-CalendarFolder $address
                    $calendarRights = @(Get-EXOMailboxFolderPermission -Identity $calendar |
                        Select-Object @{n='User';e={$_.User.ToString()}}, @{n='AccessRights';e={($_.AccessRights | ForEach-Object { $_.ToString() }) -join ','}})
                    $result = @{ mailbox = $address; display_name = $mbx.DisplayName; type = $mbx.RecipientTypeDetails.ToString()
                                 full_access = $full; send_as = $sendAs; calendar_folder = $calendar; calendar = $calendarRights }
                }
                'set_mailbox_permission' {
                    $address = (Resolve-Mailbox $p).PrimarySmtpAddress.ToString()
                    $trustee = [string]$p.trustee
                    if ($trustee -notmatch '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$') { throw 'Invalid trustee' }
                    $add = $p.add -eq $true
                    switch ($p.right) {
                        'full_access' {
                            if ($add) { Add-MailboxPermission -Identity $address -User $trustee -AccessRights FullAccess -InheritanceType All -AutoMapping:($p.automapping -eq $true) -Confirm:$false | Out-Null }
                            else { Remove-MailboxPermission -Identity $address -User $trustee -AccessRights FullAccess -InheritanceType All -Confirm:$false | Out-Null }
                        }
                        'send_as' {
                            if ($add) { Add-RecipientPermission -Identity $address -Trustee $trustee -AccessRights SendAs -Confirm:$false | Out-Null }
                            else { Remove-RecipientPermission -Identity $address -Trustee $trustee -AccessRights SendAs -Confirm:$false | Out-Null }
                        }
                        'calendar' {
                            $calendar = Get-CalendarFolder $address
                            $existing = $null
                            try { $existing = Get-EXOMailboxFolderPermission -Identity $calendar -User $trustee -ErrorAction Stop } catch { $existing = $null }
                            if ($add) {
                                if ($p.role -notin @('Reviewer', 'Author', 'Editor')) { throw 'Invalid calendar role' }
                                if ($existing) { Set-MailboxFolderPermission -Identity $calendar -User $trustee -AccessRights $p.role -Confirm:$false | Out-Null }
                                else { Add-MailboxFolderPermission -Identity $calendar -User $trustee -AccessRights $p.role -Confirm:$false | Out-Null }
                            } elseif ($existing) {
                                Remove-MailboxFolderPermission -Identity $calendar -User $trustee -Confirm:$false | Out-Null
                            }
                        }
                        default { throw 'Unsupported right' }
                    }
                    $result = @{ success = $true; mailbox = $address; trustee = $trustee; right = $p.right; added = $add
                                 notice = 'Requested. Re-read permissions with get_mailbox_permissions to verify; Outlook may take time to show mapped mailboxes.' }
                }
                'convert_shared' {
                    $mailbox = Resolve-Mailbox $p
                    Set-Mailbox -Identity $mailbox.PrimarySmtpAddress.ToString() -Type Shared -Confirm:$false | Out-Null
                    $result = @{ success = $true; external_directory_object_id = $target; requested_type = 'Shared'; notice = 'Conversion requested. Re-read mailbox to verify; licensing and retention must be checked separately.' }
                }
                default { throw 'Unsupported action' }
            }
            Send-Reply @{ ok = $true; result = $result }
        } catch {
            # Do not leak tokens, customer output or PowerShell exception internals to MCP clients.
            Send-Reply @{ ok = $false }
            # A lost connection ends the worker; the caller starts a fresh one on the next request.
            $state = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' })
            if (-not $state.Count) { exit 1 }
        } finally {
            $result = $null; $target = $null
        }
    }
} catch {
    Send-Reply @{ ok = $false }
    exit 1
} finally {
    if ($connected) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
