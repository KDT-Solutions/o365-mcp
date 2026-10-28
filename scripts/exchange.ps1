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
                    $result = Get-EXOMailbox -ExternalDirectoryObjectId $target -Properties RecipientTypeDetails,ExternalDirectoryObjectId |
                        Select-Object DisplayName,PrimarySmtpAddress,RecipientTypeDetails,ExternalDirectoryObjectId
                }
                'convert_shared' {
                    $mailbox = Get-EXOMailbox -ExternalDirectoryObjectId $target -Properties RecipientTypeDetails
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
