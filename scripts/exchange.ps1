$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$connected = $false
try {
    $p = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($p.action -notin @('list_mailboxes', 'get_mailbox', 'convert_shared')) { throw 'Unsupported action' }
    if ($p.target) { $target = ([guid]::Parse($p.target)).ToString() }
    Import-Module ExchangeOnlineManagement
    $password = ConvertTo-SecureString ([IO.File]::ReadAllText($p.password_file).TrimEnd("`r", "`n")) -AsPlainText -Force
    Connect-ExchangeOnline -AppId $p.client_id -Organization $p.organization -CertificateFilePath $p.certificate -CertificatePassword $password -ShowBanner:$false | Out-Null
    $connected = $true
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
    }
    $json = ConvertTo-Json -InputObject $result -Depth 6 -Compress
} catch {
    # Do not leak tokens, customer output or PowerShell exception internals to MCP clients.
    [Console]::Error.WriteLine('Exchange operation failed')
    exit 1
} finally {
    if ($connected) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
[Console]::Out.Write($json)
