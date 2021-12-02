<#
.SYNOPSIS
Change to a random password in AD.

.DESCRIPTION
By default, this script get AD username and domain from the current logged in user, prompt
for current password and generate a random password for the user.

AD username/domain can be overriden from command line argument.

Allowing for new password is under consideration.

There is an Auto-Type feature on KeePass that helps with password
change as well.

.NOTES
Author: Keat Chan
#>
param(
    $domain = $env:USERDOMAIN,
    $username = $env:USERNAME,
    $newPassword
)

if (!(Get-Module ActiveDirectory -ListAvailable)) {
    Write-Warning "You need to install ActiveDirectory module"
    "Windows Server:"
    "  Add-WindowsFeature RSAT-AD-PowerShell"
    "Windows 10:"
    "  https://blogs.technet.microsoft.com/ashleymcglone/2016/02/26/install-the-active-directory-powershell-module-on-windows-10/"
    exit 1
}

$currentPassword = Read-Host "What is the current password for $($domain)\$($username)" -AsSecureString

if (!$newPassword) {
    "Generating a random password"
    #Set up random number generator
     $rand = New-Object System.Random
     #Generate a new 10 character password
    1..15 | ForEach { $newPassword = $newPassword + [char]$rand.next(33,127) }
    "Write down the new password: $newPassword"
} else {
    "Using $newPassword"
}

"Continue to change password, control C to stop"

Pause

Set-ADAccountPassword $username -newpassword (convertto-securestring -asplaintext "$newPassword" -force) -oldpassword $currentPassword -server $domain

$newPassword = ""