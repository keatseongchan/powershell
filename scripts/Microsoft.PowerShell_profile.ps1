function ConvertFrom-Jwt {

[cmdletbinding()]
param(
[Parameter(Mandatory = $true)]
[string]$Token,

[Alias(‘ih’)]
[switch]$IncludeHeader
)

# Validate as per https://tools.ietf.org/html/rfc7519
# Access and ID tokens are fine, Refresh tokens will not work
if (!$Token.Contains(“.”) -or !$Token.StartsWith(“eyJ”)) { Write-Error “Invalid token” -ErrorAction Stop }

# Extract header and payload
$tokenheader, $tokenPayload = $Token.Split(“.”).Replace(‘-‘, ‘+’).Replace(‘_’, ‘/’)[0..1]

# Fix padding as needed, keep adding “=” until string length modulus 4 reaches 0
while ($tokenheader.Length % 4) { Write-Debug “Invalid length for a Base-64 char array or string, adding =”; $tokenheader += “=” }
while ($tokenPayload.Length % 4) { Write-Debug “Invalid length for a Base-64 char array or string, adding =”; $tokenPayload += “=” }

Write-Debug “Base64 encoded (padded) header:`n$tokenheader”
Write-Debug “Base64 encoded (padded) payoad:`n$tokenPayload”

# Convert header from Base64 encoded string to PSObject all at once
$header = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json
Write-Debug “Decoded header:`n$header”

# Convert payload to string array
$tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))
Write-Debug “Decoded array in JSON format:`n$tokenArray”

# Convert from JSON to PSObject
$tokobj = $tokenArray | ConvertFrom-Json
Write-Debug “Decoded Payload:”

if($IncludeHeader) {$header}
return $tokobj
}

Function Test-ADAuthentication {
    param($username,$password)
    (new-object directoryservices.directoryentry "",$username,$password).psbase.name -ne $null
}

# ignore cert check - useful to test https url on server
# https://github.com/PowerShell/PowerShell/issues/1945
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
            return true;
        }
 }
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

Function Convert-FromUnixdate ($UnixDate) { 
    [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixDate)) 
}

<#
function prompt
{
    $currentPath = (get-location).Path.replace($HOME, "~")
    
    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsName = $windowsIdentity.Name.Split("\",2)[1]
    
    $host.UI.RawUI.WindowTitle = "{0}: {1}" -f $windowsName, $(Get-Location)
    
    #replace \ with /
    $currentPath = $currentPath -replace "\\", "/"
    $time = get-date -format HHmm
    
    $myprompt = $windowsName + '@' + $env:computername + ' ' + $currentPath
    $mytime = (get-date -format yyyyMMdd.HHmm) + '>'
    if ($nestedpromptlevel -ge 1) { $myprompt += '>' }
"$myprompt
$mytime"
  
  return
}
#>

function test-port {
  Param(
  [string]$ComputerName,
  [int]$port = 5985 # new 'remoting' port
  )

  $ErrorActionPreference = “SilentlyContinue”
  $socket = new-object Net.Sockets.TcpClient
  $socket.Connect($ComputerName, $port)

  if ($socket.Connected) {
    write-output $true
    $socket.Close()
  }
  else {
   write-output $false
  }
  $socket = $null

}
    
# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}

#Import-Module 'C:\tools\poshgit\dahlbyk-posh-git-9bda399\src\posh-git.psd1'

Import-Module D:\GitHub\posh-git\src\posh-git.psd1

$GitPromptSettings.DefaultPromptWriteStatusFirst = $true
$GitPromptSettings.DefaultPromptBeforeSuffix.Text = '`n$([DateTime]::now.ToString("MM-dd HH:mm:ss"))'
$GitPromptSettings.DefaultPromptBeforeSuffix.ForegroundColor = 0x808080
$GitPromptSettings.DefaultPromptSuffix = ' $((Get-History -Count 1).id + 1)$(">" * ($nestedPromptLevel + 1)) '
$GitPromptSettings.DefaultPromptPath = '$($env:COMPUTERNAME) $(Get-PromptPath)'

function Get-UniqueString ([string]$id, $length=13)
{
$hashArray = (new-object System.Security.Cryptography.SHA512Managed).ComputeHash($id.ToCharArray())
-join ($hashArray[1..$length] | ForEach-Object { [char]($_ % 26 + [byte][char]'a') })
}

function Get-Secret {
    param($secureString)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}