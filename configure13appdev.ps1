Param(
	[string]$spDomain = "cologne.intern",
	[string]$spAppDomain = "app.cologne.intern",
	[string]$appDomain = "cologneapp.intern",
	[string]$coreAdminUserName = "CoreAdmin",
	[string]$coreAdminPassword = "Cologne123",	
    [string]$developerUserName = "Developer",
	[string]$developerPassword = "Cologne123",
	[string]$sslCertPassword = "Cologne123"
)

$machineName = $env:COMPUTERNAME
$coreAdminAccount = "$($machineName)\$($coreAdminUserName)"
$developerAccount = "$($machineName)\$($developerUserName)"
Set-ExecutionPolicy Unrestricted

function write-header($header) {
	write-host "################################################################################" -foregroundcolor "green"
	write-host "##" $header -foregroundcolor "green"
}

function add-hostfilecontent {            
 [CmdletBinding(SupportsShouldProcess=$true)]            
 param (            
  [parameter(Mandatory=$true)]            
  [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]            
  [string]$IPAddress,            
              
  [parameter(Mandatory=$true)]            
  [string]$computer            
 )            
 $file = Join-Path -Path $($env:windir) -ChildPath "system32\drivers\etc\hosts"            
 if (-not (Test-Path -Path $file)){            
   Throw "Hosts file not found"            
 }            
 $data = Get-Content -Path $file             
 $data += "$IPAddress  $computer"            
 Set-Content -Value $data -Path $file -Force -Encoding ASCII             
}

################################################################################
write-header "Disable Loopback check"
New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -Value "1" -PropertyType dword

# Create Developer User
net user /add $developerUserName $developerPassword
net localgroup Administrators $developerUserName /add
$strPass = ConvertTo-SecureString -String $developerPassword -AsPlainText -Force
$developerCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($developerAccount, $strPass)

# Force UserProfile Creation
$browser = Start-Process -FilePath "c:\Program Files\Internet Explorer\iexplore.exe" -Credential $developerCred -ArgumentList "about:blank" -LoadUserProfile
Sleep 15
get-process "IExplore" | stop-process -force

################################################################################
write-header "Enable WinRM"
winrm quickconfig -quiet -force

################################################################################
write-header "Extend HostFile"
add-hostfilecontent -IPAddress 127.0.0.1 -computer $spDomain
add-hostfilecontent -IPAddress 127.0.0.1 -computer $appDomain

################################################################################
write-header "Load SharePoint Modules"
Add-PSSnapin "Microsoft.SharePoint.PowerShell"

################################################################################
write-header "Configure SharePoint Installation"
C:\ConfigureDeveloperDesktop\Scripts\ConfigureSharePointFarm.ps1 -localSPFarmAccountName $coreAdminUserName -localSPFarmAccountPassword $coreAdminPassword

################################################################################
write-header "Set Developer as SecondaryAdmin"
Set-SPSite -Identity "http://$($machineName)" -SecondaryOwnerAlias $developerAccount

################################################################################
write-header "Configure Alternate Access Mapping"
New-SPAlternateURL "http://$($spDomain)" -Zone "Intranet" -WebApplication "http://$($machineName)"

################################################################################
write-header "Configure SharePoint for Apps"
Get-SPServiceInstance | where{$_.GetType().Name -eq "AppManagementServiceInstance" -or $_.GetType().Name -eq "SPSubscriptionSettingsServiceInstance"} | Start-SPServiceInstance
Set-SPAppDomain $spAppDomain
$account = Get-SPManagedAccount $coreAdminAccount 
$appPoolSubSvc = New-SPServiceApplicationPool -Name SPSettingsServiceAppPool -Account $account
$appPoolAppSvc = New-SPServiceApplicationPool -Name SPAppServiceAppPool -Account $account
$appSubSvc = New-SPSubscriptionSettingsServiceApplication –ApplicationPool $appPoolSubSvc –Name SettingsServiceApp –DatabaseName SettingsServiceDB
$proxySubSvc = New-SPSubscriptionSettingsServiceApplicationProxy –ServiceApplication $appSubSvc
$appAppSvc = New-SPAppManagementServiceApplication -ApplicationPool $appPoolAppSvc -Name AppServiceApp -DatabaseName AppServiceDB
$proxyAppSvc = New-SPAppManagementServiceApplicationProxy -ServiceApplication $appAppSvc
Set-SPAppSiteSubscriptionName -Name "app" -Confirm:$false

################################################################################
write-header "Create Certificates for SSL of Provider Hosted App"
$name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
$name.Encode("CN=$($appDomain)", 0)
$key = new-object -com "X509Enrollment.CX509PrivateKey.1"
$key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
$key.KeySpec = 1
$key.Length = 1024
$key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
$key.MachineContext = 1
$key.ExportPolicy = 1
$key.Create()
$serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
$ekuoids.add($serverauthoid)
$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
$ekuext.InitializeEncode($ekuoids)
$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
$cert.InitializeFromPrivateKey(2, $key, "")
$cert.Subject = $name
$cert.Issuer = $cert.Subject
$cert.NotBefore = get-date
$cert.NotAfter = $cert.NotBefore.AddDays(365)
$cert.X509Extensions.Add($ekuext)
$cert.Encode()
$enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
$enrollment.InitializeFromRequest($cert)
$certdata = $enrollment.CreateRequest(0)
$enrollment.InstallResponse(2, $certdata, 0, "")
md -Path C:\Certificates
$cert = (dir Cert:\LocalMachine\my | where {$_.Subject -eq "CN=$($appDomain)"})
Export-Certificate -Cert $cert -FilePath "C:\Certificates\$($appDomain).cer"
$certPwd = ConvertTo-SecureString -String $sslCertPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "C:\Certificates\$($appDomain).pfx" -Password $certPwd
$certStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store Root, LocalMachine
$certStore.Open("MaxAllowed")
$certStore.Add($cert)
$certStore.Close()

################################################################################
write-header "Create WebSite for ProviderHosted APP"
md -Path C:\App
cd C:\App
import-module WebAdministration
cd IIS:\Sites
New-Item iis:\Sites\app -bindings @{protocol="https";bindingInformation=":443:$($appDomain)"} -physicalPath c:\App
$cert = (dir Cert:\LocalMachine\my | where {$_.Subject -eq "CN=$($appDomain)"})
cd ..\SslBindings
$cert | new-item 0.0.0.0!443

################################################################################
write-header "Configure SharePoint for Provider Hosted App from $($appDomain)"
New-SPTrustedRootAuthority -Name "$($appDomain)" -Certificate "C:\Certificates\$($appDomain).cer"
$realm = Get-SPAuthenticationRealm
$specificIssuerId = "11111111-1111-1111-1111-111111111111"
$fullIssuerIdentifier = $specificIssuerId + '@' + $realm 
New-SPTrustedSecurityTokenIssuer -Name "$($appDomain)" -Certificate "C:\Certificates\$($appDomain).cer" -RegisteredIssuerName $fullIssuerIdentifier -IsTrustBroker
iisreset
$serviceConfig = Get-SPSecurityTokenServiceConfig
$serviceConfig.AllowOAuthOverHttp = $true
$serviceConfig.Update()

################################################################################
write-header "Set Proxy Rules and StartPage"
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\ESCHomePages" "SoftAdmin" -value "http://$($spDomain)"
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\ESCHomePages" "HardAdmin" -value "http://$($spDomain)"
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\ESCHomePages" "HardUser" -value "http://$($spDomain)"
$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -path $regKey ProxyEnable -value 1
Set-ItemProperty -path $regKey ProxyServer -value ''
Set-ItemProperty -path $regKey ProxyOverride -value "*.$($spDomain);*.$($appDomain)"
$regKey = "HKCU:\Software\Microsoft\Internet Explorer\Main"
Set-ItemProperty -path $regKey "Start Page" -value "http://$($spDomain):11111"
Set-ItemProperty -path $regKey "Default_Page_URL" -value "http://$($spDomain):11111"
Set-ItemProperty -path $regKey "First Home Page" -value "http://$($spDomain):11111"
Set-ItemProperty -path $regKey "NoProtectedModeBanner" -value 1
Rundll32 iesetup.dll,IEHardenUser 
Rundll32 iesetup.dll,IEHardenAdmin 
Rundll32 iesetup.dll,IEHardenMachineNow
$sb = {
	param($spDomain, $appDomain)
    $regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -path $regKey ProxyEnable -value 1
    Set-ItemProperty -path $regKey ProxyServer -value ''
    Set-ItemProperty -path $regKey ProxyOverride -value "*.$($spDomain);*.$($appDomain)"
	if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Internet Explorer"))
	{
		$null = New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer"
	}
	if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Internet Explorer\Main"))
	{
		$null = New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\Main"
	}
    $regKey = "HKCU:\Software\Microsoft\Internet Explorer\Main"
	Set-ItemProperty -path $regKey "Start Page" -value "http://$($spDomain)"
    Set-ItemProperty -path $regKey "Default_Page_URL" -value "http://$($spDomain)"
    Set-ItemProperty -path $regKey "First Home Page" -value "http://$($spDomain)"
    Set-ItemProperty -path $regKey "NoProtectedModeBanner" -value 1
    Rundll32 iesetup.dll,IEHardenUser 
    Rundll32 iesetup.dll,IEHardenAdmin 
    Rundll32 iesetup.dll,IEHardenMachineNow
}
Invoke-Command -ComputerName localhost -Credential $developerCred -ScriptBlock $sb -ArgumentList $spDomain,$appDomain

################################################################################
write-header "Create Developer SiteCollection"
New-SPSite -Url "http://$($spDomain)/sites/dev" -Template "DEV#0" -Name "Develop" -OwnerAlias $developerAccount

################################################################################
write-header "Install Tools"

iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
choco install procexp
choco install Console2
choco install 7zip.install
choco install git.install
choco install GoogleChrome
choco install FireFox
choco install Fiddler4
choco install nodejs.install
choco install tfs2013powertools
choco install visualstudio2013-webessentials.vsix
choco install SublimeText3

################################################################################
write-header "Install NPM Modules"
cd 'C:\Program Files\nodejs\'
.\npm install azure-cli -g
.\npm install grunt -g
.\npm install gulp -g
.\npm install bower -g

################################################################################
write-header "Set Intranet Zone"
if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)"))
{
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)"
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)" -Name http -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)" -Name https -Value 1 -Type DWord
if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)"))
{
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)"
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)" -Name http -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)" -Name https -Value 1 -Type DWord
if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)"))
{
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)"
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)" -Name http -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)" -Name https -Value 1 -Type DWord

$sb = {
	param($spDomain, $appDomain, $machineName)
	if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)"))
	{
		$null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)"
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)" -Name http -Value 1 -Type DWord
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($spDomain)" -Name https -Value 1 -Type DWord
	if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)"))
	{
		$null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)"
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)" -Name http -Value 1 -Type DWord
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($appDomain)" -Name https -Value 1 -Type DWord
	if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)"))
	{
		$null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)"
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)" -Name http -Value 1 -Type DWord
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($machineName)" -Name https -Value 1 -Type DWord
}
Invoke-Command -ComputerName localhost -Credential $developerCred -ScriptBlock $sb -ArgumentList $spDomain, $appDomain, $machineName

################################################################################
write-header "DONE! RESTART PC"
Restart-Computer -Force