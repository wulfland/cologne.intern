## SERVER NAME 	  sp13mpiendl
## Intranet URI	  cologne.intern
## API URI		  app.cologne.intern

# USER: CoreAdmin
# USER: Developer

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
net user /add Developer Cologne123
net localgroup Administrators Developer /add
$strPass = ConvertTo-SecureString -String "Cologne123" -AsPlainText -Force
$developerCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("sp13mpiendl\Developer", $strPass)


################################################################################
write-header "Extend HostFile"
add-hostfilecontent -IPAddress 127.0.0.1 -computer cologne.intern
add-hostfilecontent -IPAddress 127.0.0.1 -computer cologneapp.intern

################################################################################
write-header "Load SharePoint Modules"
Add-PSSnapin "Microsoft.SharePoint.PowerShell"

################################################################################
write-header "Configure SharePoint Installation"
C:\ConfigureDeveloperDesktop\Scripts\ConfigureSharePointFarm.ps1 -localSPFarmAccountName CoreAdmin -localSPFarmAccountPassword Cologne123	

################################################################################
write-header "Set Developer as SecondaryAdmin"
Set-SPSite -Identity "http://sp13mpiendl" -SecondaryOwnerAlias "sp13mpiendl\Developer"

################################################################################
write-header "Configure Alternate Access Mapping"
New-SPAlternateURL http://cologne.intern -Zone "Intranet" -WebApplication "http://sp13mpiendl"

################################################################################
write-header "Configure SharePoint for Apps"
Get-SPServiceInstance | where{$_.GetType().Name -eq "AppManagementServiceInstance" -or $_.GetType().Name -eq "SPSubscriptionSettingsServiceInstance"} | Start-SPServiceInstance
Set-SPAppDomain "app.cologne.intern"
$account = Get-SPManagedAccount "sp13mpiendl\CoreAdmin" 
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
$name.Encode("CN=cologneapp.intern", 0)
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
$cert = (dir Cert:\LocalMachine\my | where {$_.Subject -eq 'CN=cologneapp.intern'})
Export-Certificate -Cert $cert -FilePath C:\Certificates\cologneapp.intern.cer
$certPwd = ConvertTo-SecureString -String "Cologne123" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath C:\Certificates\cologneapp.intern.pfx -Password $certPwd
$certStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store Root, LocalMachine
$certStore.Open("MaxAllowed")
$certStore.Add($cert)
$certStore.Close()

################################################################################
write-header "Create WebSite for ProviderHosted APP"
md -Path C:\CologneApp
cd C:\CologneApp
import-module WebAdministration
cd IIS:\Sites
New-Item iis:\Sites\cologneapp -bindings @{protocol="https";bindingInformation=":443:cologneapp.intern"} -physicalPath c:\CologneApp
$cert = (dir Cert:\LocalMachine\my | where {$_.Subject -eq 'CN=cologneapp.intern'})
cd ..\SslBindings
$cert | new-item 0.0.0.0!443

################################################################################
write-header "Configure SharePoint for Provider Hosted App from cologneapp.intern"
New-SPTrustedRootAuthority -Name "CologneAppIntern" -Certificate 'C:\Certificates\cologneapp.intern.cer'
$realm = Get-SPAuthenticationRealm
$specificIssuerId = "11111111-1111-1111-1111-111111111111"
$fullIssuerIdentifier = $specificIssuerId + '@' + $realm 
New-SPTrustedSecurityTokenIssuer -Name "CologneAppIntern" -Certificate 'C:\Certificates\cologneapp.intern.cer' -RegisteredIssuerName $fullIssuerIdentifier -IsTrustBroker
iisreset
$serviceConfig = Get-SPSecurityTokenServiceConfig
$serviceConfig.AllowOAuthOverHttp = $true
$serviceConfig.Update()

################################################################################
write-header "Set Proxy Rules and StartPage"
$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -path $regKey ProxyEnable -value 1
Set-ItemProperty -path $regKey ProxyServer -value ''
Set-ItemProperty -path $regKey ProxyOverride -value '*.cologne.intern;*.cologneapp.intern'
$regKey = "HKCU:\Software\Microsoft\Internet Explorer\Main"
Set-ItemProperty -path $regKey "Start Page" -value "http://cologne.intern:11111"
$sb = {
	$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
	Set-ItemProperty -path $regKey ProxyEnable -value 1
	Set-ItemProperty -path $regKey ProxyServer -value ''
	Set-ItemProperty -path $regKey ProxyOverride -value '*.cologne.intern;*.cologneapp.intern'
	$regKey = "HKCU:\Software\Microsoft\Internet Explorer\Main"
	Set-ItemProperty -path $regKey "Start Page" -value "http://cologne.intern"
}
Start-Job -Credential $developerCred -ScriptBlock $sb | Wait-Job

################################################################################
write-header "Create Developer SiteCollection"
New-SPSite -Url http://cologne.intern/sites/dev -Template "DEV#0" -Name "Develop" -OwnerAlias sp13mpiendl\Developer

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
if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern'))
{
    $null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern'
}
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern' -Name http -Value 1 -Type DWord
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern' -Name https -Value 1 -Type DWord
if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern'))
{
    $null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern'
}
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern' -Name http -Value 1 -Type DWord
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern' -Name https -Value 1 -Type DWord
if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl'))
{
    $null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl'
}
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl' -Name http -Value 1 -Type DWord
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl' -Name https -Value 1 -Type DWord

$sb = {
	if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern'))
	{
		$null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern'
	}
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern' -Name http -Value 1 -Type DWord
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologne.intern' -Name https -Value 1 -Type DWord
	if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern'))
	{
		$null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern'
	}
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern' -Name http -Value 1 -Type DWord
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\cologneapp.intern' -Name https -Value 1 -Type DWord
	if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl'))
	{
		$null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl'
	}
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl' -Name http -Value 1 -Type DWord
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\sp13mpiendl' -Name https -Value 1 -Type DWord
}
Start-Job -Credential $developerCred -ScriptBlock $sb | Wait-Job

################################################################################
write-header "DONE! RESTART PC"
Restart-Computer -Force