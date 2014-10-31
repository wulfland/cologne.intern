# cologne.intern 
## SharePoint 2013 App Development in Azure

Steps to set up an very simple and minimal environment for SharePoint 2013 App Development in Azure

1. Open Azure Portal
2. Create a new virtual machine from gallery (MSDN Account required!)
 - Image: Visual Studio Premium 2013 Update 3 - Windows Server 2012
 - Virtual Machine Name: sp13mpiendl
 - Size: A4
 - New User Name: CoreAdmin
 - New Password: Cologne123
3. Wait until machine is provisioned and running
4. Connect with "sp13mpiendl\CoreAdmin" and "Cologne123"
5. Start PowerShell as Administrator and execute
```
   iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/michl86/cologne.intern/master/configure13appdev.ps1'))
```
Well, now you need to wait some hours. The script will reboot your machine.

## Environment

#### Users
- **sp13mpiendl\CoreAdmin** - For work in central administration and maintaince
- **sp13mpiendl\Developer** - For developing and deploying sharepoint hosted and provider hosted applications

#### Url
- http://cologne.intern:11111 - SharePoint 2013 central administration
- http://cologne.intern - Default SharePoint Site
- http://cologne.intern/sites/dev - SiteCollection with DeveloperSite Template
- https://cologneapp.intern - IIS WebSite for Provider Hosted App

#### Certificates
- "CN=cologneapp.intern" in C:\Certificates (already registered for "https://cologneapp.intern" and in SharePoint)

#### SharePoint Apps
- IssuerId: 11111111-1111-1111-1111-111111111111
- Prefix: app
- Domain: app.cologne.intern

## Develop SharePoint-hosted Applications
1. Connect to your virtual machine as sp13mpiendl\Developer
2. Start Visual Studio 2013 as Administrator and login with your MSDN Account
3. Create new project of type "App for SharePoint"
4. Use "http://cologne.intern" as debugging target and select "SharePoint-hosted"
5. Start your application and cross your fingers!

## Develop Provider-hosted Applications
1. Connect to your virtual machine as sp13mpiendl\Developer
2. Start Visual Studio 2013 as Administrator and login with your MSDN Account
3. Create new project of type "App for SharePoint"
4. Use "http://cologne.intern" as debugging target and select "Provider-hosted"
5. Use a certificate: C:\Certificates\cologneapp.intern.pfx (Password: Cologne123, IssuerId: 11111111-1111-1111-1111-111111111111)
5. Start your application
6. Trust the self signed certificate from Visual Studio
7. Trust you SharePoint App
8. Cross your fingers!
