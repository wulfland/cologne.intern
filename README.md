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

### Users
- **sp13mpiendl\CoreAdmin** - For work in central administration and maintaince
- **sp13mpiendl\Developer** - For developing and deploying sharepoint hosted and provider hosted applications

### Url
- http://cologne.intern:11111 - SharePoint 2013 central administration
- http://cologne.intern - Default SharePoint Site
- http://cologne.intern/sites/dev - SiteCollection with DeveloperSite Template
- https://cologneapp.intern - IIS WebSite for Provider Hosted App

### Certificates
- "CN=cologneapp.intern" in C:\Certificates (already register for "https://cologneapp.intern" and in SharePoint)

## SharePoint Apps
- IssuerId: 11111111-1111-1111-1111-111111111111
- Prefix: app
- Domain: app.cologne.intern
