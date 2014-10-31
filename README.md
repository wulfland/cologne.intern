# cologne.intern - SharePoint 2013 App Development in Azure
==============

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
   `iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/michl86/cologne.intern/master/configure13appdev.ps1'))`
6. Have a break, have a kit-kat (or many of them - because it will take some hours). Script reboots machine when done.
