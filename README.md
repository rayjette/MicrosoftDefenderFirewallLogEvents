# MicrosoftDefenderFirewallLogEvents
The MicrosoftDefenderFirewallLogEvents module lets you work with Microsoft Defender Firewall log events from PowerShell.  Events can be retrieved and filtered based on specified criteria.

## Installing the module
Installing a PowerShell module is as simple as copying the module to the correct directory.  To get a list of directory were the module can go run the following from PowerShell: $env:psmodulepath.  For the rest of this I will assume the module will be installed in the user's profile.

Create the following path: C:\Users\<user_name>\Documents\PowerShell\Modules\MicrosoftDefenderFirewallLogEvents.  Copy or move MicrosoftDefenderFirewallLogEvents.psm1 into the new directory.

You can see if the module was installed correctly by running the following in PowerShell:
Get-Module -ListAvailable
You should see the MicrosoftDefenderFirewallLogEvents modules

## Enable Logging
Microsoft Defender Firewall logging is not enabled by default.  It can be enabled as explained in [Configure the Windows Defender Firewall with Advanced Security Log](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/configure-the-windows-firewall-log). 

## Example use
Get all events from the log file<br>
*Get-MicrosoftDefenderFirewallEvents*<br>

Get events from a log file configured to use a non-default directory or a saved log file<br>
*Get-MicrosoftDefenderFirewallEvents -FilePath \\someserver\share\firewall.log*<br><br>

Get events where the source port is 50638 and the destination port is 443<br>
*Get-MicrosoftDefenderFirewallEvents -SourcePort 50638 -DestinationPort 443*<br><br>

Get events from and to specific IP address<br>
*Get-MicrosoftDefenderFirewallEvents -SourceIP 10.1.1.2 -DestinationIP -10.2.1.8*<br><br>

Get the last 1 hour of events<br>
*Get-MicrosoftDefenderFirewallEvents -After (Get-Date).addhours(-1)*<br><br>

Get events between 12:00pm and 1:00pm on 11/10/2022<br>
*Get-MicrosoftDefenderFirewallEvents -After '11/10/2022 12:00pm' -Before '11/10/2022 1:00pm'*<br><br>

Get events by action taken (allow, drop)<br>
*Get-MicrosoftDefenderFirewallEvents -Action drop*<br>
*Get-MicrosoftDefenderFirewallEvents -Action allow*<br><br>

Get events about received traffic direction<br>
*Get-MicrosoftDefenderFirewallEvents -Direction receive*<br>
*Get-MicrosoftDefenderFirewallEvents -Direction send*<br><br>

Get events by protocol<br>
*Get-MicrosoftDefenderFirewallEvents -Protocol tcp*<br>
*Get-MicrosoftDefenderFirewallEvents -Protocol udp*<br>
*Get-MicrosoftDefenderFirewallEvents -Protocol icmp*