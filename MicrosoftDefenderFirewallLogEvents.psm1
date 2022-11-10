#Requires -RunAsAdministrator

<#
.DESCRIPTION
    The MicrosoftDefenderFirewallLogEvents module simplifies the process of working with
    the Microsoft Defender Firewall log file.  Events can be filtered by specified critia.
#>

Function Get-MicrosoftDefenderFirewallEvent {
    <#
    .SYNOPSIS
        Get specified events from a Microsoft Defender Firewall log file.

    .DESCRIPTION
        Get events matching specified criteria from a Microsoft Defender Firewall log file.

    .PARAMETER FilePath
        The path to the firewall log.  If FilePath is not specified the default firewall
        log location of C:\Windows\system32\LogFiles\Firewall\pfirewall.log will be used.

    .PARAMETER SourcePort
        Only show events with this source port.

    .PARAMETER DestinationPort
        Only show events with this destination port.

    .PARAMETER SourceIP
        Only show events with this source ip address.

    .PARAMETER DestinationIP
        Only show events with this destination ip address.

    .PARAMETER Before
        Only show events that happend before this time.

    .PARAMETER After
        Only show events that happened after this time.

    .PARAMETER Action
        Only show events with the specified action.  Action
        can be 'Allow' or 'drop'

    .PARAMETER Direction
        Only show events based on traffic direction.  Direction
        can be 'send' or 'receive'

    .PARAMETER Protocol
        Only show events with the specified protocol.  Accepted
        protocols are 'ICMP', 'TCP' and 'UDP'

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -FilePath .\firewall.log

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -SourcePort 2552

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -DestinationPort 80

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -SourceIP 10.1.1.2

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -DestinationIP 10.40.1.2

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -Before "11/9/2022 12:00pm"

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -After "11/9/2022 1:00pm"

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -Action Drop

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -Direction Receive

    .EXAMPLE
        Get-MicrosoftDefenderFirewallEvent -Protocol TCP

    .INPUTS
        Get-MicrosoftDefenderFirewallEvent does not accept input from the pipeline.

    .OUTPUTS
        System.Management.Automation.PSCustomObject.

    .NOTES
        Author: Raymond Jette
    #>
    [OutputType([System.Management.Automation.PSCustomObject])]
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]
        $FilePath = 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log',

        [String]$SourcePort,

        [String]$DestinationPort,

        [String]$SourceIP,

        [String]$DestinationIP,

        [DateTime]$Before,

        [DateTime]$After,

        [ValidateSet('Allow', 'Drop')]
        $Action,

        [ValidateSet('Receive', 'Send')]
        $Direction,

        [ValidateSet('ICMP', 'TCP', 'UDP')]
        $Protocol
    )

    # Setup parameters to pass to
    # Get-MicrosoftDefenderFirewallFilteredLogEvent
    $filterParams = @{}
    $filterTypes = @('SourcePort', 'DestinationPort', 'SourceIP', 'DestinationIP', 'Before', 
    'After', 'Action', 'Direction', 'Protocol')
    foreach ($filter in $filterTypes) {
        if ($PSBoundParameters.ContainsKey($filter)) {
            $filterParams.add($filter, $PSBoundParameters[$filter])
        }
    }

    # Return the filtered events, from the log file, as PSCustomObjects.
    Get-MicrosoftDefenderFirewallLogEvents -FilePath $FilePath | 
        ConvertFrom-MicrosoftDefenderFirewallLogEvent | 
        Get-MicrosoftDefenderFirewallFilteredLogEvent @filterParams
}

# Helper Functions
#
Function Get-MicrosoftDefenderFirewallLogEvents($FilePath) {
    <#
    .SYNOPSIS
        Returns the text events from the specified log file.
    #>
    if (Test-Path -Path $FilePath -PathType Leaf) {
        Get-Content $FilePath
    } else { throw 'FileName does not exist' }
}

Function ConvertFrom-MicrosoftDefenderFirewallLogEvent {
    <#
    .SYNOPSIS
        Converts a text Microsoft Defender Firewall log event into a PSCustomObject.
    #>
    param (
        [Parameter(ValueFromPipeline)]
        [String]$LogEvent
    )

    BEGIN {
        $regex = '^(?<Date>\d{4}-\d{2}-\d{2}) (?<Time>\d{2}:\d{2}:\d{2}) (?<Action>\w+) '
        $regex += '(?<Proto>\S+) (?<SrcIp>\S+) (?<DstIp>\S+) (?<SrcPort>\S+) (?<DstPort>\S+) '
        $regex += '(?<Size>\S+) (?<tcpflags>\S+) (?<tcpsyn>\S+) (?<tcpack>\S+) (?<tcpwin>\S+) '
        $regex += '(?<IcmpType>\S+) (?<IcmpCode>\S+) (?<Info>\S+) (?<Path>\w+)$'
    }

    PROCESS {
        if ($LogEvent -match $regex) {
            $DateTime = [datetime]($matches.date + ' ' + $matches.time)
            [PSCustomObject]@{
                DateTime = $DateTime
                Action = $matches.action
                Protocol = $matches.proto
                Path = $matches.path
                SrcIp = $matches.srcip
                DstIp = $matches.dstip
                SrcPort = $matches.srcport
                DstPort = $matches.dstport
                Size = $matches.size
                TcpFlags = $matches.tcpflags
                TcpSyn = $matches.tcpsyn
                TcpAck = $matches.tcpack
                TcpWin = $matches.tcpwin
                IcmpType = $matches.icmptype
                IcmpCode = $matches.icmpcode
                Info = $matches.info
            }
        }
    }
}


Function Get-MicrosoftDefenderFirewallFilteredLogEvent {
    <#
        .SYNOPSIS
            Returns only events matching the specified critia.
    #>
    param (
        [Parameter(ValueFromPipeline)]
        $Object,

        [String]$SourcePort,

        [String]$DestinationPort,

        [String]$SourceIP,

        [String]$DestinationIP,

        [DateTime]$Before,

        [DateTime]$After,

        [String]$Action,

        [String]$Direction,

        [String]$Protocol
    )
    BEGIN {
        $filters = @()
        $filter = ''

        if ($PSBoundParameters.ContainsKey('SourcePort')) {
            $filters += '$_.SrcPort -eq $sourcePort'
        }
        if ($PSBoundParameters.ContainsKey('DestinationPort')) {
            $filters += '$_.DstPort -eq $destinationPort'
        }
        if ($PSBoundParameters.ContainsKey('SourceIP')) {
            $filters += '$_.SrcIP -eq $SourceIP'
        }
        if ($PSBoundParameters.ContainsKey('DestinationIP')) {
            $filters += '$_.DstIP -eq $DestinationIP'
        }
        if ($PSBoundParameters.ContainsKey('Before')) {
            $filters += '$_.dateTime -lt $before'
        }
        if ($PSBoundParameters.ContainsKey('After')) {
            $filters += '$_.dateTime -gt $after'
        }
        if ($PSBoundParameters.ContainsKey('Action')) {
            $filters += '$_.Action -eq $Action'
        }
        if ($PSBoundParameters.ContainsKey('Direction')) {
            $filters += '$_.Path -eq $Direction'
        }
        if ($PSBoundParameters.ContainsKey('Protocol')) {
            $filters += '$_.Protocol -eq $Protocol'
        }

        $filter = $filters -join ' -and '
        $sb = [ScriptBlock]::Create($filter)
    }

    PROCESS {
        if ($filter -ne '') {
            $object | Where-Object -FilterScript $sb

        } else {
            $object
        }
    }
}


Export-ModuleMember -Function 'Get-MicrosoftDefenderFirewallEvent'