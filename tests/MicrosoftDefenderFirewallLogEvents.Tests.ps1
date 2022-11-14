BeforeAll {
    Import-Module $PSScriptRoot\..\MicrosoftDefenderFirewallLogEvents.psm1

    $logData = @(
        '2022-11-11 16:58:57 ALLOW UDP 172.168.9.2 192.168.1.2 57338 53 0 - - - - - - - SEND'
        '2022-11-11 16:58:57 ALLOW TCP 172.168.9.2 192.168.1.79 63695 445 0 - 0 0 0 - - - SEND'
        '2022-11-11 16:58:59 ALLOW TCP 172.168.9.2 192.168.1.79 63696 445 0 - 0 0 0 - - - SEND'
        '2022-11-11 16:59:09 ALLOW TCP 172.168.9.2 192.168.2.3 63697 135 0 - 0 0 0 - - - SEND'
        '2022-11-11 16:59:09 ALLOW TCP 172.168.9.2 192.168.2.3 63698 55178 0 - 0 0 0 - - - SEND'
    )
}

Describe "Get-MicrosoftDefenderFirewallEvent" {
    BeforeAll {
        Mock -ModuleName MicrosoftDefenderFirewallLogEvents Get-MicrosoftDefenderFirewallLogEvents { $logData }
    }

    Context "Testing with no parameters" {
        It "Returns all events when no parameter is specified" {
            $result = Get-MicrosoftDefenderFirewallEvent
            $result.count | Should -Be 5
        }
    }

    Context "Testing direction parameter" {
        It "Returns all inbound events" {
            $result = Get-MicrosoftDefenderFirewallEvent -Direction Receive
            $result.count | Should -Be 0
        }
    
        It "Returns all outbound events" {
            $result = Get-MicrosoftDefenderFirewallEvent -Direction Send
            $result.count | Should -Be 5
        }
    }

    Context "Testing protocol parameter" {
        It "Returns all ICMP events" {
            $result = Get-MicrosoftDefenderFirewallEvent -Protocol ICMP
            $result.count | Should -Be 0
        }

        It "Returns all TCP events" {
            $result = Get-MicrosoftDefenderFirewallEvent -Protocol TCP
            $result.count | Should -Be 4
        }

        It "Returns all UDP events" {
            $result = Get-MicrosoftDefenderFirewallEvent -Protocol UDP
            $result.count | Should -Be 1
        }
    }

    Context "Testing action parameter" {
        It "Returns all events for allowed traffic" {
            $result = Get-MicrosoftDefenderFirewallEvent -Action Allow
            $result.count | Should -Be 5
        }

        It "Returns all events for dropped traffic" {
            $result = Get-MicrosoftDefenderFirewallEvent -Action Drop
            $result.count | Should -Be 0
        }
    }

    Context "Testing SourcePort parameter" {
        It "Returns all events for traffic with SourcePort" {
            $result = Get-MicrosoftDefenderFirewallEvent -SourcePort 57338
            $result.count | Should -Be 1
        }

        It "Should return 0 events for unmentioned SourcePort" {
            $result = Get-MicrosoftDefenderFirewallevent -SourcePort 57633
            $result.count | Should -Be 0
        }
    }

    Context "Testing DestinationPort parameter" {
        It "Returns all events for traffic with DestinationPort" {
            $result = Get-MicrosoftDefenderFirewallEvent -DestinationPort 445
            $result.count | Should -Be 2
        }

        It "Should return 0 events for unmentioned DestinationPort" {
            $result = Get-MicrosoftDefenderFirewallEvent -DestinationPort 448
            $result.count | Should -Be 0
        }
    }

    Context "Testing SourceIP parameter" {
        It "Returns all events for traffic with SourceIP" {
            $result = Get-MicrosoftDefenderFirewallEvent -SourceIP 172.168.9.2
            $result.count | Should -Be 5
        }

        It "Should return 0 for unmentioned SourceIP" {
            $result = Get-MicrosoftDefenderFirewallEvent -SourceIP 172.168.10.10
            $result.count | Should -Be 0
        }
    }

    Context "Testing DestinationIP parameter" {
        It "Returns all events for traffic with DestinationIP 192.168.1.79" {
            $result = Get-MicrosoftDefenderFirewallEvent -DestinationIP 192.168.1.79
            $result.count | Should -Be 2
        }

        It "Returns all events for traffic with DestinationIP 192.168.2.3" {
            $result = Get-MicrosoftDefenderFirewallEvent -DestinationIP 192.168.2.3
            $result.count | Should -Be 2
        }

        It "Should return 0 for unmentioned DestinationIP" {
            $result = Get-MicrosoftDefenderFirewallEvent -DestinationIP 192.168.10.10
            $result.count | Should -Be 0
        }
    }

    Context "Testing Before parameter" {
        It "Should return 2 events before 2022-11-11 16:58:58" {
            $result = Get-MicrosoftDefenderFirewallEvent -Before '2022-11-11 16:58:58'
            $result.count | Should -Be 2
        }
    }

    Context "Testing After parameter" {
        It "Should return 3 events after 2022-11-11 16:58:57" {
            $result = Get-MicrosoftDefenderFirewallEvent -After '2022-11-11 16:58:57'
            $result.count | Should -Be 3
        }
    }

}