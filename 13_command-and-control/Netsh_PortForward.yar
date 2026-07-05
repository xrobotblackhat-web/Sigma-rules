rule Netsh_PortForward {
    meta:
        description = "Detects netsh port forwarding (tunneling)"
        severity = "high"
        attack.tactic = "TA0011"
        attack.technique = "T1090"
        attack.id = "T1090"
    strings:
        $a = "netsh interface portproxy" fullword ascii wide
        $b = "netsh firewall" fullword ascii wide
    condition:
        any of them
}
