rule Proxy_Configuration {
    meta:
        description = "Detects proxy configuration changes (netsh winhttp, etc.)"
        severity = "medium"
        attack.tactic = "TA0011"
        attack.technique = "T1090"
        attack.id = "T1090"
    strings:
        $a = "netsh winhttp set proxy" fullword ascii wide
        $b = "proxy" fullword ascii wide
    condition:
        any of them
}
