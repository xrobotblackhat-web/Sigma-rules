rule Network_Discovery_Commands {
    meta:
        description = "Detects use of arp, route, nslookup, etc. (network reconnaissance)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1046"
        attack.id = "T1046"
    strings:
        $a = "arp.exe" fullword ascii wide
        $b = "route.exe" fullword ascii wide
        $c = "nslookup.exe" fullword ascii wide
    condition:
        any of them
}
