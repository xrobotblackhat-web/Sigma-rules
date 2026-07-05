rule Network_Enumeration {
    meta:
        description = "Detects APIs for network discovery (e.g., NetShareEnum, NetServerEnum)"
        severity = "medium"
        attack.tactic = "TA0007"
        attack.technique = "T1046"
        attack.id = "T1046"
    strings:
        $a = "NetShareEnum" fullword ascii
        $b = "NetServerEnum" fullword ascii
        $c = "NetSessionEnum" fullword ascii
        $d = "WNetOpenEnum" fullword ascii
    condition:
        any of them
}
