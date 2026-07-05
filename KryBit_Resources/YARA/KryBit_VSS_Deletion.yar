rule KryBit_VSS_Deletion {
    meta:
        description = "Detects commands to delete shadow copies"
        severity = "critical"
        attack.tactic = "TA0040"
        attack.technique = "T1490"
    strings:
        $a = "vssadmin delete shadows" fullword ascii wide
        $b = "wmic shadowcopy delete" fullword ascii wide
        $c = "diskshadow /s" fullword ascii wide
    condition:
        any of them
}
