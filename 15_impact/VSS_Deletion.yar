rule VSS_Deletion {
    meta:
        description = "Detects vssadmin.exe delete shadows (shadow copy deletion)"
        severity = "critical"
        attack.tactic = "TA0040"
        attack.technique = "T1490"
        attack.id = "T1490"
    strings:
        $a = "vssadmin delete shadows" fullword ascii wide
        $b = "vssadmin resize" fullword ascii wide
        $c = "wbadmin delete backup" fullword ascii wide
        $d = "bcdedit /set" fullword ascii wide
    condition:
        any of them
}
