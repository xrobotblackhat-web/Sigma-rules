rule Bitsadmin_Download {
    meta:
        description = "Detects bitsadmin.exe download usage (BITS job for payload transfer)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1105"
        attack.id = "T1105"
    strings:
        $a = "bitsadmin /transfer" fullword ascii wide
        $b = "bitsadmin /create" fullword ascii wide
        $c = "bitsadmin /addfile" fullword ascii wide
        $d = "bitsadmin /resume" fullword ascii wide
    condition:
        any of them
}
