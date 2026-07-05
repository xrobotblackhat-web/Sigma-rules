rule DarkSide_TokenCreation {
    meta:
        description = "Detects CreateProcessWithTokenW and DuplicateTokenEx (DarkSide signature)"
        severity = "critical"
        attack.tactic = "TA0002"
        attack.technique = "T1134.002"
        attack.id = "T1134.002"
    strings:
        $a = "CreateProcessWithTokenW" fullword ascii
        $b = "DuplicateTokenEx" fullword ascii
    condition:
        $a and $b
}
