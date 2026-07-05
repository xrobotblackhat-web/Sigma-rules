rule TokenAbuse_Combined {
    meta:
        description = "Detects token duplication and process creation with token"
        severity = "critical"
        attack.tactic = "TA0004"
        attack.technique = "T1134.002"
        attack.id = "T1134.002"
    strings:
        $a = "DuplicateTokenEx" fullword ascii
        $b = "CreateProcessWithTokenW" fullword ascii
    condition:
        $a and $b
}
