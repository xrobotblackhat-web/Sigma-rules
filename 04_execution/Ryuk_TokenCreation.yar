rule Ryuk_TokenCreation {
    meta:
        description = "Detects strings for token duplication and process creation (Ryuk/Cobalt Strike style)"
        severity = "critical"
        attack.tactic = "TA0002"
        attack.technique = "T1134.002"
        attack.id = "T1134.002"
    strings:
        $a = "CreateProcessWithTokenW" fullword ascii
        $b = "DuplicateTokenEx" fullword ascii
        $c = "ImpersonateLoggedOnUser" fullword ascii
    condition:
        (any of ($a,$b) and $c) or ($a and $b)
}
