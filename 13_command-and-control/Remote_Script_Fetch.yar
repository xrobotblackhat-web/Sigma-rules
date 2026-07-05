rule Remote_Script_Fetch {
    meta:
        description = "Detects fetching remote script and executing with eval (dynamic payload)"
        severity = "critical"
        attack.tactic = "TA0011"
        attack.technique = "T1105"
        attack.id = "T1105"
    strings:
        $a = "fetch(" fullword ascii
        $b = ".then(" fullword ascii
        $c = "eval(" fullword ascii
    condition:
        $a and $b and $c
}
