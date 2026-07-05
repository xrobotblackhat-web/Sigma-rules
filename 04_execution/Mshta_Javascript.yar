rule Mshta_Javascript {
    meta:
        description = "Detects mshta.exe invocation with javascript: URI (classic LOLBin)"
        severity = "critical"
        attack.tactic = "TA0002"
        attack.technique = "T1218.011"
        attack.id = "T1218.011"
    strings:
        $a = "mshta" fullword ascii wide
        $b = "javascript:" fullword ascii wide
    condition:
        $a and $b
}
