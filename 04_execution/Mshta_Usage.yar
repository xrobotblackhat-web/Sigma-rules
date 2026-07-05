rule Mshta_Usage {
    meta:
        description = "Detects use of mshta.exe (often abused to run JavaScript/VBScript)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1218.011"
        attack.id = "T1218.011"
    strings:
        $a = "mshta.exe" fullword ascii wide
        $b = "mshta" fullword ascii wide
        $c = "javascript:" fullword ascii wide
        $d = "vbscript:" fullword ascii wide
    condition:
        ($a or $b) and (any of ($c,$d))
}
