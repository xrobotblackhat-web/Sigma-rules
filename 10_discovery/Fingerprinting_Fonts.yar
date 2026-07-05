rule Fingerprinting_Fonts {
    meta:
        description = "Detects font enumeration (fingerprinting)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1082"
        attack.id = "T1082"
    strings:
        $a = "fonts" fullword ascii
        $b = "document.fonts" fullword ascii
        $c = "FontFace" fullword ascii
    condition:
        any of them
}
