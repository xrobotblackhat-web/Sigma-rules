rule Fingerprinting_Canvas {
    meta:
        description = "Detects canvas fingerprinting (HTML5 canvas read)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1082"
        attack.id = "T1082"
    strings:
        $a = "canvas" fullword ascii
        $b = "getContext('2d')" fullword ascii
        $c = "toDataURL" fullword ascii
    condition:
        $a and $b and $c
}
