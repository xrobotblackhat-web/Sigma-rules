rule Form_Grabbing_APIs {
    meta:
        description = "Detects code that reads form data or captures input events (password theft)"
        severity = "critical"
        attack.tactic = "TA0006"
        attack.technique = "T1056"
        attack.id = "T1056"
    strings:
        $a = "addEventListener('submit'" fullword ascii
        $b = "addEventListener('change'" fullword ascii
        $c = "addEventListener('input'" fullword ascii
        $d = "getElementById" fullword ascii
        $e = "querySelector" fullword ascii
        $f = "value" fullword ascii
    condition:
        (any of ($a,$b,$c)) and (any of ($d,$e,$f))
}
