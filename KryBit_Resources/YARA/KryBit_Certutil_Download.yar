rule KryBit_Certutil_Download {
    meta:
        description = "Detects certutil -urlcache download patterns"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1105"
    strings:
        $a = "certutil" fullword ascii wide
        $b = "-urlcache" fullword ascii wide
        $c = "-split" fullword ascii wide
        $d = "-f" fullword ascii wide
        $e = "http://" fullword ascii wide
        $f = "https://" fullword ascii wide
    condition:
        $a and $b and (any of ($c,$d,$e,$f))
}
