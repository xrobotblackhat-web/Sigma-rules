rule Medusa_Certutil_Download {
    meta:
        description = "Detects certutil download usage in scripts"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1105"
    strings:
        $a = "certutil" fullword ascii wide
        $b = "-urlcache" fullword ascii wide
        $c = "-f" fullword ascii wide
        $d = "http://" fullword ascii wide
        $e = "https://" fullword ascii wide
    condition:
        $a and $b and (any of ($c,$d,$e))
}
