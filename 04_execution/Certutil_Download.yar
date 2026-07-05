rule Certutil_Download {
    meta:
        description = "Detects use of certutil.exe with download or decode flags (abused to fetch payloads)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1105"
        attack.id = "T1105"
    strings:
        $a = "certutil.exe -urlcache" fullword ascii wide
        $b = "certutil.exe -split -f" fullword ascii wide
        $c = "certutil.exe -decode" fullword ascii wide
        $d = "certutil -urlcache" fullword ascii wide
    condition:
        any of them
}
