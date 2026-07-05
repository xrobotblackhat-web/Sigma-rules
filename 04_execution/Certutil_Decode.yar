rule Certutil_Decode {
    meta:
        description = "Detects certutil -decode usage (often used to decode Base64 payloads)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $a = "certutil.exe -decode" fullword ascii wide
        $b = "certutil -decode" fullword ascii wide
    condition:
        any of them
}
