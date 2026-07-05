rule SAM_Registry_Strings {
    meta:
        description = "Detects strings for accessing SAM and SECURITY hives (credential dumping)"
        severity = "high"
        attack.tactic = "TA0006"
        attack.technique = "T1003.002"
        attack.id = "T1003.002"
    strings:
        $a = "SAM" fullword ascii wide
        $b = "SECURITY" fullword ascii wide
        $c = "\Windows\System32\config\SAM" fullword ascii wide
    condition:
        any of them
}
