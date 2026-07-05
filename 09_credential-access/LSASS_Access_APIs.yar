rule LSASS_Access_APIs {
    meta:
        description = "Detects APIs used to access LSASS process (often for credential dumping)"
        severity = "critical"
        attack.tactic = "TA0006"
        attack.technique = "T1003.001"
        attack.id = "T1003.001"
    strings:
        $a = "OpenProcess" fullword ascii
        $b = "ReadProcessMemory" fullword ascii
        $c = "MiniDumpWriteDump" fullword ascii
        $d = "lsass" fullword ascii wide
    condition:
        (any of ($a,$b,$c)) and $d
}
