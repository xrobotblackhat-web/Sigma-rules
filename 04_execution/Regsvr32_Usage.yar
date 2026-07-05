rule Regsvr32_Usage {
    meta:
        description = "Detects use of regsvr32.exe (DLL registration proxy)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1218.010"
        attack.id = "T1218.010"
    strings:
        $a = "regsvr32" fullword ascii wide
        $b = "regsvr32.exe" fullword ascii wide
    condition:
        any of them
}
