rule Excel_XLL_Usage {
    meta:
        description = "Detects strings for Excel XLL add-ins (DLL execution via Excel)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1218"
        attack.id = "T1218"
    strings:
        $a = ".xll" fullword ascii wide
        $b = "xll" fullword ascii wide
        $c = "xlAddIn" fullword ascii wide
    condition:
        any of them
}
