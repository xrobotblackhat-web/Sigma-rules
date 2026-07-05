rule Rundll32_Usage {
    meta:
        description = "Detects use of rundll32.exe (DLL execution proxy)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1218.011"
        attack.id = "T1218.011"
    strings:
        $a = "rundll32" fullword ascii wide
        $b = "rundll32.exe" fullword ascii wide
    condition:
        any of them
}
