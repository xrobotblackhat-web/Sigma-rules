rule Suspicious_Section_Names {
    meta:
        description = "Detects unusual section names like .crypt, .upx, .vmp"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $sec1 = ".crypt" fullword ascii
        $sec2 = ".upx" fullword ascii
        $sec3 = ".vmp" fullword ascii
        $sec4 = ".ore" fullword ascii
        $sec5 = ".data0" fullword ascii
    condition:
        any of them and (entropy > 6.0)
}
