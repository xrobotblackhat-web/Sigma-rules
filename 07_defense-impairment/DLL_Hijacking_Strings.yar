rule DLL_Hijacking_Strings {
    meta:
        description = "Detects strings for DLL search order hijacking (e.g., current directory)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1574.001"
        attack.id = "T1574.001"
    strings:
        $a = ".\" fullword ascii wide
        $b = "DLL" fullword ascii
        $c = "LoadLibrary" fullword ascii
    condition:
        $a and $b and $c
}
