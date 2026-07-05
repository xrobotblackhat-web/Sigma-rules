rule DotNet_ProcessStart {
    meta:
        description = "Detects .NET binaries with Process.Start and System.Diagnostics"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "System.Diagnostics.Process" fullword ascii
        $b = "Process.Start" fullword ascii
        $c = "ProcessStartInfo" fullword ascii
    condition:
        (any of ($a,$b,$c)) and uint16(0) == 0x5A4D
        and for any i in (0..pe.number_of_sections) : (pe.sections[i].name == ".text" and pe.sections[i].contains("mscorlib.dll"))
}
