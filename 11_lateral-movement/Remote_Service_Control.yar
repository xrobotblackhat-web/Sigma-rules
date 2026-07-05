rule Remote_Service_Control {
    meta:
        description = "Detects remote service control (sc.exe \\remote)"
        severity = "high"
        attack.tactic = "TA0008"
        attack.technique = "T1570"
        attack.id = "T1570"
    strings:
        $a = "sc.exe \\" fullword ascii wide
        $b = "sc \\" fullword ascii wide
    condition:
        any of them
}
