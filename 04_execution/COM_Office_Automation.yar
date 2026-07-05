rule COM_Office_Automation {
    meta:
        description = "Detects use of Office COM objects (Excel, Word) to execute code"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "Excel.Application" fullword ascii wide
        $b = "Word.Application" fullword ascii wide
        $c = "PowerPoint.Application" fullword ascii wide
    condition:
        any of them
}
