rule WMI_Remote_Execution {
    meta:
        description = "Detects remote WMI execution patterns (often lateral movement)"
        severity = "critical"
        attack.tactic = "TA0008"
        attack.technique = "T1047"
        attack.id = "T1047"
    strings:
        $a = "winrm" fullword ascii wide
        $b = "Invoke-WmiMethod" fullword ascii wide
        $c = "Invoke-CimMethod" fullword ascii wide
    condition:
        any of them
}
