rule WinRM_Usage {
    meta:
        description = "Detects use of winrs.exe or WinRM (remote management, lateral movement)"
        severity = "high"
        attack.tactic = "TA0008"
        attack.technique = "T1021.006"
        attack.id = "T1021.006"
    strings:
        $a = "winrs" fullword ascii wide
        $b = "winrm" fullword ascii wide
    condition:
        any of them
}
