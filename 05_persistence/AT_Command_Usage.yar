rule AT_Command_Usage {
    meta:
        description = "Detects use of AT command (legacy scheduler, often abused)"
        severity = "medium"
        attack.tactic = "TA0003"
        attack.technique = "T1053.002"
        attack.id = "T1053.002"
    strings:
        $a = "at.exe" fullword ascii wide
        $b = "at " fullword ascii wide
    condition:
        any of them
}
