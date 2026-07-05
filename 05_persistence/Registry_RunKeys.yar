rule Registry_RunKeys {
    meta:
        description = "Detects strings for common persistence Run keys"
        severity = "medium"
        attack.tactic = "TA0003"
        attack.technique = "T1547.001"
        attack.id = "T1547.001"
    strings:
        $a = "Software\Microsoft\Windows\CurrentVersion\Run" fullword ascii wide
        $b = "Software\Microsoft\Windows\CurrentVersion\RunOnce" fullword ascii wide
        $c = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" fullword ascii wide
    condition:
        any of them
}
