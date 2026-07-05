rule External_Process_Launcher {
    meta:
        description = "Detects attempt to launch external process via native host (e.g., PowerShell)"
        severity = "critical"
        attack.tactic = "TA0002"
        attack.technique = "T1059"
        attack.id = "T1059"
    strings:
        $a = "powershell" fullword ascii wide
        $b = "cmd.exe" fullword ascii wide
        $c = "wmic" fullword ascii wide
        $d = "rundll32" fullword ascii wide
    condition:
        any of them
}
