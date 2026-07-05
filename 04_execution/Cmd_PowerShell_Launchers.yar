rule Cmd_PowerShell_Launchers {
    meta:
        description = "Detects usage of cmd.exe or powershell.exe in suspicious contexts"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1059"
        attack.id = "T1059"
    strings:
        $a = "cmd.exe /c" fullword ascii wide
        $b = "powershell.exe -" fullword ascii wide
        $c = "pwsh.exe -" fullword ascii wide
    condition:
        any of them
}
