rule WMI_PowerShell_String {
    meta:
        description = "Detects strings that indicate WMI invocation from PowerShell"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1047"
        attack.id = "T1047"
    strings:
        $a = "Invoke-WmiMethod" fullword ascii wide
        $b = "Get-WmiObject" fullword ascii wide
        $c = "Win32_ProcessStartup" fullword ascii wide
        $d = "Win32_Process.Create" fullword ascii wide
    condition:
        any of them
}
