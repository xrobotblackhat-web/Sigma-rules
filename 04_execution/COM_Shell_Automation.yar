rule COM_Shell_Automation {
    meta:
        description = "Detects usage of COM objects that can launch processes (Shell.Application, ShellWindows)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "Shell.Application" fullword ascii wide
        $b = "ShellWindows" fullword ascii wide
        $c = "CLSID_ShellWindows" fullword ascii wide
        $d = "DesktopAutomation" fullword ascii wide
        $e = "ShellExecute" fullword ascii
    condition:
        (any of ($a,$b,$c,$d)) and $e
}
