rule PlugX_COM_Automation {
    meta:
        description = "Detects heavy COM automation imports (PlugX characteristic)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "CLSID_ShellWindows" fullword ascii wide
        $b = "Shell.Windows" fullword ascii wide
        $c = "DesktopAutomation" fullword ascii wide
    condition:
        any of them
}
