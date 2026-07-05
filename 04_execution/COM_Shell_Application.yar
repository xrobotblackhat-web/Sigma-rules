rule COM_Shell_Application {
    meta:
        description = "Detects use of Shell.Application COM object (commonly abused to launch processes)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "Shell.Application" fullword ascii wide
        $b = "ShellWindows" fullword ascii wide
        $c = "WScript.Shell" fullword ascii wide
        $d = "ShellExecute" fullword ascii
    condition:
        any of ($a,$b,$c) or ($c and $d)
}
