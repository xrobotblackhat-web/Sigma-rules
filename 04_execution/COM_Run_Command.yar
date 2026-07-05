rule COM_Run_Command {
    meta:
        description = "Detects COM objects used to run commands (e.g., WScript.Shell.Run)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "WScript.Shell" fullword ascii wide
        $b = ".Run" fullword ascii
        $c = ".Exec" fullword ascii
    condition:
        $a and (any of ($b,$c))
}
