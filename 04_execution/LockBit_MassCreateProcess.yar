rule LockBit_MassCreateProcess {
    meta:
        description = "Detects multiple process creation imports (often used in ransomware mass-spreading)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "CreateProcess" ascii
        $b = "ShellExecute" ascii
        $c = "WinExec" ascii
        $d = "CreateProcessAsUser" ascii
    condition:
        (count of ($a,$b,$c,$d) >= 3)
}
