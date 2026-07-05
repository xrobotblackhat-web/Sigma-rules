rule CreateProcess_Import {
    meta:
        description = "Detects import of CreateProcess or WinExec (common process creation)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "CreateProcess" fullword ascii
        $b = "WinExec" fullword ascii
        $c = "ShellExecute" fullword ascii
    condition:
        any of them
}
