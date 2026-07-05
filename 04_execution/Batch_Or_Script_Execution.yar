rule Batch_Or_Script_Execution {
    meta:
        description = "Detects strings that indicate launching batch or script files"
        severity = "low"
        attack.tactic = "TA0002"
        attack.technique = "T1059"
        attack.id = "T1059"
    strings:
        $a = "cmd.exe /c" fullword ascii wide
        $b = "powershell.exe -" fullword ascii wide
        $c = "wscript" fullword ascii wide
        $d = "cscript" fullword ascii wide
        $e = "mshta" fullword ascii wide
    condition:
        any of them
}
