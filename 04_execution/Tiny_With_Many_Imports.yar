rule Tiny_With_Many_Imports {
    meta:
        description = "Small files (e.g., < 50KB) with many process creation imports – suspicious"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "CreateProcess" ascii
        $b = "ShellExecute" ascii
        $c = "WinExec" ascii
        $d = "system" ascii
    condition:
        filesize < 50KB and (count of ($a,$b,$c,$d) >= 3)
}
