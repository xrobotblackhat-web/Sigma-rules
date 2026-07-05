rule WScript_Cscript_Usage {
    meta:
        description = "Detects use of wscript.exe or cscript.exe (script interpreters)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1059.005"
        attack.id = "T1059.005"
    strings:
        $a = "wscript.exe" fullword ascii wide
        $b = "cscript.exe" fullword ascii wide
    condition:
        any of them
}
