rule Emotet_CommandPatterns {
    meta:
        description = "Detects command-line patterns often seen in Emotet downloads"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1059"
        attack.id = "T1059"
    strings:
        $a = "cmd.exe /c powershell" fullword ascii wide
        $b = "powershell -NoP -NonI -W Hidden" fullword ascii wide
        $c = "bitsadmin /transfer" fullword ascii wide
        $d = "certutil -urlcache" fullword ascii wide
    condition:
        any of them
}
