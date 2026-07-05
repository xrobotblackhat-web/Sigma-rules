rule Suspicious_CommandLine {
    meta:
        description = "Detects embedded command lines that are often used in malware"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1059"
        attack.id = "T1059"
    strings:
        $a = "cmd /c" fullword ascii wide
        $b = "powershell -NoP -NonI -W Hidden -Exec Bypass" fullword ascii wide
        $c = "rundll32" fullword ascii wide
        $d = "regsvr32 /s /u" fullword ascii wide
        $e = "msiexec /i" fullword ascii wide
        $f = "bitsadmin" fullword ascii wide
        $g = "certutil -urlcache" fullword ascii wide
    condition:
        any of them
}
