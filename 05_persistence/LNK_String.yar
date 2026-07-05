rule LNK_String {
    meta:
        description = "Detects .lnk file creation strings (used for persistence or initial access)"
        severity = "low"
        attack.tactic = "TA0003"
        attack.technique = "T1204"
        attack.id = "T1204"
    strings:
        $a = ".lnk" fullword ascii wide
        $b = "ShellLink" fullword ascii
    condition:
        any of them
}
