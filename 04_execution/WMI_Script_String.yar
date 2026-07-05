rule WMI_Script_String {
    meta:
        description = "Detects strings used to invoke WMI from scripts (e.g., VBS)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1047"
        attack.id = "T1047"
    strings:
        $a = "GetObject(\"winmgmts:\")" fullword ascii wide
        $b = "Win32_Process" fullword ascii wide
        $c = ".Create" fullword ascii
    condition:
        $a and $b and $c
}
