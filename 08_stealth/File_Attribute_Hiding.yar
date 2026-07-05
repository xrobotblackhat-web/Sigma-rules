rule File_Attribute_Hiding {
    meta:
        description = "Detects use of SetFileAttributes to hide files (common in stealth)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1564.001"
        attack.id = "T1564.001"
    strings:
        $a = "SetFileAttributes" fullword ascii
        $b = "FILE_ATTRIBUTE_HIDDEN" fullword ascii
    condition:
        $a and $b
}
