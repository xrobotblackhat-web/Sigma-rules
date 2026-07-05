rule Attrib_Hide_Files {
    meta:
        description = "Detects use of attrib.exe to hide files (attrib +h)"
        severity = "low"
        attack.tactic = "TA0005"
        attack.technique = "T1564.001"
        attack.id = "T1564.001"
    strings:
        $a = "attrib +h" fullword ascii wide
        $b = "attrib -h" fullword ascii wide
    condition:
        any of them
}
