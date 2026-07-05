rule Expand_Makecab_Archive {
    meta:
        description = "Detects use of expand.exe or makecab.exe for archive extraction/creation"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $a = "expand.exe" fullword ascii wide
        $b = "makecab.exe" fullword ascii wide
        $c = "extrac32.exe" fullword ascii wide
    condition:
        any of them
}
