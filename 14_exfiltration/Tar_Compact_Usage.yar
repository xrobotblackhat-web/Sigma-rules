rule Tar_Compact_Usage {
    meta:
        description = "Detects use of tar.exe, compact.exe, makecab.exe (archiving/compression)"
        severity = "medium"
        attack.tactic = "TA0010"
        attack.technique = "T1560"
        attack.id = "T1560"
    strings:
        $a = "tar.exe" fullword ascii wide
        $b = "compact.exe" fullword ascii wide
        $c = "makecab.exe" fullword ascii wide
    condition:
        any of them
}
