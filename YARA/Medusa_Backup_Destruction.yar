rule Medusa_Backup_Destruction {
    meta:
        description = "Detects attempts to delete backup files (.vhd, .bak, .wbk)"
        severity = "critical"
        attack.tactic = "TA0040"
        attack.technique = "T1485"
    strings:
        $a = ".vhd" fullword ascii wide
        $b = ".bak" fullword ascii wide
        $c = ".wbk" fullword ascii wide
        $d = "del " fullword ascii wide
        $e = "erase " fullword ascii wide
    condition:
        (any of ($a,$b,$c)) and (any of ($d,$e))
}
