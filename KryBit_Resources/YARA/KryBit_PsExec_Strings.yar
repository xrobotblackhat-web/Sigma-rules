rule KryBit_PsExec_Strings {
    meta:
        description = "Detects PsExec usage in scripts"
        severity = "high"
        attack.tactic = "TA0008"
        attack.technique = "T1570"
    strings:
        $a = "PsExec.exe" fullword ascii wide
        $b = "-accepteula" fullword ascii wide
        $c = "-s" fullword ascii wide
        $d = "-d" fullword ascii wide
    condition:
        $a and (any of ($b,$c,$d))
}
