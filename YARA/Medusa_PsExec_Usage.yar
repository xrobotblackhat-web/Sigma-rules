rule Medusa_PsExec_Usage {
    meta:
        description = "Detects embedded PsExec commands in scripts"
        severity = "high"
        attack.tactic = "TA0008"
        attack.technique = "T1570"
    strings:
        $a = "PsExec.exe" fullword ascii wide
        $b = "-accepteula" fullword ascii wide
        $c = "-s" fullword ascii wide
        $d = " -d " fullword ascii wide
    condition:
        $a and (any of ($b,$c,$d))
}
