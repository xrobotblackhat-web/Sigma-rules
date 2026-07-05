rule COM_Hijacking {
    meta:
        description = "Detects COM hijacking registry modifications (InprocServer32, TreatAs)"
        severity = "high"
        attack.tactic = "TA0004"
        attack.technique = "T1546.015"
        attack.id = "T1546.015"
    strings:
        $a = "InprocServer32" fullword ascii wide
        $b = "TreatAs" fullword ascii wide
        $c = "CLSID" fullword ascii wide
    condition:
        any of them
}
