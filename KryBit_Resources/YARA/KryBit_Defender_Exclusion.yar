rule KryBit_Defender_Exclusion {
    meta:
        description = "Detects Defender exclusion commands"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1562.001"
    strings:
        $a = "Add-MpPreference -ExclusionPath" fullword ascii wide
        $b = "Set-MpPreference -ExclusionPath" fullword ascii wide
        $c = "MpCmdRun -AddExclusion" fullword ascii wide
    condition:
        any of them
}
