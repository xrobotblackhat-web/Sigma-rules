rule Defender_Exclusion {
    meta:
        description = "Detects PowerShell or reg commands to add Defender exclusions"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1562.001"
        attack.id = "T1562.001"
    strings:
        $a = "Set-MpPreference -ExclusionPath" fullword ascii wide
        $b = "Add-MpPreference -ExclusionPath" fullword ascii wide
    condition:
        any of them
}
