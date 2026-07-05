rule Medusa_Encoded_PowerShell {
    meta:
        description = "Detects Base64 encoded PowerShell commands (common in Medusa)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
    strings:
        $a = "-EncodedCommand" fullword ascii wide
        $b = "-e " fullword ascii wide
        $c = "[System.Convert]::FromBase64String" fullword ascii wide
    condition:
        any of them
}
