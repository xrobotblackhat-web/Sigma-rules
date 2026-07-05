rule KryBit_Encoded_Commands {
    meta:
        description = "Detects encoded PowerShell commands and Base64 strings used by KryBit"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
    strings:
        $a = "-EncodedCommand" fullword ascii wide
        $b = "-e " fullword ascii wide
        $c = "[System.Convert]::FromBase64String" fullword ascii wide
        $d = "gzip" fullword ascii wide
    condition:
        any of them
}
