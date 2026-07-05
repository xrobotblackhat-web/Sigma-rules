rule Base64_Encoded_Command {
    meta:
        description = "Detects Base64 encoded command strings (e.g., -enc, -e, -EncodedCommand)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $a = "-EncodedCommand" fullword ascii wide
        $b = "-e " fullword ascii wide
        $c = "-enc" fullword ascii wide
        $d = "Base64" fullword ascii wide
    condition:
        any of them
}
