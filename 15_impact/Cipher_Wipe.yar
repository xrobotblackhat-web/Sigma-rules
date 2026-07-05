rule Cipher_Wipe {
    meta:
        description = "Detects use of cipher.exe /w to wipe free space (data destruction)"
        severity = "medium"
        attack.tactic = "TA0040"
        attack.technique = "T1485"
        attack.id = "T1485"
    strings:
        $a = "cipher /w" fullword ascii wide
    condition:
        any of them
}
