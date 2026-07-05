rule Steganography_C2 {
    meta:
        description = "Detects image decoding for C2 payload (steganography)"
        severity = "high"
        attack.tactic = "TA0011"
        attack.technique = "T1105"
        attack.id = "T1105"
    strings:
        $a = "createImageBitmap" fullword ascii
        $b = "getImageData" fullword ascii
        $c = "atob" fullword ascii
    condition:
        $a and $b and $c
}
