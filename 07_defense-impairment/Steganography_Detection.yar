rule Steganography_Detection {
    meta:
        description = "Detects steganography usage (image decoding + eval) in extension"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $img = "createImageBitmap" fullword ascii
        $canvas = "canvas" fullword ascii
        $getImageData = "getImageData" fullword ascii
        $atob = "atob(" fullword ascii
        $eval = "eval(" fullword ascii
    condition:
        ($img or $canvas or $getImageData) and $atob and $eval
}
