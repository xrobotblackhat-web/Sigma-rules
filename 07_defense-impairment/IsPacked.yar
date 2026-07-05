rule IsPacked {
    meta:
        description = "Detects common packer signatures or high entropy indicating obfuscation"
        severity = "low"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $upx = "UPX0" fullword ascii
        $upx1 = "UPX1" fullword ascii
        $aspack = "ASPack" fullword ascii
        $themida = "Themida" fullword ascii
        $vmprotect = "VMProtect" fullword ascii
    condition:
        any of them or (entropy > 7.5 and filesize > 100KB)
}
