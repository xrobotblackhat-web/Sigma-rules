rule Wallet_Clipboard_Replace {
    meta:
        description = "Detects clipboard manipulation to replace crypto addresses"
        severity = "critical"
        attack.tactic = "TA0006"
        attack.technique = "T1056"
        attack.id = "T1056"
    strings:
        $a = "clipboard.writeText" fullword ascii
        $b = "clipboard.readText" fullword ascii
        $c = "wallet" fullword ascii wide
        $d = "address" fullword ascii wide
    condition:
        ($a or $b) and ($c or $d)
}
