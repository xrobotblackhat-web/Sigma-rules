rule CryptoMiner_Detection {
    meta:
        description = "Detects crypto mining scripts in extension (Monero, etc.)"
        severity = "high"
        attack.tactic = "TA0040"
        attack.technique = "T1496"
        attack.id = "T1496"
    strings:
        $a = "Coinhive" fullword ascii
        $b = "cryptonight" fullword ascii
        $c = "miner" fullword ascii
        $d = "hashrate" fullword ascii
    condition:
        any of them
}
