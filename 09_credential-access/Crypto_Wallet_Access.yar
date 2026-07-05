rule Crypto_Wallet_Access {
    meta:
        description = "Detects access to window.ethereum or other wallet objects (crypto theft)"
        severity = "critical"
        attack.tactic = "TA0006"
        attack.technique = "T1539"
        attack.id = "T1539"
    strings:
        $a = "window.ethereum" fullword ascii
        $b = "window.solana" fullword ascii
        $c = "window.phantom" fullword ascii
        $d = "window.keplr" fullword ascii
        $e = "window.coinbaseWallet" fullword ascii
    condition:
        any of them
}
