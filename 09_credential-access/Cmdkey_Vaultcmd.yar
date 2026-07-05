rule Cmdkey_Vaultcmd {
    meta:
        description = "Detects use of cmdkey.exe or vaultcmd.exe (stored credential access)"
        severity = "high"
        attack.tactic = "TA0006"
        attack.technique = "T1555"
        attack.id = "T1555"
    strings:
        $a = "cmdkey" fullword ascii wide
        $b = "vaultcmd" fullword ascii wide
    condition:
        any of them
}
