rule Medusa_Batch_Commands {
    meta:
        description = "Detects Medusa ransomware batch file patterns (vssadmin, net, wmic, etc.)"
        severity = "high"
        attack.tactic = "TA0040"
        attack.technique = "T1490"
    strings:
        $a = "vssadmin delete shadows" fullword ascii wide
        $b = "wmic shadowcopy delete" fullword ascii wide
        $c = "net user" fullword ascii wide
        $d = "net group" fullword ascii wide
        $e = "taskkill" fullword ascii wide
        $f = "netsh advfirewall set" fullword ascii wide
        $g = "reg add" fullword ascii wide
    condition:
        2 of them
}
