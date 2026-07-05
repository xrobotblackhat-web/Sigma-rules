rule System_Info_Commands {
    meta:
        description = "Detects use of systeminfo, whoami, hostname, tasklist, net, ipconfig, etc."
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1082"
        attack.id = "T1082"
    strings:
        $a = "systeminfo.exe" fullword ascii wide
        $b = "whoami.exe" fullword ascii wide
        $c = "hostname.exe" fullword ascii wide
        $d = "tasklist.exe" fullword ascii wide
        $e = "ipconfig" fullword ascii wide
        $f = "net.exe" fullword ascii wide
        $g = "net1.exe" fullword ascii wide
    condition:
        any of them
}
