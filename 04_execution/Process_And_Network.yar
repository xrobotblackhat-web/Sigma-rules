rule Process_And_Network {
    meta:
        description = "Combines process creation with networking imports – common malware"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "CreateProcess" ascii
        $b = "ShellExecute" ascii
        $c = "URLDownloadToFile" ascii
        $d = "InternetOpen" ascii
        $e = "WinHttpOpen" ascii
        $f = "WSAStartup" ascii
    condition:
        (any of ($a,$b) and any of ($c,$d,$e,$f))
}
