rule PowerShell_Download {
    meta:
        description = "Detects PowerShell download cradle patterns (Invoke-WebRequest, DownloadFile, etc.)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1059.001"
        attack.id = "T1059.001"
    strings:
        $a = "Invoke-WebRequest" fullword ascii wide
        $b = "DownloadFile" fullword ascii wide
        $c = "WebClient" fullword ascii wide
        $d = "DownloadString" fullword ascii wide
    condition:
        any of them
}
