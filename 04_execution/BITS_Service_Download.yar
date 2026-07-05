rule BITS_Service_Download {
    meta:
        description = "Detects use of Background Intelligent Transfer Service (BITS) COM object for download"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1105"
        attack.id = "T1105"
    strings:
        $a = "BackgroundCopyManager" fullword ascii
        $b = "IBackgroundCopyJob" fullword ascii
        $c = "CreateJob" fullword ascii
        $d = "BITS" fullword ascii
    condition:
        any of them
}
