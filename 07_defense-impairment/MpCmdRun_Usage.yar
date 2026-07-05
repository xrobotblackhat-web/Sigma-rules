rule MpCmdRun_Usage {
    meta:
        description = "Detects use of MpCmdRun.exe (Windows Defender command-line utility, abused to disable or exclusions)"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1562.001"
        attack.id = "T1562.001"
    strings:
        $a = "MpCmdRun.exe" fullword ascii wide
        $b = "MpCmdRun" fullword ascii wide
        $c = "-DisableRealtimeMonitoring" fullword ascii wide
        $d = "-DisableBehaviorMonitoring" fullword ascii wide
    condition:
        any of them
}
