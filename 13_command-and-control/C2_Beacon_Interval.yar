rule C2_Beacon_Interval {
    meta:
        description = "Detects periodic beaconing (setInterval with fetch/WebSocket) in extension"
        severity = "high"
        attack.tactic = "TA0011"
        attack.technique = "T1071"
        attack.id = "T1071"
    strings:
        $a = "setInterval(function" fullword ascii
        $b = "fetch(" fullword ascii
        $c = "WebSocket" fullword ascii
        $d = "XMLHttpRequest" fullword ascii
    condition:
        $a and (any of ($b,$c,$d))
}
