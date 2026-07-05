rule Large_POST_Request {
    meta:
        description = "Detects fetch/XHR with POST method and large data (exfiltration)"
        severity = "medium"
        attack.tactic = "TA0010"
        attack.technique = "T1048"
        attack.id = "T1048"
    strings:
        $a = "method: 'POST'" fullword ascii
        $b = "method: "POST"" fullword ascii
        $c = "body:" fullword ascii
    condition:
        any of ($a,$b) and $c
}
