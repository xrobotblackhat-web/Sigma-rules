rule WebSocket_C2 {
    meta:
        description = "Detects WebSocket creation to external domains (C2 communication)"
        severity = "high"
        attack.tactic = "TA0011"
        attack.technique = "T1071"
        attack.id = "T1071"
    strings:
        $a = "new WebSocket('wss://" fullword ascii
        $b = "new WebSocket('ws://" fullword ascii
        $c = ".onmessage" fullword ascii
    condition:
        any of them
}
