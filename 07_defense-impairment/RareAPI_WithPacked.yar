rule RareAPI_WithPacked {
    meta:
        description = "Detects rare API usage in a packed binary – high suspicion"
        severity = "critical"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $a = "RouteTheCall" fullword ascii
        $b = "IHxHelpPaneServer" fullword ascii
        $c = "RunHTMLApplication" fullword ascii
    condition:
        any of ($a,$b,$c) and (entropy > 7.0)
}
