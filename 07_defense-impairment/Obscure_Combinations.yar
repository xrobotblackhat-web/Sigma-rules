rule Obscure_Combinations {
    meta:
        description = "Detects binaries that import multiple rare process‑creation APIs"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "RunHTMLApplication" fullword ascii
        $b = "RouteTheCall" fullword ascii
        $c = "OpenURL" fullword ascii
        $d = "FileProtocolHandlerA" fullword ascii
        $e = "IHxHelpPaneServer" fullword ascii
    condition:
        (2 or more of them)
}
