rule HelpPane_COM {
    meta:
        description = "Detects references to IHxHelpPaneServer or IHxInteractiveUser (rare)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "IHxHelpPaneServer" fullword ascii wide
        $b = "IHxInteractiveUser" fullword ascii wide
        $c = "HelpPane" fullword ascii
    condition:
        any of them
}
