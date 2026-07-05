rule Permission_Escalation_Pattern {
    meta:
        description = "Looks for optional permissions or permission request patterns that can be escalated"
        severity = "medium"
        attack.tactic = "TA0004"
        attack.technique = "T1098"
        attack.id = "T1098"
    strings:
        $opt = ""optional_permissions"" fullword ascii
        $req = "permissions.request" fullword ascii
    condition:
        any of them
}
