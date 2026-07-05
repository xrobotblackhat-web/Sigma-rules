rule Extension_Auto_Update {
    meta:
        description = "Detects extension update mechanism that may be abused for persistence"
        severity = "low"
        attack.tactic = "TA0003"
        attack.technique = "T1078"
        attack.id = "T1078"
    strings:
        $a = ""update_url"" fullword ascii
        $b = "update_url" fullword ascii
        $c = "https://clients2.google.com/service/update2/crx" fullword ascii
    condition:
        any of them
}
