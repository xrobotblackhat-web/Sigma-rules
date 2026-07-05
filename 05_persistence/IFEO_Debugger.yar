rule IFEO_Debugger {
    meta:
        description = "Detects Image File Execution Options (IFEO) Debugger key (used for persistence or hijack)"
        severity = "high"
        attack.tactic = "TA0003"
        attack.technique = "T1546"
        attack.id = "T1546"
    strings:
        $a = "Debugger" fullword ascii wide
        $b = "Image File Execution Options" fullword ascii wide
    condition:
        any of them
}
