rule At_Command {
    meta:
        description = "Detects strings for 'at' command (rare nowadays, often malware)"
        severity = "medium"
        attack.tactic = "TA0003"
        attack.technique = "T1053"
        attack.id = "T1053"
    strings:
        $a = "at " fullword ascii wide
        $b = "schtasks" fullword ascii wide
    condition:
        $a or $b
}
