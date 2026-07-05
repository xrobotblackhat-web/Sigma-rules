rule CobaltStrike_NamedPipes {
    meta:
        description = "Detects strings for Cobalt Strike named pipes (often used for inter-process communication)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1055"
        attack.id = "T1055"
    strings:
        $a = "\\.\pipe\msagent_" fullword ascii wide
        $b = "\\.\pipe\MSSE-" fullword ascii wide
        $c = "\\.\pipe\postex_" fullword ascii wide
        $d = "\\.\pipe\status_" fullword ascii wide
    condition:
        any of them
}
