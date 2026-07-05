rule Keylogger_APIs {
    meta:
        description = "Detects keydown/keypress listeners that may log keystrokes"
        severity = "critical"
        attack.tactic = "TA0006"
        attack.technique = "T1056.001"
        attack.id = "T1056.001"
    strings:
        $a = "addEventListener('keydown'" fullword ascii
        $b = "addEventListener('keypress'" fullword ascii
        $c = "addEventListener('keyup'" fullword ascii
        $d = "event.key" fullword ascii
        $e = "event.code" fullword ascii
    condition:
        (any of ($a,$b,$c)) and (any of ($d,$e))
}
