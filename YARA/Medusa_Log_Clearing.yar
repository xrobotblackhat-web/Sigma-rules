rule Medusa_Log_Clearing {
    meta:
        description = "Detects commands used to clear event logs"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1070"
    strings:
        $a = "wevtutil cl" fullword ascii wide
        $b = "Clear-EventLog" fullword ascii wide
        $c = "Remove-EventLog" fullword ascii wide
    condition:
        any of them
}
