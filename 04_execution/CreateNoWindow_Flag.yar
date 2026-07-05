rule CreateNoWindow_Flag {
    meta:
        description = "Detects presence of CREATE_NO_WINDOW (0x08000000) in binary data – often used by malware"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = { 00 00 00 08 }
    condition:
        $a
}
