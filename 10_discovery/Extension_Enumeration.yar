rule Extension_Enumeration {
    meta:
        description = "Detects use of management API to enumerate installed extensions (victim profiling)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1018"
        attack.id = "T1018"
    strings:
        $a = "chrome.management" fullword ascii
        $b = "management.getAll" fullword ascii
    condition:
        any of them
}
