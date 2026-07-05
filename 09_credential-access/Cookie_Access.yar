rule Cookie_Access {
    meta:
        description = "Detects use of chrome.cookies API (cookie theft)"
        severity = "critical"
        attack.tactic = "TA0006"
        attack.technique = "T1539"
        attack.id = "T1539"
    strings:
        $a = "chrome.cookies.get" fullword ascii
        $b = "chrome.cookies.getAll" fullword ascii
        $c = "chrome.cookies.set" fullword ascii
        $d = "cookies" fullword ascii
    condition:
        any of them
}
