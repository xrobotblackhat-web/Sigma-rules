rule History_Access {
    meta:
        description = "Detects use of history API (browsing history collection)"
        severity = "medium"
        attack.tactic = "TA0009"
        attack.technique = "T1005"
        attack.id = "T1005"
    strings:
        $a = "chrome.history" fullword ascii
        $b = "history.search" fullword ascii
        $c = "history.getVisits" fullword ascii
    condition:
        any of them
}
