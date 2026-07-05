rule Downloads_Access {
    meta:
        description = "Detects use of downloads API (download history collection)"
        severity = "medium"
        attack.tactic = "TA0009"
        attack.technique = "T1005"
        attack.id = "T1005"
    strings:
        $a = "chrome.downloads" fullword ascii
        $b = "downloads.search" fullword ascii
    condition:
        any of them
}
