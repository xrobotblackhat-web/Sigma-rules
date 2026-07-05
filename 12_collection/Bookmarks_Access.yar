rule Bookmarks_Access {
    meta:
        description = "Detects use of bookmarks API (bookmark collection)"
        severity = "medium"
        attack.tactic = "TA0009"
        attack.technique = "T1005"
        attack.id = "T1005"
    strings:
        $a = "chrome.bookmarks" fullword ascii
        $b = "bookmarks.getTree" fullword ascii
        $c = "bookmarks.get" fullword ascii
    condition:
        any of them
}
