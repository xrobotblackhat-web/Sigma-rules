rule Manifest_Permission_Change {
    meta:
        description = "Detects addition of sensitive permissions in manifest (supply chain)"
        severity = "high"
        attack.tactic = "TA0001"
        attack.technique = "T1195"
        attack.id = "T1195"
    strings:
        $a = ""cookies"" fullword ascii
        $b = ""webRequest"" fullword ascii
        $c = ""nativeMessaging"" fullword ascii
        $d = ""debugger"" fullword ascii
        $e = ""tabs"" fullword ascii
        $f = ""history"" fullword ascii
        $g = ""bookmarks"" fullword ascii
        $h = ""downloads"" fullword ascii
        $i = ""proxy"" fullword ascii
        $j = ""management"" fullword ascii
    condition:
        any of them
}
