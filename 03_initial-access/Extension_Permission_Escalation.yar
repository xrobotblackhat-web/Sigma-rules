rule Extension_Permission_Escalation {
    meta:
        description = "Detects suspicious permission escalation in extension manifest (e.g., adding cookies, webRequest)"
        severity = "high"
        attack.tactic = "TA0001"
        attack.technique = "T1098"
        attack.id = "T1098"
    strings:
        $perm1 = ""permissions": ["cookies"" fullword ascii
        $perm2 = ""permissions": ["webRequest"" fullword ascii
        $perm3 = ""permissions": ["webRequestBlocking"" fullword ascii
        $perm4 = ""permissions": ["nativeMessaging"" fullword ascii
        $perm5 = ""permissions": ["debugger"" fullword ascii
        $perm6 = ""permissions": ["tabs"" fullword ascii
        $perm7 = ""permissions": ["history"" fullword ascii
        $perm8 = ""permissions": ["bookmarks"" fullword ascii
        $perm9 = ""permissions": ["downloads"" fullword ascii
        $perm10 = ""permissions": ["proxy"" fullword ascii
        $perm11 = ""permissions": ["management"" fullword ascii
        $host1 = ""host_permissions": ["<all_urls>"" fullword ascii
        $host2 = ""host_permissions": ["*://*/*"" fullword ascii
    condition:
        any of ($perm*) or any of ($host*)
}
