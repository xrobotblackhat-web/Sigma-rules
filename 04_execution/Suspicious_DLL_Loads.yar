rule Suspicious_DLL_Loads {
    meta:
        description = "Detects imports from DLLs used for download & execute"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "URLDownloadToFileA" fullword ascii
        $b = "URLDownloadToFileW" fullword ascii
        $c = "DeleteUrlCacheEntry" fullword ascii
        $d = "FindWindow" fullword ascii
        $e = "GetAsyncKeyState" fullword ascii
    condition:
        any of them
}
