rule File_Enumeration {
    meta:
        description = "Detects APIs for file/directory enumeration (often used for discovery)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1083"
        attack.id = "T1083"
    strings:
        $a = "FindFirstFile" fullword ascii
        $b = "FindNextFile" fullword ascii
        $c = "NtQueryDirectoryFile" fullword ascii
    condition:
        any of them
}
