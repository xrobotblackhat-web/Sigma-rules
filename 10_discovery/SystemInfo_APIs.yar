rule SystemInfo_APIs {
    meta:
        description = "Detects APIs to query system information (e.g., GetSystemInfo, GetComputerName)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1082"
        attack.id = "T1082"
    strings:
        $a = "GetSystemInfo" fullword ascii
        $b = "GetComputerName" fullword ascii
        $c = "GetUserName" fullword ascii
        $d = "NetWkstaGetInfo" fullword ascii
    condition:
        any of them
}
