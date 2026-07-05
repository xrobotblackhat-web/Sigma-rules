rule Service_Process_Creation {
    meta:
        description = "Detects imports for service control functions that can launch processes"
        severity = "medium"
        attack.tactic = "TA0003"
        attack.technique = "T1543"
        attack.id = "T1543"
    strings:
        $a = "CreateService" fullword ascii
        $b = "StartService" fullword ascii
        $c = "OpenSCManager" fullword ascii
        $d = "DeleteService" fullword ascii
    condition:
        any of them
}
