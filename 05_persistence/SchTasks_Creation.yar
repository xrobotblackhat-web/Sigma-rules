rule SchTasks_Creation {
    meta:
        description = "Detects scheduled task creation (schtasks or COM task scheduler)"
        severity = "high"
        attack.tactic = "TA0003"
        attack.technique = "T1053.005"
        attack.id = "T1053.005"
    strings:
        $a = "schtasks /create" fullword ascii wide
        $b = "schtasks /change" fullword ascii wide
        $c = "ITaskScheduler" fullword ascii
        $d = "TaskScheduler" fullword ascii
    condition:
        any of them
}
