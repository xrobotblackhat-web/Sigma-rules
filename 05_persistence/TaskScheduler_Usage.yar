rule TaskScheduler_Usage {
    meta:
        description = "Detects strings indicating use of Task Scheduler for execution"
        severity = "medium"
        attack.tactic = "TA0003"
        attack.technique = "T1053"
        attack.id = "T1053"
    strings:
        $a = "schtasks" fullword ascii wide
        $b = "CreateTask" fullword ascii
        $c = "ITaskScheduler" fullword ascii
        $d = "TaskSchedulerClass" fullword ascii
    condition:
        any of them
}
