rule System_Info_Collection {
    meta:
        description = "Detects collection of system information (OS, CPU, RAM) – fingerprinting"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1082"
        attack.id = "T1082"
    strings:
        $a = "navigator.userAgent" fullword ascii
        $b = "navigator.platform" fullword ascii
        $c = "navigator.hardwareConcurrency" fullword ascii
        $d = "navigator.deviceMemory" fullword ascii
    condition:
        any of them
}
