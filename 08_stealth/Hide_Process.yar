rule Hide_Process {
    meta:
        description = "Detects API used to hide processes via unhooking or similar (e.g., NtSetInformationProcess)"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1480"
        attack.id = "T1480"
    strings:
        $a = "NtSetInformationProcess" fullword ascii
        $b = "ZwSetInformationProcess" fullword ascii
        $c = "SetProcessInformation" fullword ascii
    condition:
        any of them
}
