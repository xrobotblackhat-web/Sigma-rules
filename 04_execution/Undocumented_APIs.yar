rule Undocumented_APIs {
    meta:
        description = "Detects imports of undocumented NT functions often used by malware"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "RtlCreateProcessParameters" fullword ascii
        $b = "RtlDestroyProcessParameters" fullword ascii
        $c = "RtlCreateUserProcess" fullword ascii
        $d = "NtRaiseHardError" fullword ascii
        $e = "NtQueryInformationProcess" fullword ascii
    condition:
        any of them
}
