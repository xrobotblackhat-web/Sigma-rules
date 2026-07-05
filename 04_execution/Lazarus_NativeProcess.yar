rule Lazarus_NativeProcess {
    meta:
        description = "Detects imports of NtCreateUserProcess and related native APIs (Lazarus group signature)"
        severity = "critical"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "NtCreateUserProcess" fullword ascii
        $b = "ZwCreateUserProcess" fullword ascii
        $c = "NtCreateThreadEx" fullword ascii
        $d = "ZwCreateThreadEx" fullword ascii
    condition:
        (any of ($a,$b)) and (any of ($c,$d))
}
