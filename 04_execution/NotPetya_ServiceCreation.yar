rule NotPetya_ServiceCreation {
    meta:
        description = "Detects service creation APIs often abused by NotPetya and other ransomware"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1543"
        attack.id = "T1543"
    strings:
        $a = "CreateService" fullword ascii
        $b = "OpenSCManager" fullword ascii
        $c = "DeleteService" fullword ascii
    condition:
        any of them
}
