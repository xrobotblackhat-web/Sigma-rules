rule Fingerprinting_Audio {
    meta:
        description = "Detects audio fingerprinting (AudioContext)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1082"
        attack.id = "T1082"
    strings:
        $a = "AudioContext" fullword ascii
        $b = "createAnalyser" fullword ascii
        $c = "getByteTimeDomainData" fullword ascii
    condition:
        any of them
}
