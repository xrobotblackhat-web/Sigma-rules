rule AgentTesla_DotNetInstallers {
    meta:
        description = "Detects use of RegAsm, RegSvcs (Agent Tesla often abuses .NET installers)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1218"
        attack.id = "T1218"
    strings:
        $a = "RegAsm" fullword ascii
        $b = "RegSvcs" fullword ascii
    condition:
        any of them
}
