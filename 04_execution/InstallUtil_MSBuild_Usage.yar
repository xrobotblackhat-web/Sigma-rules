rule InstallUtil_MSBuild_Usage {
    meta:
        description = "Detects use of InstallUtil.exe or MSBuild.exe (proxy execution via .NET)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1218.004"
        attack.id = "T1218.004"
    strings:
        $a = "InstallUtil.exe" fullword ascii wide
        $b = "MSBuild.exe" fullword ascii wide
        $c = "PresentationHost.exe" fullword ascii wide
    condition:
        any of them
}
