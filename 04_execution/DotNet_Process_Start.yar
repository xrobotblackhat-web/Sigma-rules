rule DotNet_Process_Start {
    meta:
        description = "Detects .NET Process.Start usage (common in C# malware)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "Process.Start" fullword ascii
        $b = "System.Diagnostics.Process" fullword ascii
        $c = "ProcessStartInfo" fullword ascii
    condition:
        any of them
}
