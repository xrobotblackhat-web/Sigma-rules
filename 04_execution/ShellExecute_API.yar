rule ShellExecute_API {
    meta:
        description = "Detects import of ShellExecute or ShellExecuteEx"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "ShellExecuteA" fullword ascii
        $b = "ShellExecuteW" fullword ascii
        $c = "ShellExecuteEx" fullword ascii
        $d = "ShellExec_RunDLLW" fullword ascii
        $e = "RunAsNewUser_RunDLLW" fullword ascii
    condition:
        any of them
}
