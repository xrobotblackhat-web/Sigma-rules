rule COM_CLSIDs {
    meta:
        description = "Looks for well-known COM CLSIDs used for process launch"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"  // ShellWindows
        $b = "{13709620-C279-11CE-A49E-444553540000}"  // Shell.Application
        $c = "{00024500-0000-0000-C000-000000000046}"  // Microsoft Word
    condition:
        any of them
}
