rule NativeMessaging_Send {
    meta:
        description = "Detects sending message via native messaging (sandbox escape)"
        severity = "critical"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "chrome.runtime.sendNativeMessage" fullword ascii
        $b = "connectNative" fullword ascii
    condition:
        any of them
}
