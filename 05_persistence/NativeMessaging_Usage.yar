rule NativeMessaging_Usage {
    meta:
        description = "Detects use of chrome.runtime.connectNative (native messaging) – often for sandbox escape"
        severity = "critical"
        attack.tactic = "TA0003"
        attack.technique = "T1546"
        attack.id = "T1546"
    strings:
        $a = "connectNative" fullword ascii
        $b = "nativeMessaging" fullword ascii
        $c = "sendNativeMessage" fullword ascii
    condition:
        any of them
}
