rule HawkEye_Keylogger {
    meta:
        description = "Detects HawkEye Keylogger strings and artifacts"
        author = "HookShield"
        threat_level = "High"
    strings:
        $s1 = "HawkEye Keylogger" ascii wide nocase
        $s2 = "HolderMail" ascii wide
        $s3 = "HawkEye_Keylogger" ascii wide nocase
        $s4 = "KeylogRecords" ascii wide
    condition:
        2 of them
}

rule AgentTesla_Keylogger {
    meta:
        description = "Detects Agent Tesla Keylogger strings and behavior"
        author = "HookShield"
        threat_level = "High"
    strings:
        $s1 = "Agent Tesla" ascii wide nocase
        $s2 = "IELibrary.dll" ascii wide
        $s3 = "GetClipboardData" ascii wide
        $s4 = "get_Clipboard" ascii wide
        $s5 = "smtpserver" ascii wide nocase
    condition:
        3 of them
}

rule Snake_Keylogger {
    meta:
        description = "Detects Snake Keylogger strings"
        author = "HookShield"
        threat_level = "High"
    strings:
        $s1 = "Snake Keylogger" ascii wide nocase
        $s2 = "SnakeKeylogger" ascii wide nocase
        $s3 = "Scrlogtimerrr" ascii wide
        $s4 = "ScreenshotLoggerTimer" ascii wide
    condition:
        2 of them
}
