rule Ransomware_Generic {
    meta:
        description = "Detects generic ransomware strings and APIs"
        author = "DragonCode"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
        $s2 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $s3 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii wide nocase
        $s4 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $s5 = ".onion" ascii nocase
        $btc1 = "bc1" ascii wide
        $btc2 = "1" ascii wide
        $onion1 = ".onion" ascii fullword
    condition:
        2 of ($s*) or ($onion1 and 1 of ($btc*))
}

rule RAT_Behaviors {
    meta:
        description = "Detects common RAT strings like keylogging and webcam"
    strings:
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetKeyboardState" ascii wide
        $api3 = "capCreateCaptureWindow" ascii wide
        $cam1 = "webcam" nocase ascii wide
        $cam2 = "camera" nocase ascii wide
    condition:
        all of ($api*) or ($api1 and 1 of ($cam*))
}

rule Powershell_Encoded {
    meta:
        description = "Suspicious powershell execution"
    strings:
        $p1 = "powershell" ascii wide nocase
        $p2 = "-enc" ascii wide nocase
        $p3 = "-EncodedCommand" ascii wide nocase
        $p4 = "-w hidden" ascii wide nocase
    condition:
        $p1 and 1 of ($p2, $p3, $p4)
}

rule UPX_Packed {
    meta:
        description = "Detects UPX Packing"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $u3 = "UPX2"
    condition:
        (uint16(0) == 0x5a4d) and all of ($u*)
}
