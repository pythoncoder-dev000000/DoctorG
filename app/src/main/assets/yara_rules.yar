rule Android_Banking_Trojan_Overlay {
    meta:
        description = "Detects banking trojan combining AccessibilityService, Overlay, and SMS interception"
        severity = "MALICIOUS"
    strings:
        $a1 = "BIND_ACCESSIBILITY_SERVICE"
        $a2 = "SYSTEM_ALERT_WINDOW"
        $a3 = "RECEIVE_SMS"
        $a4 = "performGlobalAction"
    condition:
        3 of them
}

rule Android_Dynamic_Dex_Dropper {
    meta:
        description = "Detects dynamic DEX loading combined with runtime shell execution"
        severity = "SUSPICIOUS"
    strings:
        $s1 = "dalvik/system/DexClassLoader"
        $s2 = "java/lang/Runtime;->exec"
        $s3 = "InMemoryDexClassLoader"
        $s4 = "REQUEST_INSTALL_PACKAGES"
    condition:
        2 of them
}

rule Android_SMS_OTP_Stealer {
    meta:
        description = "Detects SMS OTP harvesting and forwarding behavior"
        severity = "MALICIOUS"
    strings:
        $s1 = "android.provider.Telephony.SMS_RECEIVED"
        $s2 = "getMessageBody"
        $s3 = "sendTextMessage"
        $s4 = "SmsManager"
    condition:
        3 of them
}

rule Android_Spyware_Hidden_Surveillance {
    meta:
        description = "Detects stealth surveillance combining component hiding with mic/location capture"
        severity = "MALICIOUS"
    strings:
        $s1 = "setComponentEnabledSetting"
        $s2 = "MediaRecorder"
        $s3 = "ACCESS_BACKGROUND_LOCATION"
        $s4 = "READ_CALL_LOG"
    condition:
        3 of them
}

rule Android_Ransomware_Crypto_Locker {
    meta:
        description = "Detects bulk file encryption and ransom demand indicators"
        severity = "MALICIOUS"
    strings:
        $s1 = "javax/crypto/Cipher"
        $s2 = "EXTERNAL_STORAGE"
        $s3 = "bitcoin"
        $s4 = "your files have been encrypted"
    condition:
        3 of them
}

rule Android_EICAR_Test_Rule {
    meta:
        description = "Standard EICAR test pattern for verifying DoctorG YARA engine"
        severity = "MALICIOUS"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        1 of them
}
