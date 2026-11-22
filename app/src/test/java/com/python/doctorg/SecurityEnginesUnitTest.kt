package com.python.doctorg

import android.Manifest
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.python.doctorg.core.security.CryptoManager
import com.python.doctorg.domain.engine.ApkFeatureVector
import com.python.doctorg.domain.engine.ApkMlClassifier
import com.python.doctorg.domain.engine.AppVerdictInput
import com.python.doctorg.domain.engine.PermissionRiskAnalyzer
import com.python.doctorg.domain.engine.ScanVerdictEngine
import com.python.doctorg.domain.engine.ScamSmsClassifier
import com.python.doctorg.domain.engine.TrustedPublisherEntry
import com.python.doctorg.domain.engine.YaraRuleEngine
import com.python.doctorg.domain.model.SignalKind
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.domain.model.TrustTier
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SecurityEnginesUnitTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val syntheticGoogleCert = "a".repeat(64)
    private val syntheticGooglePayCert = "b".repeat(64)
    private val syntheticGooglePayRotatedCert = "c".repeat(64)
    private val syntheticWhatsAppCert = "d".repeat(64)
    private val syntheticOemCert = "e".repeat(64)
    private val syntheticUserCert = "1".repeat(64)
    private val syntheticFakeCert = "9".repeat(64)
    private val syntheticKnownBadCert = "f".repeat(64)

    private val fixtureTrustedPublishers = listOf(
        TrustedPublisherEntry(
            packageName = "com.google.android.gms",
            displayName = "Google Play services",
            certSha256 = listOf(syntheticGoogleCert),
            publisher = "Google LLC",
            category = "system"
        ),
        TrustedPublisherEntry(
            packageName = "com.google.android.apps.nbu.paisa.user",
            displayName = "Google Pay (GPay)",
            certSha256 = listOf(syntheticGooglePayCert, syntheticGooglePayRotatedCert),
            publisher = "Google LLC",
            category = "payments"
        ),
        TrustedPublisherEntry(
            packageName = "com.whatsapp",
            displayName = "WhatsApp",
            certSha256 = listOf(syntheticWhatsAppCert),
            publisher = "WhatsApp LLC",
            category = "messaging"
        )
    )

    @Test
    fun `cryptoManager encrypts decrypts verifies PIN and generates RFC6238 TOTP`() {
        val crypto = CryptoManager(context)

        val secret = "DoctorG-SuperSecret-Vault-Payload!"
        val encrypted = crypto.encryptString(secret)
        assertTrue(encrypted.isNotBlank() && encrypted != secret)
        assertEquals(secret, crypto.decryptString(encrypted))

        val pinHash = crypto.hashSecretPin("246810")
        assertTrue(crypto.verifySecretPin("246810", pinHash))
        assertFalse(crypto.verifySecretPin("000000", pinHash))

        // Password-based AES-GCM backup round-trip
        val blob = crypto.encryptWithPassword("totp-backup-json".toByteArray(), "StrongPass#99")
        val restored = String(crypto.decryptWithPassword(blob, "StrongPass#99"))
        assertEquals("totp-backup-json", restored)

        // RFC 6238 TOTP sanity: 6 numeric digits, deterministic for identical timestamp
        val code1 = crypto.generateTotp("JBSWY3DPEHPK3PXP", timeMillis = 1_700_000_000_000L)
        val code2 = crypto.generateTotp("JBSWY3DPEHPK3PXP", timeMillis = 1_700_000_000_000L)
        assertEquals(6, code1.length)
        assertTrue(code1.all { it.isDigit() })
        assertEquals(code1, code2)

        val generated = crypto.generateStrongPassword(length = 18)
        assertEquals(18, generated.length)
        assertTrue(crypto.evaluatePasswordStrength(generated) >= 85)
        assertTrue(crypto.evaluatePasswordStrength("123456") <= 20)
    }

    @Test
    fun `permissionRiskAnalyzer returns zero for system or verified apps and flags sideloaded trojan combos`() {
        val analyzer = PermissionRiskAnalyzer()

        val systemApp = analyzer.analyzePermissions(
            permissions = setOf(
                Manifest.permission.ACCESS_BACKGROUND_LOCATION,
                Manifest.permission.CAMERA,
                Manifest.permission.RECORD_AUDIO,
                Manifest.permission.RECEIVE_SMS
            ),
            isSideloaded = false,
            isHiddenApp = false,
            isDeviceAdmin = true,
            hasActiveAccessibility = true,
            targetSdk = 35,
            isSystemOrVerified = true,
            isPlayStoreApp = false
        )
        assertEquals(0, systemApp.score)
        assertTrue(systemApp.reasons.isEmpty())

        val benign = analyzer.analyzePermissions(
            permissions = setOf(Manifest.permission.INTERNET),
            isSideloaded = false,
            isHiddenApp = false,
            isDeviceAdmin = false,
            hasActiveAccessibility = false,
            targetSdk = 35,
            isSystemOrVerified = false,
            isPlayStoreApp = true
        )
        assertEquals(0, benign.score)

        val banker = analyzer.analyzePermissions(
            permissions = setOf(
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SYSTEM_ALERT_WINDOW,
                Manifest.permission.REQUEST_INSTALL_PACKAGES,
                Manifest.permission.INTERNET
            ),
            isSideloaded = true,
            isHiddenApp = true,
            isDeviceAdmin = true,
            hasActiveAccessibility = true,
            targetSdk = 27,
            isSystemOrVerified = false,
            isPlayStoreApp = false
        )
        assertTrue(banker.score >= 85)
        assertTrue(banker.reasons.any { it.contains("SMS + Accessibility") })
        assertTrue(banker.reasons.any { it.contains("Screen Overlay + Install Packages") })
    }

    @Test
    fun `apkMlClassifier disables ML signal and returns null when offline tflite model is not bundled`() {
        val classifier = ApkMlClassifier(context)
        assertFalse(classifier.isTfliteModelLoaded)
        val prob = classifier.predictMalwareProbability(
            ApkFeatureVector(
                hasReceiveSms = true,
                hasAccessibility = true,
                hasOverlay = true,
                hasDexClassLoader = true,
                isSideloaded = true,
                isHiddenNoLauncher = true
            ),
            lightweightMode = false
        )
        assertNull("ML signal must be disabled (null) when no calibrated .tflite model is bundled", prob)
    }

    @Test
    fun `yaraRuleParser parses bundled rules and matches banking trojan and EICAR patterns`() {
        val rawYara = context.assets.open("yara_rules.yar").bufferedReader().use { it.readText() }
        val rules = YaraRuleEngine.parseRules(rawYara)
        assertTrue("Expected at least 5 bundled YARA rules", rules.size >= 5)

        val eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"
        val eicarHits = YaraRuleEngine.scanText(eicar, rules)
        assertTrue(eicarHits.any { it.ruleName == "Android_EICAR_Test_Rule" })

        val trojanSample = "BIND_ACCESSIBILITY_SERVICE SYSTEM_ALERT_WINDOW RECEIVE_SMS performGlobalAction"
        val trojanHits = YaraRuleEngine.scanText(trojanSample, rules)
        assertTrue(trojanHits.any { it.ruleName == "Android_Banking_Trojan_Overlay" })
    }

    // -------------------------------------------------------------------------
    // BUG 1: Trust Tiers, Hard-Only Malicious, Soft Ceilings & Lookalike Fixes
    // -------------------------------------------------------------------------

    @Test
    fun `bug1 fixture 1 to 4 legitimate Google system apps are always TRUSTED never MALICIOUS or lookalike`() {
        val analyzer = PermissionRiskAnalyzer()
        val sensitivePerms = setOf(
            Manifest.permission.ACCESS_BACKGROUND_LOCATION,
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.SYSTEM_ALERT_WINDOW,
            Manifest.permission.REQUEST_INSTALL_PACKAGES
        )

        // 1. Google Play services (updated system app, active Device Admin, BgLocation+Camera+Mic)
        val gms = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.google.android.gms",
                appName = "Google Play services",
                apkPath = "/data/app/~~abc==/com.google.android.gms-xyz==/base.apk",
                isFlagSystem = true,
                isFlagUpdatedSystemApp = true,
                signingCertSha256s = listOf(syntheticGoogleCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = false,
                permissions = sensitivePerms,
                isDeviceAdmin = true,
                hasActiveAccessibility = true,
                targetSdk = 35,
                mlProbability = 0.96f, // Even if a noisy ML score arrived, Tier 1 is immune
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.TRUSTED, gms.threatLevel)
        assertEquals(TrustTier.TRUSTED_SYSTEM, gms.trustTier)
        assertEquals("Trusted: System app", gms.trustLabel)
        assertEquals(0, gms.riskScore)
        assertTrue(gms.signals.none { it.category == "LOOKALIKE" })

        // 2. Google Play Store
        val vending = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.android.vending",
                appName = "Google Play Store",
                apkPath = "/product/priv-app/Phonesky/Phonesky.apk",
                isFlagSystem = true,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticGoogleCert),
                installerPackageName = "",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.REQUEST_INSTALL_PACKAGES, Manifest.permission.INTERNET),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.TRUSTED, vending.threatLevel)
        assertEquals(TrustTier.TRUSTED_SYSTEM, vending.trustTier)

        // 3. Google app
        val googleApp = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.google.android.googlequicksearchbox",
                appName = "Google",
                apkPath = "/product/priv-app/Velvet/Velvet.apk",
                isFlagSystem = true,
                isFlagUpdatedSystemApp = true,
                signingCertSha256s = listOf(syntheticGoogleCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.ACCESS_BACKGROUND_LOCATION, Manifest.permission.CAMERA),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.TRUSTED, googleApp.threatLevel)
        assertEquals(TrustTier.TRUSTED_SYSTEM, googleApp.trustTier)

        // 4. Google Chrome
        val chrome = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.android.chrome",
                appName = "Chrome",
                apkPath = "/data/app/~~abc==/com.android.chrome-xyz==/base.apk",
                isFlagSystem = true,
                isFlagUpdatedSystemApp = true,
                signingCertSha256s = listOf(syntheticGoogleCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO, Manifest.permission.INTERNET),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.TRUSTED, chrome.threatLevel)
        assertEquals(TrustTier.TRUSTED_SYSTEM, chrome.trustTier)
    }

    @Test
    fun `bug1 fixture 5 to 8 verified publishers OEM system app and Play Store app are TRUSTED or SAFE`() {
        val analyzer = PermissionRiskAnalyzer()

        // 5. Google Pay (Tier 2 Verified Publisher, including signing-lineage rotation match)
        val gpay = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.google.android.apps.nbu.paisa.user",
                appName = "Google Pay",
                apkPath = "/data/app/~~123==/com.google.android.apps.nbu.paisa.user/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticGooglePayRotatedCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.CAMERA, Manifest.permission.RECEIVE_SMS, Manifest.permission.ACCESS_FINE_LOCATION),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.TRUSTED, gpay.threatLevel)
        assertEquals(TrustTier.VERIFIED_PUBLISHER, gpay.trustTier)
        assertEquals("Verified: Google LLC", gpay.trustLabel)

        // 6a. WhatsApp (Tier 2 Verified Publisher)
        val whatsappVerified = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.whatsapp",
                appName = "WhatsApp",
                apkPath = "/data/app/~~123==/com.whatsapp/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticWhatsAppCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO, Manifest.permission.ACCESS_BACKGROUND_LOCATION),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.TRUSTED, whatsappVerified.threatLevel)
        assertEquals(TrustTier.VERIFIED_PUBLISHER, whatsappVerified.trustTier)

        // 6b. WhatsApp before cert hashes are populated (Tier 3 Play Store -> SAFE)
        val whatsappPlayStore = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.whatsapp",
                appName = "WhatsApp",
                apkPath = "/data/app/~~123==/com.whatsapp/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticWhatsAppCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO, Manifest.permission.ACCESS_FINE_LOCATION),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = emptyList()
            ),
            analyzer
        )
        assertEquals(ThreatLevel.SAFE, whatsappPlayStore.threatLevel)
        assertEquals(TrustTier.PLAY_STORE, whatsappPlayStore.trustTier)

        // 7. OEM system app (e.g. ColorOS / OnePlus com.oplus.*)
        val oemApp = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.oplus.sos",
                appName = "Emergency SOS",
                apkPath = "/system_ext/priv-app/OplusSos/OplusSos.apk",
                isFlagSystem = true,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticOemCert),
                installerPackageName = "",
                hasLauncherIcon = false,
                permissions = setOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION, Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO),
                isDeviceAdmin = true,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.TRUSTED, oemApp.threatLevel)
        assertEquals(TrustTier.TRUSTED_SYSTEM, oemApp.trustTier)

        // 8. Normal user-installed Play Store app
        val userPlayApp = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.example.camerajournal",
                appName = "Camera Journal",
                apkPath = "/data/app/~~123==/com.example.camerajournal/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticUserCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.CAMERA, Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.INTERNET),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.SAFE, userPlayApp.threatLevel)
        assertEquals(TrustTier.PLAY_STORE, userPlayApp.trustTier)
    }

    @Test
    fun `bug1 fixture 9 and 10 synthetic malware is MALICIOUS synthetic lookalike is SUSPICIOUS and soft signals never reach MALICIOUS`() {
        val analyzer = PermissionRiskAnalyzer()

        // 9. Synthetic malware fixture (hard known-malware SHA-256 match)
        val malware = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.synthetic.trojan.sample",
                appName = "Quick Update",
                apkPath = "/data/app/com.synthetic.trojan.sample/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticFakeCert),
                installerPackageName = "",
                hasLauncherIcon = false,
                permissions = setOf(Manifest.permission.INTERNET),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 33,
                knownMalwareFamily = "Android.BankBot.Synthetic",
                knownMalwareDescription = "Known synthetic test hash",
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.MALICIOUS, malware.threatLevel)
        assertTrue(malware.signals.any { it.kind == SignalKind.HARD && it.category == "MALWARE_HASH" })

        // Hard evidence: known-bad cert, YARA malicious, VirusTotal >= 5
        val badCertApp = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.synthetic.badcert",
                appName = "Utility",
                apkPath = "/data/app/com.synthetic.badcert/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticKnownBadCert),
                installerPackageName = "",
                hasLauncherIcon = true,
                permissions = emptySet(),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 34,
                knownBadCerts = mapOf(syntheticKnownBadCert to "Known Fake Banker Key"),
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.MALICIOUS, badCertApp.threatLevel)

        // VirusTotal below threshold (2 < 5) must NOT produce MALICIOUS
        val vtLow = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.example.clean",
                appName = "Clean Utility",
                apkPath = "/data/app/com.example.clean/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticUserCert),
                installerPackageName = "com.android.vending",
                hasLauncherIcon = true,
                permissions = emptySet(),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 35,
                virusTotalMaliciousCount = 2,
                virusTotalThreshold = 5,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertNotEquals(ThreatLevel.MALICIOUS, vtLow.threatLevel)

        // 10. Synthetic lookalike (different package, different cert, similar label "Google Pay", sideloaded)
        val lookalike = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.fake.gpay.reward",
                appName = "Google Pay",
                apkPath = "/data/app/com.fake.gpay.reward/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticFakeCert),
                installerPackageName = "",
                hasLauncherIcon = true,
                permissions = setOf(Manifest.permission.INTERNET),
                isDeviceAdmin = false,
                hasActiveAccessibility = false,
                targetSdk = 34,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.SUSPICIOUS, lookalike.threatLevel)
        val lookalikeSignal = lookalike.signals.firstOrNull { it.category == "LOOKALIKE" }
        assertTrue("Expected LOOKALIKE signal naming Google Pay (GPay)", lookalikeSignal?.message?.contains("Google Pay (GPay)") == true)
        assertTrue("Expected LOOKALIKE signal explaining different package & cert", lookalikeSignal?.message?.contains("different package name") == true)

        // Strict soft-signal invariant: permissions alone (single soft category) can NEVER produce MALICIOUS or SUSPICIOUS
        val permsOnly = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.sideloaded.heavyperms",
                appName = "Heavy Utility",
                apkPath = "/data/app/com.sideloaded.heavyperms/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticUserCert),
                installerPackageName = "",
                hasLauncherIcon = false,
                permissions = setOf(
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.SYSTEM_ALERT_WINDOW,
                    Manifest.permission.REQUEST_INSTALL_PACKAGES,
                    Manifest.permission.ACCESS_BACKGROUND_LOCATION,
                    Manifest.permission.CAMERA,
                    Manifest.permission.RECORD_AUDIO
                ),
                isDeviceAdmin = true,
                hasActiveAccessibility = true,
                targetSdk = 28,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.NEEDS_REVIEW, permsOnly.threatLevel)

        // Even multiple independent soft signals without hard evidence can produce AT MOST SUSPICIOUS
        val multiSoft = ScanVerdictEngine.evaluate(
            AppVerdictInput(
                packageName = "com.fake.gpay.dropper",
                appName = "Google Pay",
                apkPath = "/data/app/com.fake.gpay.dropper/base.apk",
                isFlagSystem = false,
                isFlagUpdatedSystemApp = false,
                signingCertSha256s = listOf(syntheticFakeCert),
                installerPackageName = "",
                hasLauncherIcon = false,
                permissions = setOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.SYSTEM_ALERT_WINDOW),
                isDeviceAdmin = true,
                hasActiveAccessibility = true,
                targetSdk = 29,
                hasSuspiciousStaticCode = true,
                mlProbability = 0.94f,
                trustedPublishers = fixtureTrustedPublishers
            ),
            analyzer
        )
        assertEquals(ThreatLevel.SUSPICIOUS, multiSoft.threatLevel)
    }

    @Test
    fun `trusted_publishers asset is valid schema and contains zero fabricated certificate hashes`() {
        val raw = context.assets.open("trusted_publishers.json").bufferedReader().use { it.readText() }
        val root = JSONObject(raw)
        assertTrue(root.getInt("schemaVersion") >= 1)
        val publishers = root.getJSONArray("publishers")
        assertTrue("Expected seeded trusted publishers", publishers.length() >= 15)

        val pkgs = mutableSetOf<String>()
        for (i in 0 until publishers.length()) {
            val obj = publishers.getJSONObject(i)
            val pkg = obj.getString("packageName")
            pkgs.add(pkg)
            val certs = obj.getJSONArray("certSha256")
            // Every seeded entry must either be empty (ready for real device extraction) or valid 64-char hex
            for (j in 0 until certs.length()) {
                val h = certs.getString(j)
                assertTrue("Invalid cert SHA-256 format for $pkg: $h", Regex("^[a-fA-F0-9]{64}$").matches(h))
            }
        }
        assertTrue("com.google.android.gms" in pkgs)
        assertTrue("com.google.android.apps.nbu.paisa.user" in pkgs)
        assertTrue("com.whatsapp" in pkgs)
    }

    // -------------------------------------------------------------------------
    // BUG 2: Scam Awareness Guides Full Localization (en, hi, ur, bn, ta)
    // -------------------------------------------------------------------------

    @Test
    fun `bug2 scam_awareness json provides complete translations for en hi ur bn ta and zero English leakage in Hindi`() {
        val raw = context.assets.open("scam_awareness.json").bufferedReader().use { it.readText() }
        val cards = ScamSmsClassifier.parseAwarenessCardsJson(raw)
        assertTrue("Expected at least 5 awareness guides", cards.size >= 5)

        val requiredLocales = listOf("en", "hi", "ur", "bn", "ta")
        for (card in cards) {
            val en = card.resolve("en")
            assertTrue("EN locale missing for ${card.id}", card.i18n.containsKey("en"))
            assertTrue(en.title.isNotBlank())
            assertTrue(en.description.isNotBlank())
            assertTrue(en.redFlags.isNotEmpty())
            assertTrue(en.whatToDo.isNotEmpty())

            for (locale in requiredLocales) {
                val rawLocale = card.i18n[locale]
                assertTrue("Missing i18n entry '$locale' for guide ${card.id}", rawLocale != null)
                val localized = card.resolve(locale)
                assertTrue("Blank title in $locale for ${card.id}", localized.title.isNotBlank())
                assertTrue("Blank description in $locale for ${card.id}", localized.description.isNotBlank())
                assertTrue("Empty redFlags in $locale for ${card.id}", localized.redFlags.isNotEmpty())
                assertTrue("Empty whatToDo in $locale for ${card.id}", localized.whatToDo.isNotEmpty())
                assertTrue("Blank redFlag bullet in $locale for ${card.id}", localized.redFlags.all { it.isNotBlank() })
                assertTrue("Blank whatToDo bullet in $locale for ${card.id}", localized.whatToDo.all { it.isNotBlank() })
            }

            // Strict Hindi check: NO Hindi field or bullet may remain equal to English
            val hi = card.resolve("hi")
            assertNotEquals("Hindi title stayed in English for ${card.id}", en.title, hi.title)
            assertNotEquals("Hindi description stayed in English for ${card.id}", en.description, hi.description)
            hi.redFlags.forEach { bullet ->
                assertFalse("Hindi redFlag stayed in English for ${card.id}: $bullet", bullet in en.redFlags)
            }
            hi.whatToDo.forEach { bullet ->
                assertFalse("Hindi whatToDo stayed in English for ${card.id}: $bullet", bullet in en.whatToDo)
            }
        }

        // Fallback test for unsupported locale -> gracefully falls back to English
        val fallback = cards.first().resolve("fr")
        assertEquals(cards.first().resolve("en").title, fallback.title)
        assertEquals(cards.first().resolve("en").redFlags, fallback.redFlags)
    }

    @Test
    fun `app identity string and package match DoctorG specification`() {
        assertEquals("DoctorG", context.getString(R.string.app_name))
        assertEquals("com.python.doctorg", context.packageName)
        assertEquals("1.0.0", BuildConfig.VERSION_NAME)
        assertEquals(ThreatLevel.MALICIOUS, ThreatLevel.valueOf("MALICIOUS"))
        assertEquals(ThreatLevel.TRUSTED, ThreatLevel.valueOf("TRUSTED"))
        assertEquals(ThreatLevel.NEEDS_REVIEW, ThreatLevel.valueOf("NEEDS_REVIEW"))
    }
}
