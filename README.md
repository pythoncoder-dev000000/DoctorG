# DoctorG — Open-Source, Offline-First Android Security Suite

**DoctorG** (`com.python.doctorg`, `v1.0.0`) is a complete, private, open-source Android security suite built with Kotlin, Jetpack Compose, Material 3 Adaptive layouts, Hilt, Room, SQLCipher (16 KB page-size aligned), LiteRT (TensorFlow Lite 16 KB aligned), CameraX, ML Kit, WorkManager, and Jetpack Glance.

- **100% Offline & Private**: Zero custom backend, zero Firebase, zero cloud accounts, zero ads, zero analytics, and zero monetization.
- **User Always in Control**: Every permission is requested strictly just-in-time with a clear explanation before Android's system prompt. Denied permissions never block the app.


## Download

[![Download APK](https://img.shields.io/badge/Download-APK-green?style=for-the-badge&logo=android)](https://github.com/pythoncoder-dev000000/DoctorG/releases/latest)

Latest release: https://github.com/pythoncoder-dev000000/DoctorG/releases/latest

### Install
1. Open the link above and download the `.apk` file from **Assets**.
2. Allow "Install unknown apps" for your browser or file manager when asked.
3. Open the APK and tap Install. Play Protect may show a warning for apps from outside the Play Store. This is expected.
4. If Play Protect blocks the installation, tap **More details > Install anyway**. If the app still does not install, temporarily turn off **Scan apps with Play Protect** (Play Store > profile icon > Play Protect > Settings), install DoctorG, and then turn it back on.

Requires Android 8.0 or newer.

## Screenshots

| Home | Scan result with "Why?" | Scam guides | App Lock |
|------|-------------------------|-------------|----------|
| <img src="PASTE_IMAGE_1" width="200"> | <img src="PASTE_IMAGE_2" width="200"> | <img src="PASTE_IMAGE_3" width="200"> | <img src="PASTE_IMAGE_4" width="200"> |

### Verify your download
Compare the SHA-256 checksum shown in the release notes with your file.

---

## Replacing the DoctorG Logo

DoctorG uses `app/src/main/res/drawable/doctorg_logo.png` across the adaptive launcher icon, SplashScreen, Onboarding, Home top bar, and About screen.

To replace the logo in **Android Studio**:
1. Replace `app/src/main/res/drawable/doctorg_logo.png` with your updated square PNG asset.
2. Open **Android Studio > File > New > Image Asset** (or right-click `app/src/main/res > New > Image Asset`).
3. Set **Icon Type** to `Launcher Icons (Adaptive and Legacy)`.
4. Select your image as the **Foreground Layer** (`ic_launcher_foreground`) and choose your matching solid color (`#0F143A` by default, defined in `ui/theme/Color.kt`) for the **Background Layer** (`ic_launcher_background`).
5. Optionally update `app/src/main/res/drawable/ic_launcher_monochrome.xml` for Android 13+ themed icons.

---

## Feature Availability Map (API Level & Fallback)

| Feature | Minimum API | Fallback / Graceful Degradation |
|---|---|---|
| Core Quick & Full Malware Scanner, YARA, ML, Room DB | API 26 (Android 8.0) | Runs fully offline on all devices (no Google Play services required) |
| SQLCipher 256-bit Vault & 2FA TOTP Authenticator | API 26 | Hardware Android Keystore AES-256-GCM wrapping |
| Local VPN DNS Filter & Per-App Firewall | API 26 | Works via `VpnService` loopback without external servers |
| BiometricPrompt (Vault / App Lock) | API 26 (Compat) | Falls back cleanly to PBKDF2-hashed PIN when biometric hardware is absent |
| SplashScreen API (`core-splashscreen`) | API 26 (Compat) | Uses Android 12+ native SplashScreen and compat theme on API 26–30 |
| All-Files Storage Scan (`MANAGE_EXTERNAL_STORAGE`) | API 30 (Android 11) | Uses standard storage access on API 26–29; skips stage gracefully if denied |
| Material You Dynamic Color | API 31 (Android 12) | Falls back to DoctorG signature Midnight Indigo / Emerald static M3 palette |
| BLE Tracker Scan (`neverForLocation`) | API 31 (Android 12) | Uses `ACCESS_FINE_LOCATION` on API 26–30; hidden on devices without BLE |
| Exact Alarms (`SCHEDULE_EXACT_ALARM`) | API 31 (Android 12) | Standard WorkManager periodic scheduling on API 26–30 |
| Post Notifications Runtime Prompt & Monochrome Themed Icon | API 33 (Android 13) | Notifications allowed at install on API 26–32; Restricted Settings guide shown on API 33+ |
| Foreground Service Types (`dataSync` / `specialUse`) | API 34 (Android 14) | Declared in manifest; backward-compatible on API 26–33 |
| 16 KB Page-Size Native Libraries (SQLCipher 4.6.1, LiteRT 1.4.0) | API 35+ (Android 15/16) | Packaged uncompressed (`useLegacyPackaging = false`) across `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` |
| Location Tool (`FusedLocationProvider`) | API 26 | Automatically falls back to Android `LocationManager` when Google Play Services is unavailable |
| QR Code Scanner & Intruder Selfie | API 26 | Hidden gracefully when device has no camera hardware |
| Scam Call Guard & SMS Inspection | API 26 | Hidden/noted gracefully on Wi-Fi-only tablets without SIM/telephony |

---

## Device Compatibility Matrix

DoctorG is engineered and configured (including Gradle Managed Devices in `app/build.gradle.kts`) for:
- **Android Versions**: Android 8.0 (API 26) through Android 16 (API 36).
- **Small & Large Phones**: Compact `WindowSizeClass` with bottom navigation bar, edge-to-edge safe insets, up to 200% font scaling.
- **Tablets & ChromeOS**: Medium (`NavigationRail`) and Expanded (Permanent Drawer + Two-Pane List-Detail for Scan Results + App Detail and Vault List + Item Detail).
- **Foldables**: `androidx.window` `WindowInfoTracker` posture awareness (Book two-pane avoiding hinge; Tabletop mode for Safety Siren & Camera tools).
- **Low-RAM / Android Go (≤ 2 GB RAM)**: Streaming 8 KB SHA-256 hashing, bounded-memory ZIP/DEX YARA reading, `ScanIntensity.LOW`, and Lightweight Mode disabling heavy animations & ML inference.
- **RTL Languages**: Full start/end layout support including Urdu (`res/values-ur/strings.xml`).
- **Google-Play-Services-Free Devices**: Huawei, custom ROMs, and AOSP devices run all core protection modules without Play Services.

---

## Static GitHub Feeds Without a Backend

DoctorG fetches versioned static JSON/text threat feeds from a user-configurable HTTPS GitHub raw/releases base URL (`Tools > Settings & Feeds`) and verifies a SHA-256 checksum from `manifest.json` before importing into Room:

```json
{
  "version": "2026.11.20",
  "files": {
    "malware_hashes.json": "<sha256-hex>",
    "yara_rules.yar": "<sha256-hex>",
    "official_apps.json": "<sha256-hex>",
    "stalkerware_list.json": "<sha256-hex>",
    "blocklist_domains.txt": "<sha256-hex>",
    "spam_numbers.json": "<sha256-hex>",
    "scam_patterns.json": "<sha256-hex>",
    "scam_awareness.json": "<sha256-hex>",
    "android_cves.json": "<sha256-hex>"
  }
}
```
If offline or checksum verification fails, DoctorG automatically retains its verified local Room database and bundled starter assets.

---

## Training On-Device TensorFlow Lite / LiteRT Models

```bash
pip install numpy tensorflow
python3 ml/train_apk_malware_classifier.py --output app/src/main/assets/apk_malware_classifier.tflite
python3 ml/train_scam_sms_classifier.py --output app/src/main/assets/scam_sms_classifier.tflite
```
If `.tflite` binaries are not bundled, `ApkMlClassifier` and `ScamSmsClassifier` fall back gracefully to calibrated on-device logistic scoring.

---

## Running Tests

```bash
# Fast JVM Unit + Robolectric Adaptive Compose UI tests
gradle :app:testDebugUnitTest

# Gradle Managed Devices (Pixel 8, Pixel Tablet, Pixel Fold, Low-RAM API 28)
gradle :app:allDevicesCheck
```
