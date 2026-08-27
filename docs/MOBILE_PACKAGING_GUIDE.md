# 📱 AegisChat Mobile Packaging & Cross-Platform Deployment Guide

AegisChat is architected from the ground up to be a **unified cross-platform end-to-end-encrypted application** across **PC (Windows / macOS / Linux)**, **Android**, and **iOS**.

---

## 🏛️ Architectural Overview

```
                        ┌─────────────────────────────────────┐
                        │      AegisChat React Frontend       │
                        │   (Tailwind / Responsive Mobile)    │
                        └──────────────────┬──────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │       Tauri v2 Mobile Bridge        │
                        └─────────┬─────────────────┬─────────┘
                                  │                 │
                ┌─────────────────┴──────┐   ┌──────┴──────────────────┐
                │   Android NDK Layer    │   │     iOS Swift/C-ABI     │
                │ (.so shared libraries) │   │ (.framework static lib) │
                └─────────┬──────────────┘   └──────┬──────────────────┘
                          │                         │
                          └─────────────┬───────────┘
                                        │
                        ┌───────────────┴─────────────────────┐
                        │     aegis-core-crypto (Rust)        │
                        │ • Argon2id Key Derivation           │
                        │ • BIP-39 Zero-Anchor Onboarding     │
                        │ • X3DH Key Agreement & Ratchet      │
                        │ • Memory Scrubbing (ZeroizeOnDrop)  │
                        └─────────────────────────────────────┘
```

> **Important:** `core-crypto/` (Rust) is **reference code and is not yet wired
> into the running app** — the shipping client uses the TypeScript
> implementation in `client/src/crypto/`. The properties below describe what the
> Rust core is designed for once it is on the live path; today they do **not**
> apply to the mobile builds produced by this guide. See
> [`THREAT_MODEL.md`](THREAT_MODEL.md).

Intended, once wired in:
1. **RAM scrubbing** of secrets via `ZeroizeOnDrop` (the web/TS layer cannot do this reliably).
2. Constant-time ChaCha20-Poly1305 / Curve25519 from the RustCrypto crates, compiled natively.
3. No mandatory Google Play Services or Apple iCloud dependency for the app to function (sideload-friendly), which reduces — but does not by itself provide — censorship resistance.

---

## 🤖 1. Android Packaging (.apk / .aab)

### Prerequisites (Windows / Linux / macOS)

1. **Java 17 JDK**:
   * Windows (PowerShell):
     ```powershell
     winget install EclipseAdoptium.Temurin.17.JDK
     ```
   * Ensure `JAVA_HOME` environment variable is set:
     ```powershell
     [System.Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Program Files\Eclipse Adoptium\jdk-17...", "User")
     ```

2. **Android Studio & SDK Command-Line Tools**:
   * Download and install [Android Studio](https://developer.android.com/studio).
   * In Android Studio, open **Settings > Languages & Frameworks > Android SDK**:
     * Under **SDK Platforms**: Check `Android 14.0 (API 34)` and `Android 15.0 (API 35)`.
     * Under **SDK Tools**: Check `Android SDK Build-Tools`, `NDK (Side by side) 26.x+`, and `CMake`.
   * Set `ANDROID_HOME` in environment variables:
     ```powershell
     $env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
     ```

3. **Install Rust Android Toolchain Targets**:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
   ```

---

### Android Build Commands

From the root project directory (`D:\newapp`):

#### Step 1: Initialize the Android Project Scaffold
```bash
npm run mobile:android:init
```
This generates the native Gradle Android project inside `client/src-tauri/gen/android`.

#### Step 2: Test on an Android Device or Emulator
Connect an Android phone via USB with **USB Debugging** enabled, or start an Android Studio emulator, then run:
```bash
npm run mobile:android
```

#### Step 3: Build the Standalone Release `.apk`
```bash
npm run mobile:android:build
```

The compiled release APK will be generated at:
```
client/src-tauri/gen/android/app/build/outputs/apk/release/app-release-unsigned.apk
```

---

### Signing and Sideloading (Bypassing Google Play)

To distribute the `.apk` directly to users for **Freedom of Speech** without Google censorship:

1. Generate a self-signed release key:
   ```bash
   keytool -genkey -v -keystore aegischat-release.keystore -alias aegis -keyalg RSA -keysize 2048 -validity 10000
   ```

2. Sign the APK with `apksigner`:
   ```bash
   apksigner sign --ks aegischat-release.keystore --out aegischat-signed.apk client/src-tauri/gen/android/app/build/outputs/apk/release/app-release-unsigned.apk
   ```

3. Users can now download and install `aegischat-signed.apk` directly via their web browser or USB!

---

## 🍏 2. iOS Packaging (.ipa / Xcode)

### Prerequisites (macOS)

1. **macOS with Xcode 15+**:
   * Install Xcode from the Mac App Store.
   * Install Command Line Tools:
     ```bash
     xcode-select --install
     ```

2. **Install Rust iOS Toolchain Targets**:
   ```bash
   rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
   ```

---

### iOS Build Commands

#### Step 1: Initialize the iOS Project Scaffold
```bash
npm run mobile:ios:init
```
This generates the Xcode project inside `client/src-tauri/gen/apple`.

#### Step 2: Test in iOS Simulator or iPhone
```bash
npm run mobile:ios
```

#### Step 3: Build Standalone IPA
```bash
npm run mobile:ios:build
```

---

### Sideloading on iOS (Without App Store Approval)

State actors often pressure Apple to remove encrypted communications apps from national App Stores. AegisChat can be installed without the App Store:
1. **AltStore / SideStore**: Open source tool allowing any user with an Apple ID to sideload the `.ipa` directly to their iPhone.
2. **TrollStore**: For iOS versions supporting CoreTrust bugs, permanently installs without app revokes.
3. **TestFlight / Enterprise Certificate**: Distribute to unlimited beta testers without full App Store review.

---

## 🛡️ Mobile Security & Anti-Forensic Hardening

### 1. Screen Capture & Screenshot Blocking (`FLAG_SECURE`)
In Android's `MainActivity.kt`:
```kotlin
import android.view.WindowManager

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // Prevents screenshots, screen recording, and task switcher previews
    window.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE
    )
}
```

### 2. Required Mobile Permissions
* `android.permission.INTERNET`: Direct WebSocket & HTTP communication.
* `android.permission.RECORD_AUDIO`: Voice notes and encrypted WebRTC audio calls.
* `android.permission.CAMERA`: Encrypted WebRTC video calls and safety number QR verification.

### 3. iOS Info.plist Privacy Entries
* `NSMicrophoneUsageDescription`: "AegisChat requires microphone access for end-to-end encrypted voice calls and voice notes."
* `NSCameraUsageDescription`: "AegisChat requires camera access for end-to-end encrypted video calls and QR verification."

---

## 🚀 Quick Command Reference

| Target | Command | Result |
| :--- | :--- | :--- |
| **PC (Dev)** | `npm run desktop:dev` | Launches native Windows/macOS `.exe` window |
| **PC (Release)** | `npm run desktop:build` | Standalone `.msi` / `.exe` installer |
| **Android (Dev)** | `npm run mobile:android` | Live reload on connected Android device |
| **Android (APK)** | `npm run mobile:android:build` | Release `.apk` ready for sideloading |
| **iOS (Dev)** | `npm run mobile:ios` | Launches in iOS Simulator / iPhone |
| **iOS (Build)** | `npm run mobile:ios:build` | Standalone `.ipa` archive |
