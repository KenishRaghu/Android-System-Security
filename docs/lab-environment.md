# Lab Environment

## 1. Lab Setup Overview

The Android Systems Security Analysis Lab runs on **Ubuntu 22.04 LTS** as the host operating system. All analysis tools (ADB, apktool, aapt, Python, androguard) are installed on the host. The target environment is an **Android Emulator** created and managed via **Android Studio AVD Manager**. The emulator provides an isolated, repeatable Android instance for installing vulnerable APKs (DIVA, InsecureBankv2) and performing dynamic analysis without affecting a physical device. Network access from the host to the emulator is provided by ADB over the local bridge.

## 2. Tools Installed

| Tool | Version (example) | Purpose |
|------|-------------------|---------|
| **ADB** | 34.0.5 | Install APKs, shell access (`adb shell`), `logcat`, `dumpsys`, `pm`, `am` |
| **apktool** | 2.7.0 | Decompile APK to smali, resources, and AndroidManifest.xml for static analysis |
| **aapt** | 8.x (via build-tools) | Inspect APK manifest and resources (permissions, components) |
| **androguard** | 4.0.x | Python library to parse APK and extract manifest, permissions, components programmatically |
| **Python 3** | 3.10+ | Run analysis scripts (analyze_permissions, check_exported_components, package_inspector) |

## 3. Emulator Configuration

| Setting | Value |
|---------|--------|
| **Device** | Pixel 6 |
| **System image** | Android 13 (API 33), x86_64 |
| **RAM** | 4 GB |
| **Developer options** | Enabled |
| **USB debugging** | Enabled |

Developer options and USB debugging are required so that ADB can connect and run commands (e.g., `adb shell`, `adb logcat`, `dumpsys`).

## 4. Security Boundaries Analyzed

### Android permission model

- **Normal permissions**: Granted at install time without user prompt (e.g., INTERNET, ACCESS_NETWORK_STATE). Low risk.
- **Dangerous permissions**: Require runtime user consent (e.g., READ_CONTACTS, ACCESS_FINE_LOCATION, READ_CALL_LOG). Must be justified; overuse increases attack surface.
- **Signature permissions**: Only granted to apps signed with the same key as the declaring app. Used for inter-app communication within a vendor’s suite.

Analysis focused on which permissions DIVA declares and whether they align with app functionality (principle of least privilege).

### App sandboxing (Linux UID isolation)

Each app runs under a distinct Linux UID. Process and file system isolation are enforced by the kernel; app data under `/data/data/<package>/` is not readable by other apps. We verified isolation using `adb shell ps` and `adb shell ls /data/data/jakhar.aseem.diva/` to confirm the app’s process and data directory are scoped to its UID.

### Inter-process communication (IPC)

- **Intents**: Used to start activities, services, and broadcast receivers. Exported components can be targeted by any app; unvalidated intent data can lead to injection or unauthorized actions.
- **Exported components**: Activities, services, receivers, and content providers with `android:exported="true"` are part of the app’s IPC attack surface. We enumerated them and checked for permission enforcement.

### File system isolation

App-private storage is under `/data/data/<package>/` (and app-specific directories on external storage). We confirmed that other apps cannot read this path and that DIVA also uses shared storage and internal files that were reviewed for sensitive data exposure.

## 5. Attack Surfaces Identified

| Surface | Description |
|---------|-------------|
| **Exported activities without permission** | Several DIVA activities are exported with no `<intent-filter>` permission or custom permission, so any app can launch them and trigger insecure behaviors (e.g., hardcoded credentials screen). |
| **Overprivileged permissions** | The app requests dangerous permissions (e.g., READ_CALL_LOG, READ_CONTACTS) that are not obviously required for its stated features, increasing impact of compromise or misuse. |
| **Insecure data storage** | Use of SharedPreferences and file storage for sensitive data without encryption; data readable by root or backup/restore. |
| **Unprotected content providers** | Content providers that are exported or world-readable can leak app data to other apps; we identified components that expose data without proper access control. |

## 6. ADB Commands Used

Commands run during the lab and their typical output are below.

**List connected devices:**

```bash
adb devices
```

```
List of devices attached
emulator-5554   device
```

**List installed packages (filter for DIVA):**

```bash
adb shell pm list packages | grep diva
```

```
package:jakhar.aseem.diva
```

**Dump package info (version, permissions, components):**

```bash
adb shell dumpsys package jakhar.aseem.diva
```

```
Activity Resolver Table:
  ...
  Full MISSION ...
  Non-data actions:
    ...
    jakhar.aseem.diva/.MainActivity filter ...
    jakhar.aseem.diva/.APICredsActivity filter ...
Package [jakhar.aseem.diva] (xxx):
  versionCode=1 targetSdk=33
  versionName=1.0
  firstInstallTime=2025-03-15 12:00:00
  requested permissions:
    android.permission.READ_CONTACTS: granted=true
    android.permission.WRITE_EXTERNAL_STORAGE: granted=true
    ...
```

**List processes for the app:**

```bash
adb shell ps | grep diva
```

```
u0_a123  1234  123  1234567 12345 0 S jakhar.aseem.diva
```

**List app’s private data directory (must run as shell/root in context of that app):**

```bash
adb shell run-as jakhar.aseem.diva ls /data/data/jakhar.aseem.diva/
```

```
cache
code_cache
shared_prefs
databases
files
```

(If `run-as` is not available on the emulator image, `adb shell ls /data/data/jakhar.aseem.diva/` may require root.)

## 7. Lab Environment Diagram

```
+------------------+
|  Host (Ubuntu    |
|  22.04)          |
|                  |
|  - apktool       |
|  - aapt          |
|  - Python 3      |
|  - androguard    |
+--------+---------+
         |
         | ADB (adb devices, adb install, adb shell, adb logcat)
         |
+--------v---------+
|  ADB Server /    |
|  Bridge          |
|  (localhost:5037)|
+--------+---------+
         |
         | USB / TCP (emulator-5554)
         |
+--------v---------+
|  Android         |
|  Emulator (AVD)  |
|  Pixel 6, API 33|
|  - System server|
|  - Package Mgr  |
+--------+---------+
         |
         | Install / Run
         |
+--------v---------+
|  Target APK      |
|  (DIVA /         |
|  InsecureBankv2) |
+------------------+
```

This diagram shows the flow: **Host Linux** runs analysis tools; **ADB** connects to the **Android Emulator**; the **Target APK** (e.g., DIVA) is installed and analyzed on the emulator.
