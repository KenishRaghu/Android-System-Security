# Android Systems Security Analysis Lab

**Jan 2025 – Apr 2025**

## Overview

This repository documents an Android Systems Security Analysis Lab conducted in a controlled environment. The lab focuses on understanding Android system behaviors, security boundaries, and attack surfaces by analyzing intentionally vulnerable applications. The goal is to build hands-on experience with static and dynamic analysis techniques used in mobile security assessments.

The lab uses two well-known vulnerable apps—**DIVA** (Damn Insecure and Vulnerable App) and **OWASP InsecureBankv2**—as safe, legal targets. These apps contain deliberate security flaws (hardcoded credentials, exported components without permission checks, insecure storage, and sensitive data logging) that mirror real-world vulnerabilities. By analyzing them, we identify how malware or poorly designed apps can abuse the Android platform and document defensive improvements aligned with secure system design principles.

All analysis is performed on a Linux host with an Android emulator (AVD), using standard tools such as ADB, apktool, aapt, and Python scripts backed by the androguard library. Findings are documented with reproducible commands and script outputs so that recruiters or interviewers can replicate the work.

## Tech Stack

| Component | Purpose |
|-----------|---------|
| **Linux** | Host OS (Ubuntu 22.04) for running tools and emulator |
| **ADB** | Android Debug Bridge — install APKs, shell access, logcat, dumpsys |
| **Python 3** | Scripts for permission analysis, exported-component checks, package inspection |
| **apktool** | Decompile APK to smali and resources for static analysis |
| **aapt** | Android Asset Packaging Tool — inspect manifest and resources |
| **androguard** | Python library to parse APK and extract manifest/components programmatically |
| **Android Emulator (AVD)** | Target environment (Pixel 6, API 33) for dynamic analysis |

## Lab Target APKs

- **DIVA (Damn Insecure and Vulnerable App)** — Package: `jakhar.aseem.diva`. Intentionally vulnerable app covering insecure data storage, hardcoded credentials, exported components, and logging issues. Primary target for this lab.
- **OWASP InsecureBankv2** — Educational vulnerable banking app used for additional testing of authentication, session, and transport security issues.

## Repository Structure

```
Android-System-Security/
├── docs/
│   ├── lab-environment.md      # Lab setup, tools, security boundaries, attack surfaces, ADB commands
│   ├── malware-analysis.md     # Static/dynamic analysis of DIVA, permission and component analysis
│   └── findings-and-improvements.md  # Findings table, evidence, defensive recommendations, OWASP mapping
├── scripts/
│   ├── README.md               # Usage and example output for each script
│   ├── analyze_permissions.py  # Parse APK with androguard; list and classify permissions
│   ├── check_exported_components.py  # List exported components and flag those without permission
│   └── package_inspector.py    # ADB-based inspector; dumps package info to a report file
├── .gitignore
└── README.md                   # This file
```

## Setup Instructions

### 1. Install dependencies

On Ubuntu 22.04:

```bash
sudo apt update
sudo apt install adb android-tools-adb apktool aapt -y
pip3 install androguard
```

Verify:

```bash
adb version
apktool --version
python3 -c "import androguard; print(androguard.__version__)"
```

Expected (versions may vary):

```
Android Debug Bridge version 34.0.5
Apktool 2.7.0
4.0.1
```

### 2. Download Android Studio and set up AVD

1. Download Android Studio from https://developer.android.com/studio and install.
2. Open **Tools → Device Manager** (AVD Manager).
3. Create Virtual Device: **Pixel 6**, system image **API 33** (Android 13), **x86_64**.
4. Allocate **4 GB RAM**. Finish and start the emulator once to ensure it boots.

### 3. Start emulator and verify ADB

Start the Pixel 6 API 33 AVD from Device Manager, then:

```bash
adb devices
```

Expected:

```
List of devices attached
emulator-5554   device
```

### 4. Download DIVA APK

```bash
wget https://github.com/payatu/diva-android/raw/master/diva-beta.apk
```

Or clone and use the APK from the repo:

```bash
git clone https://github.com/payatu/diva-android.git
# APK is at diva-android/diva-beta.apk
```

### 5. Install APK on emulator

```bash
adb install diva-beta.apk
```

Expected:

```
Performing Streamed Install
Success
```

## Running the Scripts

All scripts are run from the repository root. Ensure the emulator is running for `package_inspector.py`; `analyze_permissions.py` and `check_exported_components.py` work on the APK file only.

### analyze_permissions.py (APK path)

Analyzes permissions declared in the APK manifest and classifies them as DANGEROUS, NORMAL, or SIGNATURE.

```bash
python3 scripts/analyze_permissions.py diva-beta.apk
```

Example output:

```
================================================================================
PERMISSION ANALYSIS REPORT
================================================================================
APK: diva-beta.apk
Package: jakhar.aseem.diva
Total permissions: 6
--------------------------------------------------------------------------------
[!] android.permission.READ_CONTACTS (DANGEROUS)
[!] android.permission.WRITE_EXTERNAL_STORAGE (DANGEROUS)
[!] android.permission.ACCESS_FINE_LOCATION (DANGEROUS)
[!] android.permission.READ_CALL_LOG (DANGEROUS)
[+] android.permission.INTERNET (NORMAL)
[+] android.permission.ACCESS_NETWORK_STATE (NORMAL)
--------------------------------------------------------------------------------
Dangerous: 4 | Normal: 2 | Signature: 0
================================================================================
```

### check_exported_components.py (APK path)

Lists Activities, Services, BroadcastReceivers, and ContentProviders; flags components that are exported with no permission as `[VULNERABLE]`.

```bash
python3 scripts/check_exported_components.py diva-beta.apk
```

Example output:

```
================================================================================
EXPORTED COMPONENTS REPORT
================================================================================
APK: diva-beta.apk
Package: jakhar.aseem.diva
--------------------------------------------------------------------------------
ACTIVITY    jakhar.aseem.diva.MainActivity              exported=True   permission=NONE        [VULNERABLE]
ACTIVITY    jakhar.aseem.diva.APICredsActivity          exported=True   permission=NONE        [VULNERABLE]
ACTIVITY    jakhar.aseem.diva.HardcodeActivity         exported=True   permission=NONE        [VULNERABLE]
ACTIVITY    jakhar.aseem.diva.InputValidation2Activity  exported=True   permission=NONE        [VULNERABLE]
--------------------------------------------------------------------------------
Vulnerable (exported, no permission): 4
================================================================================
```

### package_inspector.py (package name, device required)

Runs ADB commands to gather package version, install date, declared/granted permissions, and running processes. Writes a report to `<package_name>_report.txt`.

```bash
python3 scripts/package_inspector.py jakhar.aseem.diva
```

Example output:

```
[*] Inspecting package: jakhar.aseem.diva
[*] Running ADB commands...
[*] Report saved to: jakhar.aseem.diva_report.txt
```

Report file excerpt:

```
PACKAGE INSPECTION REPORT
Package: jakhar.aseem.diva
Generated: 2025-03-18 14:22:00
---
versionName: 1.0
firstInstallTime: 2025-03-15 12:00:00
---
DECLARED PERMISSIONS:
  android.permission.READ_CONTACTS
  android.permission.WRITE_EXTERNAL_STORAGE
  ...
GRANTED PERMISSIONS:
  android.permission.INTERNET
  android.permission.ACCESS_NETWORK_STATE
  ...
PROCESSES:
  u0_a123  1234  123  jakhar.aseem.diva
```

If no device is connected:

```
Error: No device/emulator connected. Run 'adb devices' to check.
```

## Key Findings Summary

- **Dangerous permissions**: DIVA requests READ_CONTACTS, WRITE_EXTERNAL_STORAGE, ACCESS_FINE_LOCATION, READ_CALL_LOG without clear need for all of them, increasing impact if the app is compromised or used to exfiltrate data.
- **Exported components**: Multiple activities (e.g., APICredsActivity, HardcodeActivity) are exported with no permission enforcement, allowing any app to launch them and trigger insecure behaviors or access internal UI.
- **Hardcoded credentials**: Static analysis of smali code revealed hardcoded API keys and default passwords (e.g., in API credentials and SQL injection screens), which could be extracted by decompilation.
- **Insecure logging**: logcat showed usernames and passwords being logged in plaintext via `Log.d()` during login and API flows, enabling credential theft from device logs or malware with READ_LOGS.

## Defensive Recommendations

- **Least privilege**: Request only permissions necessary for declared features; use runtime permissions and explain usage to the user.
- **Secure credential storage**: Use Android Keystore for keys and secrets; avoid hardcoded credentials and plaintext SharedPreferences for sensitive data; consider EncryptedSharedPreferences.
- **Harden exported components**: Set `android:exported="false"` unless the component must be reachable by other apps; enforce a custom permission or signature check for exported components that handle sensitive data.
- **Production-safe logging**: Remove or guard `Log.d()`/`Log.v()` for sensitive data; use build flags or ProGuard to strip debug logs in release builds.

## References

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Documentation](https://source.android.com/docs/security)
- [DIVA – Damn Insecure and Vulnerable App (GitHub)](https://github.com/payatu/diva-android)
- [OWASP InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2)
