# Lab Scripts

Three Python 3 scripts for the Android Systems Security Analysis Lab. They support static analysis of APK files (permissions, exported components) and runtime inspection of installed packages via ADB.

**Requirements:** Python 3.6+, androguard (`pip3 install androguard`) for the two APK scripts; ADB and a connected device/emulator for `package_inspector.py`.

---

## 1. analyze_permissions.py

**Purpose:** Parse an APK with androguard, extract all `uses-permission` entries from the manifest, and classify each as DANGEROUS, NORMAL, or SIGNATURE. Dangerous permissions are marked with `[!]`, normal with `[+]`, and signature with `[#]`.

**Usage:**

```bash
python3 scripts/analyze_permissions.py <path_to.apk>
```

**Arguments:** Single positional argument: path to the APK file (e.g., `diva-beta.apk`).

**Example:**

```bash
python3 scripts/analyze_permissions.py diva-beta.apk
```

**Full example output:**

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

---

## 2. check_exported_components.py

**Purpose:** Parse an APK with androguard, extract all Activities, Services, BroadcastReceivers, and ContentProviders, and for each component report whether it is exported and whether a permission is required. Components that are exported with no permission are flagged as `[VULNERABLE]`.

**Usage:**

```bash
python3 scripts/check_exported_components.py <path_to.apk>
```

**Arguments:** Single positional argument: path to the APK file.

**Example:**

```bash
python3 scripts/check_exported_components.py diva-beta.apk
```

**Full example output:**

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
ACTIVITY    jakhar.aseem.diva.SQLInjectionActivity     exported=True   permission=NONE        [VULNERABLE]
--------------------------------------------------------------------------------
Vulnerable (exported, no permission): 5
================================================================================
```

---

## 3. package_inspector.py

**Purpose:** Use ADB to inspect an installed package: run `adb shell pm list packages`, `adb shell dumpsys package <package_name>`, and `adb shell ps`, then extract package version, first install time, declared permissions, granted permissions, and running processes. Writes a text report to `<package_name>_report.txt`.

**Usage:**

```bash
python3 scripts/package_inspector.py <package_name>
```

**Arguments:** Single positional argument: package name (e.g., `jakhar.aseem.diva`).

**Example:**

```bash
python3 scripts/package_inspector.py jakhar.aseem.diva
```

**Full example output (stdout):**

```
[*] Inspecting package: jakhar.aseem.diva
[*] Running ADB commands...
[*] Report saved to: jakhar.aseem.diva_report.txt
```

**Example report file (`jakhar.aseem.diva_report.txt`):**

```
PACKAGE INSPECTION REPORT
Package: jakhar.aseem.diva
Generated: 2025-03-18 14:22:00
---
versionName: 1.0
versionCode: 1
firstInstallTime: 2025-03-15 12:00:00
---
DECLARED PERMISSIONS:
  android.permission.READ_CONTACTS
  android.permission.WRITE_EXTERNAL_STORAGE
  android.permission.INTERNET
  android.permission.ACCESS_NETWORK_STATE
  android.permission.ACCESS_FINE_LOCATION
  android.permission.READ_CALL_LOG
GRANTED PERMISSIONS:
  android.permission.INTERNET
  android.permission.ACCESS_NETWORK_STATE
  android.permission.READ_CONTACTS
  android.permission.WRITE_EXTERNAL_STORAGE
  android.permission.ACCESS_FINE_LOCATION
  android.permission.READ_CALL_LOG
---
PROCESSES (matching package):
  u0_a123  1234  123  1234567 12345 0 S jakhar.aseem.diva
```

**If no device is connected:**

```
Error: No device/emulator connected. Run 'adb devices' to check.
```

(Exit code 2.)
