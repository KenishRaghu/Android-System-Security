# Lab Scripts

Runnable tools used in the Android Systems Security Analysis Lab for behavior inspection and attack-surface review.

## Requirements

- **ADB** (Android Debug Bridge) from Android SDK platform-tools
- Android device or emulator with USB debugging enabled
- Python 3.6+

## Scripts

| Script | Purpose |
|--------|--------|
| `analyze_permissions.py` | Lists requested/granted permissions for a package and flags sensitive ones (SMS, contacts, location, etc.) for overprivilege review. |
| `check_exported_components.py` | Parses `dumpsys package` to list exported activities, services, and receivers (potential attack surface). |
| `analyze_package.sh` | Runs both analyses for a given package name via ADB. |

## Usage

```bash
# Single package (device/emulator connected)
./analyze_package.sh com.example.someapp

# Permissions only
adb shell dumpsys package com.example.someapp | python3 analyze_permissions.py -
# Or with package name (script will call adb)
python3 analyze_permissions.py com.example.someapp

# Exported components only
adb shell dumpsys package com.example.someapp | python3 check_exported_components.py -
python3 check_exported_components.py com.example.someapp
```

Output supports the malware analysis and findings documented in `../docs/`.
