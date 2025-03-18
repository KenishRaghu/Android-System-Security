#!/usr/bin/env python3
"""
Analyze permissions declared in an APK manifest using androguard.
Classifies each permission as DANGEROUS, NORMAL, or SIGNATURE and prints
a formatted report. Used for malware/security analysis of Android apps.
Usage: python3 analyze_permissions.py <path_to.apk>
"""

import sys
import os

# Lookup: permission -> category for classification (DANGEROUS, NORMAL, SIGNATURE).
# Includes at least 15 Android permissions across categories as required.
PERMISSION_CATEGORY = {
    # Dangerous (runtime) permissions
    "android.permission.READ_CONTACTS": "DANGEROUS",
    "android.permission.WRITE_CONTACTS": "DANGEROUS",
    "android.permission.READ_EXTERNAL_STORAGE": "DANGEROUS",
    "android.permission.WRITE_EXTERNAL_STORAGE": "DANGEROUS",
    "android.permission.ACCESS_FINE_LOCATION": "DANGEROUS",
    "android.permission.ACCESS_COARSE_LOCATION": "DANGEROUS",
    "android.permission.READ_CALL_LOG": "DANGEROUS",
    "android.permission.WRITE_CALL_LOG": "DANGEROUS",
    "android.permission.READ_SMS": "DANGEROUS",
    "android.permission.RECEIVE_SMS": "DANGEROUS",
    "android.permission.SEND_SMS": "DANGEROUS",
    "android.permission.RECORD_AUDIO": "DANGEROUS",
    "android.permission.CAMERA": "DANGEROUS",
    "android.permission.CALL_PHONE": "DANGEROUS",
    "android.permission.READ_PHONE_STATE": "DANGEROUS",
    "android.permission.GET_ACCOUNTS": "DANGEROUS",
    "android.permission.READ_CALENDAR": "DANGEROUS",
    "android.permission.WRITE_CALENDAR": "DANGEROUS",
    "android.permission.BODY_SENSORS": "DANGEROUS",
    "android.permission.READ_MEDIA_IMAGES": "DANGEROUS",
    "android.permission.READ_MEDIA_VIDEO": "DANGEROUS",
    "android.permission.READ_MEDIA_AUDIO": "DANGEROUS",
    # Normal permissions
    "android.permission.INTERNET": "NORMAL",
    "android.permission.ACCESS_NETWORK_STATE": "NORMAL",
    "android.permission.ACCESS_WIFI_STATE": "NORMAL",
    "android.permission.BLUETOOTH": "NORMAL",
    "android.permission.BLUETOOTH_ADMIN": "NORMAL",
    "android.permission.VIBRATE": "NORMAL",
    "android.permission.WAKE_LOCK": "NORMAL",
    "android.permission.RECEIVE_BOOT_COMPLETED": "NORMAL",
    "android.permission.FOREGROUND_SERVICE": "NORMAL",
    "android.permission.FOREGROUND_SERVICE_LOCATION": "NORMAL",
    "android.permission.POST_NOTIFICATIONS": "NORMAL",
    # Signature / signatureOrSystem (treated as SIGNATURE for reporting)
    "android.permission.BIND_DEVICE_ADMIN": "SIGNATURE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "SIGNATURE",
}


def classify_permission(perm: str) -> str:
    """Return DANGEROUS, NORMAL, or SIGNATURE; default to NORMAL if unknown."""
    return PERMISSION_CATEGORY.get(perm, "NORMAL")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_permissions.py <path_to.apk>")
        sys.exit(1)
    apk_path = sys.argv[1]
    if not os.path.isfile(apk_path):
        print(f"Error: File not found: {apk_path}", file=sys.stderr)
        sys.exit(2)
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError:
        print("Error: androguard not installed. Run: pip3 install androguard", file=sys.stderr)
        sys.exit(3)
    try:
        a = AnalyzeAPK(apk_path)
        if isinstance(a, (list, tuple)):
            a = a[0]
    except Exception as e:
        print(f"Error: Failed to parse APK: {e}", file=sys.stderr)
        sys.exit(4)
    package = a.get_package()
    if not package:
        package = "unknown"
    permissions = a.get_permissions()
    if permissions is None:
        permissions = []
    # Build report
    dangerous = []
    normal = []
    signature = []
    for p in sorted(permissions):
        cat = classify_permission(p)
        if cat == "DANGEROUS":
            dangerous.append(p)
        elif cat == "SIGNATURE":
            signature.append(p)
        else:
            normal.append(p)
    apk_name = os.path.basename(apk_path)
    total = len(permissions)
    sep = "=" * 80
    print(sep)
    print("PERMISSION ANALYSIS REPORT")
    print(sep)
    print(f"APK: {apk_name}")
    print(f"Package: {package}")
    print(f"Total permissions: {total}")
    print("-" * 80)
    for p in dangerous:
        print(f"[!] {p} (DANGEROUS)")
    for p in normal:
        print(f"[+] {p} (NORMAL)")
    for p in signature:
        print(f"[#] {p} (SIGNATURE)")
    print("-" * 80)
    print(f"Dangerous: {len(dangerous)} | Normal: {len(normal)} | Signature: {len(signature)}")
    print(sep)


if __name__ == "__main__":
    main()
