#!/usr/bin/env python3
"""
Analyze permissions of an Android package (installed on device/emulator).
Maps declared and requested permissions and flags sensitive/dangerous ones
for malware behavior inspection.
Usage: python3 analyze_permissions.py <package_name>
       Or with ADB: adb shell dumpsys package <pkg> | python3 analyze_permissions.py -
"""

import re
import sys

# Sensitive permissions that warrant closer review (subset of dangerous/signature)
SENSITIVE_PERMISSIONS = frozenset({
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE", "android.permission.READ_PHONE_STATE",
    "android.permission.GET_ACCOUNTS", "android.permission.USE_CREDENTIALS",
    "android.permission.BIND_DEVICE_ADMIN", "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.ACCESS_NETWORK_STATE", "android.permission.INTERNET",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
})


def parse_dumpsys_package(text: str) -> dict:
    """Parse 'dumpsys package <pkg>' output for requested and granted permissions."""
    result = {"requested": [], "granted": [], "package": None}
    in_requested = False
    in_granted = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Package ["):
            m = re.search(r"Package \[([^\]]+)\]", line)
            if m:
                result["package"] = m.group(1)
        if "requested permissions:" in line.lower():
            in_requested = True
            in_granted = False
            continue
        if "granted permissions:" in line.lower():
            in_granted = True
            in_requested = False
            continue
        if in_requested or in_granted:
            if not line or line.startswith("["):
                if line.startswith("["):
                    in_requested = in_granted = False
                continue
            perm = line.split(":")[0].strip() if ":" in line else line.split()[0] if line else ""
            if perm and perm.startswith("android.permission."):
                if in_requested and perm not in result["requested"]:
                    result["requested"].append(perm)
                if in_granted and perm not in result["granted"]:
                    result["granted"].append(perm)
    return result


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: analyze_permissions.py <package_name>")
        print("   Or: adb shell dumpsys package <pkg> | analyze_permissions.py -")
        sys.exit(1)
    arg = sys.argv[1]
    if arg == "-":
        text = sys.stdin.read()
    else:
        import subprocess
        r = subprocess.run(
            ["adb", "shell", "dumpsys", "package", arg],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            print("Error: adb failed. Is device connected?", file=sys.stderr)
            sys.exit(2)
        text = r.stdout or ""
    data = parse_dumpsys_package(text)
    pkg = data["package"] or arg
    print(f"Package: {pkg}\n")
    print("Requested permissions:")
    for p in data["requested"]:
        flag = " [SENSITIVE]" if p in SENSITIVE_PERMISSIONS else ""
        print(f"  {p}{flag}")
    print("\nGranted permissions:")
    for p in data["granted"]:
        flag = " [SENSITIVE]" if p in SENSITIVE_PERMISSIONS else ""
        print(f"  {p}{flag}")
    sensitive_requested = [p for p in data["requested"] if p in SENSITIVE_PERMISSIONS]
    if sensitive_requested:
        print(f"\n--- {len(sensitive_requested)} sensitive permission(s) requested; review for necessity. ---")


if __name__ == "__main__":
    main()
