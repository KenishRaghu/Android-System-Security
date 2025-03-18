#!/usr/bin/env python3
"""
Inspect an installed Android package via ADB: version, install date,
declared permissions, granted permissions, and running processes.
Saves a report to <package_name>_report.txt.
Usage: python3 package_inspector.py <package_name>
Requires: device/emulator connected (adb devices).
"""

import subprocess
import sys
import re
from datetime import datetime


def run_adb(args, timeout=10):
    """Run adb with args; return (success, stdout_text)."""
    try:
        r = subprocess.run(
            ["adb"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode != 0:
            return False, r.stderr or r.stdout or ""
        return True, r.stdout or ""
    except FileNotFoundError:
        return False, "adb not found"
    except subprocess.TimeoutExpired:
        return False, "adb timeout"
    except Exception as e:
        return False, str(e)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 package_inspector.py <package_name>")
        print("Example: python3 package_inspector.py jakhar.aseem.diva")
        sys.exit(1)
    pkg = sys.argv[1]
    ok, out = run_adb(["devices"])
    if not ok or "device" not in out.replace("List of devices attached", "").strip():
        print("Error: No device/emulator connected. Run 'adb devices' to check.")
        sys.exit(2)
    lines = []
    lines.append("PACKAGE INSPECTION REPORT")
    lines.append("Package: " + pkg)
    lines.append("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("---")
    ok, out = run_adb(["shell", "dumpsys", "package", pkg])
    if not ok:
        lines.append("Failed to run: adb shell dumpsys package " + pkg)
    else:
        # versionName
        m = re.search(r"versionName=(\S+)", out)
        if m:
            lines.append("versionName: " + m.group(1))
        m = re.search(r"versionCode=(\d+)", out)
        if m:
            lines.append("versionCode: " + m.group(1))
        m = re.search(r"firstInstallTime=(\d+)", out)
        if m:
            try:
                ts = int(m.group(1))
                dt = datetime.fromtimestamp(ts / 1000.0)
                lines.append("firstInstallTime: " + dt.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                lines.append("firstInstallTime: " + m.group(1))
        lines.append("---")
        in_requested = False
        in_granted = False
        declared = []
        granted = []
        for line in out.splitlines():
            line = line.strip()
            if "requested permissions:" in line.lower():
                in_requested = True
                in_granted = False
                continue
            if "granted permissions:" in line.lower():
                in_granted = True
                in_requested = False
                continue
            if in_requested or in_granted:
                if not line or (line.startswith("[") and "Package" in line):
                    in_requested = in_granted = False
                    continue
                perm = line.split(":")[0].strip() if ":" in line else line.split()[0] if line else ""
                if perm and "android.permission" in perm:
                    if in_requested and perm not in declared:
                        declared.append(perm)
                    if in_granted and perm not in granted:
                        granted.append(perm)
        lines.append("DECLARED PERMISSIONS:")
        for p in declared:
            lines.append("  " + p)
        lines.append("GRANTED PERMISSIONS:")
        for p in granted:
            lines.append("  " + p)
    lines.append("---")
    ok, out = run_adb(["shell", "ps", "-A"])
    if ok:
        lines.append("PROCESSES (matching package):")
        for line in out.splitlines():
            if pkg in line:
                lines.append("  " + line.strip())
        if not any(pkg in ln for ln in lines):
            lines.append("  (no running process)")
    report = "\n".join(lines)
    out_path = pkg + "_report.txt"
    try:
        with open(out_path, "w") as f:
            f.write(report)
    except OSError as e:
        print(f"Error: Could not write report: {e}", file=sys.stderr)
        sys.exit(3)
    print("[*] Inspecting package: " + pkg)
    print("[*] Running ADB commands...")
    print("[*] Report saved to: " + out_path)


if __name__ == "__main__":
    main()
