#!/usr/bin/env python3
"""
Identify exported components (activities, services, receivers) for an Android package.
Exported components are an attack surface—they can be invoked by other apps.
Usage: adb shell dumpsys package <pkg> | python3 check_exported_components.py -
       Or: python3 check_exported_components.py <package_name>
"""

import re
import sys


def parse_components(text: str) -> dict:
    """Extract activities, services, receivers and their exported flag from dumpsys package."""
    result = {"activities": [], "services": [], "receivers": []}
    in_block = None
    comp_name = None
    for line in text.splitlines():
        if "Activity Resolver" in line:
            in_block = "activities"
            comp_name = None
            continue
        if "Service Resolver" in line:
            in_block = "services"
            comp_name = None
            continue
        if "Receiver Resolver" in line:
            in_block = "receivers"
            comp_name = None
            continue
        if in_block and "  " in line:
            m = re.search(r"\s+([a-zA-Z0-9_.]+/[a-zA-Z0-9_.]+)", line)
            if m:
                comp_name = m.group(1)
            exported = "exported=true" in line or "exported: true" in line.lower()
            if comp_name:
                result[in_block].append({"name": comp_name, "exported": exported})
    for key in result:
        seen = set()
        out = []
        for c in reversed(result[key]):
            if c["name"] not in seen:
                seen.add(c["name"])
                out.append(c)
        result[key] = list(reversed(out))
    return result


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: check_exported_components.py <package_name>")
        print("   Or: adb shell dumpsys package <pkg> | check_exported_components.py -")
        sys.exit(1)
    arg = sys.argv[1]
    if arg == "-":
        text = sys.stdin.read()
    else:
        import subprocess
        r = subprocess.run(["adb", "shell", "dumpsys", "package", arg], capture_output=True, text=True)
        if r.returncode != 0:
            print("Error: adb failed.", file=sys.stderr)
            sys.exit(2)
        text = r.stdout or ""
    data = parse_components(text)
    print("Exported components (attack surface):\n")
    for kind in ("activities", "services", "receivers"):
        label = kind.capitalize()
        items = [c for c in data[kind] if c.get("exported")]
        if items:
            print(f"  {label}:")
            for c in items:
                print(f"    - {c['name']}")
    total = sum(1 for k in data for c in data[k] if c.get("exported"))
    if total == 0:
        print("  (No exported components found in parsed output; run with device connected.)")
    else:
        print(f"\n  Total exported: {total} — validate caller and intent data for each.")


if __name__ == "__main__":
    main()
