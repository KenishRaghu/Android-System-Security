#!/usr/bin/env python3
"""
Extract Activities, Services, BroadcastReceivers, and ContentProviders from an APK
using androguard. Flag components that are exported with NO permission as [VULNERABLE].
Usage: python3 check_exported_components.py <path_to.apk>
"""

import sys
import os


def get_components_from_axml(apk):
    """
    Use androguard's APK object to get manifest info.
    We need component name, exported, and permission.
    androguard.core.apk.APK provides get_activities(), get_services(), etc.
    and for each we need exported and permission from the manifest.
    """
    from androguard.core.apk import APK
    if not isinstance(apk, APK):
        apk = APK(apk)
    package = apk.get_package() or "unknown"
    results = []
    # get_activities returns list of activity names; we need exported and permission
    # androguard APK: get_activities() returns list of (name, exported, permission) or similar
    # Actually androguard APK has: get_activities(), get_services(), get_receivers(), get_providers()
    # and for details we need the manifest. Let me check: in androguard, get_activities() returns
    # list of activity class names. For exported/permission we need to parse the manifest XML.
    # Alternative: use apk.get_android_manifest_axml() and parse, or use apk.get_android_resources()
    # Actually in androguard 4.x: APK has get_android_manifest_xml() or we iterate elements.
    # Simpler: use apk.get_activities() which returns list of strings (component names).
    # For exported: in androguard we can use get_element() or the manifest. I'll use the
    # internal structure: apk.android_manifest or apk.get_android_manifest_axml().
    # Androguard 4: from androguard.core.apk import APK
    # apk.get_activities() -> list of activity names (string)
    # To get exported/permission we need to read the AXML. Androguard has get_activity() that might
    # return more info. Checking androguard docs: get_activities() returns list of names.
    # We can use apk.get_android_manifest_xml() and then find all activity/service/receiver/provider
    # and read android:exported and android:permission.
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception:
        manifest = None
    if manifest is None:
        # Fallback: just get component names and assume we don't have exported info
        for name in apk.get_activities():
            results.append(("ACTIVITY", name, True, None))
        for name in apk.get_services():
            results.append(("SERVICE", name, True, None))
        for name in apk.get_receivers():
            results.append(("RECEIVER", name, True, None))
        for name in apk.get_providers():
            results.append(("PROVIDER", name, True, None))
        return package, results
    ns = "{http://schemas.android.com/apk/res/android}"
    def get_attr(e, attr, default=None):
        return e.get(ns + attr) or e.get(attr) or default
    for elem in manifest.iter():
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if tag == "activity":
            name = get_attr(elem, "name")
            if not name:
                continue
            if "." in name and not name.startswith("."):
                full_name = name
            else:
                full_name = package + name if name.startswith(".") else name
            exported = get_attr(elem, "exported")
            if exported is None:
                # Default: if has intent-filter, exported is true
                exported = "true" if elem.find(".//intent-filter") is not None else "false"
            exported = str(exported).lower() == "true"
            perm = get_attr(elem, "permission") or "NONE"
            results.append(("ACTIVITY", full_name, exported, perm if perm else "NONE"))
        elif tag == "service":
            name = get_attr(elem, "name")
            if not name:
                continue
            full_name = package + name if name.startswith(".") else (name if "." in name else package + "." + name)
            exported = get_attr(elem, "exported")
            if exported is None:
                exported = "true" if elem.find(".//intent-filter") is not None else "false"
            exported = str(exported).lower() == "true"
            perm = get_attr(elem, "permission") or "NONE"
            results.append(("SERVICE", full_name, exported, perm))
        elif tag == "receiver":
            name = get_attr(elem, "name")
            if not name:
                continue
            full_name = package + name if name.startswith(".") else (name if "." in name else package + "." + name)
            exported = get_attr(elem, "exported")
            if exported is None:
                exported = "true" if elem.find(".//intent-filter") is not None else "false"
            exported = str(exported).lower() == "true"
            perm = get_attr(elem, "permission") or "NONE"
            results.append(("RECEIVER", full_name, exported, perm))
        elif tag == "provider":
            name = get_attr(elem, "name")
            if not name:
                continue
            full_name = package + name if name.startswith(".") else (name if "." in name else package + "." + name)
            exported = get_attr(elem, "exported")
            if exported is None:
                exported = "true"
            exported = str(exported).lower() == "true"
            perm = get_attr(elem, "permission") or "NONE"
            results.append(("PROVIDER", full_name, exported, perm))
    # If no results from manifest parsing, fallback to get_*()
    if not results:
        for name in apk.get_activities():
            results.append(("ACTIVITY", name, True, "NONE"))
        for name in apk.get_services():
            results.append(("SERVICE", name, True, "NONE"))
        for name in apk.get_receivers():
            results.append(("RECEIVER", name, True, "NONE"))
        for name in apk.get_providers():
            results.append(("PROVIDER", name, True, "NONE"))
    return package, results


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 check_exported_components.py <path_to.apk>")
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
    package, components = get_components_from_axml(a)
    apk_name = os.path.basename(apk_path)
    sep = "=" * 80
    print(sep)
    print("EXPORTED COMPONENTS REPORT")
    print(sep)
    print(f"APK: {apk_name}")
    print(f"Package: {package}")
    print("-" * 80)
    vulnerable_count = 0
    for comp_type, name, exported, permission in components:
        if not exported:
            continue
        perm_str = permission or "NONE"
        vulnerable = exported and (not permission or permission == "NONE")
        if vulnerable:
            vulnerable_count += 1
        flag = " [VULNERABLE]" if vulnerable else ""
        print(f"{comp_type:12} {name:45} exported={exported}   permission={perm_str:20} {flag}")
    print("-" * 80)
    print(f"Vulnerable (exported, no permission): {vulnerable_count}")
    print(sep)


if __name__ == "__main__":
    main()
