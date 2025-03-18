#!/bin/bash
# Run permission and exported-component analysis for an installed Android package.
# Usage: ./analyze_package.sh <package_name>
# Requires: ADB, device/emulator connected

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$1"
if [ -z "$PKG" ]; then
  echo "Usage: $0 <package_name>"
  echo "Example: $0 com.example.app"
  exit 1
fi
if ! command -v adb &>/dev/null; then
  echo "Error: adb not found. Install Android platform-tools."
  exit 2
fi
if ! adb shell true 2>/dev/null; then
  echo "Error: No device/emulator connected or unauthorized."
  exit 3
fi
echo "=== Analyzing package: $PKG ==="
echo ""
adb shell dumpsys package "$PKG" | python3 "$SCRIPT_DIR/analyze_permissions.py" -
echo ""
adb shell dumpsys package "$PKG" | python3 "$SCRIPT_DIR/check_exported_components.py" -
