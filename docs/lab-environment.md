# Lab Environment: Security Boundaries and Attack Surfaces

## Controlled Lab Setup

- **Host:** Linux (Ubuntu) with isolated network segment
- **Target:** Android emulator (AVD) and/or dedicated test device, not used for production data
- **Tools:** ADB, logcat, package manager; optional: apktool, jadx, Frida for deeper inspection

Isolation ensures analysis does not affect production systems and allows repeatable experiments.

## Android Security Boundaries

1. **Process isolation** — Each app runs in its own process with a unique UID; the kernel and SELinux enforce memory and resource separation.
2. **Application sandbox** — Apps are restricted to their data directories; cross-app access requires explicit permissions or IPC (Intents, Binder).
3. **Permission model** — Normal, signature, and dangerous permissions gate access to sensors, storage, and identity; runtime permissions required for sensitive capabilities.
4. **SELinux** — Mandatory Access Control constrains processes (e.g., app processes, system_server) to defined domains and limits privilege escalation.

## Potential Attack Surfaces

- **Exported components** — Activities, services, or broadcast receivers with `android:exported="true"` can be invoked by other apps; misconfiguration can expose internal logic or data.
- **Intent handling** — Implicit intents and unvalidated extras can lead to injection, unauthorized launches, or data leakage.
- **Storage and backups** — World-readable files, backup flags, or shared storage can expose sensitive data to other apps or to backup/restore.
- **Native code and system APIs** — JNI, reflection, and use of hidden/legacy APIs can bypass Java-level checks or introduce memory-safety issues.
- **Inter-process communication** — Binder interfaces and AIDL services can be abused if authentication or input validation is weak.

Understanding these boundaries and surfaces guides where to focus malware analysis and hardening.
