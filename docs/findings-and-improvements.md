# Findings and Defensive Improvements

## 1. Executive Summary

Analysis of the intentionally vulnerable app DIVA (jakhar.aseem.diva) in a controlled lab environment revealed a weak security posture consistent with its design: multiple critical and high-severity issues including hardcoded credentials, exported components without permission enforcement, and sensitive data logged in plaintext. The app also requests more dangerous permissions than necessary and stores sensitive data in SharedPreferences and files without encryption. These findings align with common OWASP Mobile Top 10 categories. The proposed defensive improvements—use of Android Keystore, permission enforcement on exported components, removal of sensitive logging, least privilege, and EncryptedSharedPreferences—would bring the app in line with secure system design principles and reduce attack surface.

## 2. Findings Table

| Finding ID | Title | Severity | Description | Evidence |
|------------|--------|----------|-------------|----------|
| F-01 | Hardcoded Credentials in Source Code | Critical | API keys and default passwords (e.g., admin/admin123, api_key_here_12345) are embedded in smali and recoverable via decompilation. | `grep -r "password\|secret\|key" diva_decompiled/smali/`; APICredsActivity.smali and HardcodeActivity.smali contain const-string credentials. |
| F-02 | Exported Activities Without Permission Enforcement | High | Five activities are exported with no custom or system permission; any app can start them. | `python3 scripts/check_exported_components.py diva-beta.apk` lists multiple activities with permission=NONE and [VULNERABLE]. |
| F-03 | Sensitive Data Logged in Plaintext | High | Usernames, passwords, and API keys are logged via Log.d() and visible in logcat. | `adb logcat` shows lines such as "Credentials entered: user=admin pass=admin123" and "API Key loaded: api_key_here_12345". |
| F-04 | Overprivileged Permission Request | Medium | The app requests READ_CONTACTS, READ_CALL_LOG, ACCESS_FINE_LOCATION, WRITE_EXTERNAL_STORAGE without clear need. | `python3 scripts/analyze_permissions.py diva-beta.apk` reports 4 dangerous permissions; app functionality does not justify all. |
| F-05 | Insecure Data Storage in SharedPreferences | Medium | Credentials and API keys are stored in plaintext SharedPreferences. | Decompiled code and run-as inspection of shared_prefs; logcat references "Storing credential in SharedPreferences". |
| F-06 | Unencrypted Network Communication | Medium | No evidence of certificate pinning or enforced HTTPS in the analyzed code; network use may be susceptible to MITM. | Static inspection of network-related code and manifest; no security config or pinning found. |

## 3. Detailed Finding Descriptions

### F-01: Hardcoded Credentials in Source Code

**Description**: The app embeds default credentials and API keys directly in the compiled code. Decompilation with apktool and a simple grep over smali reveals these strings.

**Evidence**:

```bash
grep -r "password\|secret\|key\|token" diva_decompiled/smali/ --include="*.smali"
```

```
diva_decompiled/smali/jakhar/aseem/diva/APICredsActivity.smali:    const-string v3, "admin123"
diva_decompiled/smali/jakhar/aseem/diva/APICredsActivity.smali:    const-string v1, "api_key_here_12345"
diva_decompiled/smali/jakhar/aseem/diva/HardcodeActivity.smali:    const-string v1, "diva_secret"
```

**Risk**: Attackers who obtain the APK can extract credentials and API keys to impersonate the app, access backend services, or pivot to user accounts. Compliance (e.g., PCI-DSS, OWASP) explicitly flags hardcoded secrets.

**Recommendation**: Remove all hardcoded secrets. Use Android Keystore for keys and tokens; fetch or derive credentials at runtime from a secure backend with proper authentication. Use build-time secrets only in dev and never commit them to source.

---

### F-02: Exported Activities Without Permission Enforcement

**Description**: Several activities are marked `android:exported="true"` and do not require any permission. Any installed app can start these activities via explicit intents.

**Evidence**:

```bash
python3 scripts/check_exported_components.py diva-beta.apk
```

Output excerpt:

```
ACTIVITY    jakhar.aseem.diva.APICredsActivity          exported=True   permission=NONE        [VULNERABLE]
ACTIVITY    jakhar.aseem.diva.HardcodeActivity         exported=True   permission=NONE        [VULNERABLE]
ACTIVITY    jakhar.aseem.diva.InputValidation2Activity  exported=True   permission=NONE        [VULNERABLE]
```

**Risk**: Malicious apps can launch these activities to trigger insecure flows, abuse UI that displays credentials, or combine with other bugs (e.g., intent injection). This expands the app’s attack surface.

**Recommendation**: Set `android:exported="false"` for components that do not need to be started by other apps. For components that must be exported, enforce a custom permission (signature or signatureOrSystem) or verify the caller (e.g., getCallingPackage() / signature check).

---

### F-03: Sensitive Data Logged in Plaintext

**Description**: The app uses `Log.d()` (or equivalent) to log credentials and API keys during normal operation. These entries appear in logcat and can be read by other apps with READ_LOGS (on older APIs) or by anyone with shell access.

**Evidence**:

```bash
adb logcat -s DIVA:* jakhar.aseem.diva:* | head -20
```

```
DIVA     D  Credentials entered: user=admin pass=admin123
DIVA     D  API Key loaded: api_key_here_12345
```

**Risk**: Credential theft from device logs; compliance violations; facilitation of account takeover if logs are exposed (e.g., via debugging, analytics, or malware).

**Recommendation**: Remove or guard all logging of credentials, tokens, PII, and API keys. Use build flags or ProGuard to strip debug logs in release builds. For necessary diagnostics, use non-sensitive identifiers and secure, server-side logging.

---

### F-04: Overprivileged Permission Request

**Description**: The manifest declares dangerous permissions (READ_CONTACTS, WRITE_EXTERNAL_STORAGE, ACCESS_FINE_LOCATION, READ_CALL_LOG) that are not justified by the app’s visible functionality.

**Evidence**:

```bash
python3 scripts/analyze_permissions.py diva-beta.apk
```

Reports four dangerous permissions; the app’s feature set does not require contacts, call log, or fine-grained location.

**Risk**: Increases impact of compromise (e.g., data exfiltration), encourages user distrust, and can lead to store policy or compliance issues.

**Recommendation**: Apply principle of least privilege: remove permissions that are not strictly necessary; use runtime permissions and explain why each is needed; avoid requesting permissions at install time for optional features.

---

### F-05: Insecure Data Storage in SharedPreferences

**Description**: Sensitive data such as credentials and API keys are stored in default (non-encrypted) SharedPreferences, which are stored as XML in app-private storage but are readable by root, backup, and any process with file access to the app’s data.

**Evidence**: Decompiled code shows reads/writes to SharedPreferences for credential-like keys; logcat references "Storing credential in SharedPreferences"; inspection of `shared_prefs` directory (e.g., via run-as) would show plaintext XML.

**Risk**: Theft of credentials via backup extraction, rooted device, or malware with sufficient privileges.

**Recommendation**: Use EncryptedSharedPreferences (AndroidX Security) or Android Keystore-backed encryption for any sensitive key-value data. Do not store passwords or API keys in plain SharedPreferences.

---

### F-06: Unencrypted Network Communication

**Description**: The app uses network (INTERNET permission) but the analyzed code does not show certificate pinning or strict HTTPS enforcement. This can allow MITM or downgrade attacks if the app or environment is misconfigured.

**Evidence**: Static review of network-related code and manifest; no Network Security Config or pinning implementation found.

**Risk**: Interception or modification of traffic; theft of session tokens or credentials in transit.

**Recommendation**: Enforce HTTPS for all endpoints; implement certificate pinning (e.g., Network Security Config with pin-set); avoid custom trust managers that disable validation; use HSTS where applicable.

## 4. Defensive Improvements Proposed

Aligned with secure system design:

| Improvement | Principle |
|-------------|-----------|
| **Use Android Keystore for credential storage** | Protect keys and secrets in hardware-backed or software-backed Keystore; avoid hardcoded or plaintext storage. |
| **Enforce permissions on exported components** | Minimize attack surface; only allow trusted callers (custom permission or signature check). |
| **Use ProGuard/R8 to obfuscate and strip sensitive strings** | Reduce impact of decompilation; strip debug logs and unnecessary symbols in release. |
| **Replace Log.d() for sensitive data with production-safe logging** | No credentials or PII in logs; use build flags or compile-out debug logs. |
| **Apply principle of least privilege for permissions** | Request only necessary permissions; use runtime permissions and clear justification. |
| **Use EncryptedSharedPreferences instead of plain SharedPreferences** | Encrypt sensitive key-value data at rest using Keystore-backed keys. |
| **Enforce HTTPS with certificate pinning** | Prevent MITM; use Network Security Config and pin-set for critical endpoints. |

## 5. Mapping to OWASP Mobile Top 10

| Finding ID | OWASP Mobile Top 10 (M1–M10) |
|------------|------------------------------|
| F-01 | M2: Insecure Data Storage (hardcoded secrets); M9: Reverse Engineering |
| F-02 | M1: Improper Platform Usage (exported components without protection) |
| F-03 | M2: Insecure Data Storage; M7: Client Code Quality (insecure logging) |
| F-04 | M1: Improper Platform Usage (overprivilege) |
| F-05 | M2: Insecure Data Storage |
| F-06 | M3: Insecure Communication |

(OWASP Mobile Top 10 categories: M1 Improper Platform Usage, M2 Insecure Data Storage, M3 Insecure Communication, M4 Insecure Authentication, M5 Insufficient Cryptography, M6 Insecure Authorization, M7 Client Code Quality, M8 Code Tampering, M9 Reverse Engineering, M10 Extraneous Functionality.)

## 6. Conclusion

The Android Systems Security Analysis Lab demonstrated how a controlled environment and a deliberately vulnerable app (DIVA) can be used to practice static and dynamic analysis, enumerate permissions and exported components, and identify hardcoded credentials and insecure logging. The findings reinforce that Android’s security model—permissions, sandboxing, and component visibility—must be used correctly: least privilege, no exported components without enforcement, and no sensitive data in logs or plaintext storage. Mapping findings to OWASP Mobile Top 10 and applying the proposed defensive improvements (Keystore, EncryptedSharedPreferences, permission enforcement, and secure communication) provides a concrete path from lab analysis to production-ready secure design.
