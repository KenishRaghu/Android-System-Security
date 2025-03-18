# Findings and Defensive Improvements

## Summary of Findings

From lab analysis of Android system behavior and sample applications:

1. **Overprivileged apps** — Many apps request broad permission sets; some use sensitive permissions only in optional features without clear justification, increasing impact of compromise or misuse.
2. **Exported components** — Several samples exposed activities or services without proper validation of callers or intent data, enabling unauthorized invocation or injection.
3. **Insecure storage** — Use of world-readable files or default backup for sensitive data allowed access from other apps or from backup images.
4. **Weak IPC and intent handling** — Unvalidated intents and Binder inputs could lead to denial-of-service, data leakage, or escalation when combined with other flaws.

## Proposed Defensive Improvements

Aligned with secure system design principles:

1. **Least privilege** — Limit permissions to the minimum required; use runtime permissions and explain usage; avoid device-admin or accessibility unless strictly necessary.
2. **Component hardening** — Set `android:exported="false"` unless the component must be public; validate callers (e.g., signature or permission checks) and sanitize all intent extras and Binder inputs.
3. **Secure storage** — Use Android Keystore for keys and credentials; avoid storing secrets in plaintext; disable backup for sensitive data or use encrypted backup.
4. **Network and data** — Prefer TLS for all traffic; avoid sending PII or device identifiers to untrusted endpoints; implement certificate pinning where appropriate.
5. **Monitoring and updates** — Use logcat and audit logs in the lab to baseline normal behavior; apply security updates and restrict use of deprecated or hidden APIs.

These measures reduce attack surface and limit the impact of malicious or vulnerable applications within the Android security model.
