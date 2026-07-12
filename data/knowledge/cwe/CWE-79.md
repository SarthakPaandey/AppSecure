# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Official URL:** https://cwe.mitre.org/data/definitions/79.html

## Description

The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page that is served to other users.

## Mitigations

- Context-aware output encoding (HTML, attribute, JS, URL contexts).
- Prefer frameworks that auto-escape by default.
- Implement a strong Content-Security-Policy.
- Validate and sanitize untrusted input; treat all input as untrusted.
