# QSentinal Platform: Comprehensive Codebase Analysis & Strategic Plan

## Executive Summary

**QSentinal** (`h:\qiskitt`) is a quantum-safe readiness and educational platform focused on **Post-Quantum Cryptography (PQC)** readiness, threat intelligence, and cryptographic migration planning. The platform addresses emerging enterprise concerns surrounding quantum computing threats—specifically Shor's algorithm and "Harvest Now, Decrypt Later" (HNDL) data interception campaigns—by highlighting the NIST-standardized algorithms:
- **ML-KEM** (FIPS 203 / Module-Lattice-Based Key-Encapsulation Mechanism)
- **ML-DSA** (FIPS 204 / Module-Lattice-Based Digital Signature Algorithm)
- **Stateful & Classical baselines** (RSA-2048, ECC P-256, AES-256-GCM)

The codebase has been refactored into a **fully synchronized full-stack architecture** with an active Python Flask API backend and an interactive client:
1. [`app.py`](file:///h:/qiskitt/app.py) — Production Flask API backend serving 12 cryptographic & analytics endpoints and security headers.
2. [`index.html`](file:///h:/qiskitt/index.html) — Single-page application structure with live backend synchronization indicators and dual-mode file vault.
3. [`script.js`](file:///h:/qiskitt/script.js) — Controller logic handling automated backend syncing, fallback offline mode, and zero-knowledge PBKDF2/AES-GCM encryption & decryption.
4. [`style.css`](file:///h:/qiskitt/style.css) — Custom design system with WCAG AA compliant typography, status indicators, and responsive breakpoints.

---

## 1. Codebase Architecture & Feature Breakdown

### 1.1 Structural Inventory

```
h:\qiskitt\
├── app.py           # Flask REST API server (Port 5000), crypto engine, analytics & advisor
├── index.html       # Single-page layout containing 12 distinct sections & modals
├── script.js        # Controller logic, event listeners, Chart.js instances, Web Crypto
├── style.css        # Complete CSS design system, typography, animations, responsive media queries
└── plan.md          # Architectural audit and implementation report
```

### 1.2 Module-by-Module Analysis

| Section ID | Section Title | Code Reference | Functionality & Implementation |
| :--- | :--- | :--- | :--- |
| `#home` | **Hero & Visual Core** | [`index.html:40-72`](file:///h:/qiskitt/index.html#L40-L72) | Dynamic orbit animation (`.visual-orbit`, `.visual-core`), node callouts (ML-KEM, ML-DSA, AES-256), CTA triggers, and four-column metric summary strip. |
| `#threats` | **Threat Intelligence** | [`index.html:74-117`](file:///h:/qiskitt/index.html#L74-L117) | "Harvest Now, Decrypt Later" briefing, mini-stats, and an interactive 4-step comparative pathway grid contrasting the legacy exposure path vs. quantum-ready path. |
| `#dashboard` | **Quantum Threat Exposure Engine** | [`index.html:119-150`](file:///h:/qiskitt/index.html#L119-L150), [`script.js:88-126`](file:///h:/qiskitt/script.js#L88-L126), [`app.py:75-155`](file:///h:/qiskitt/app.py#L75-L155) | Interactive assessment tool computing exposure scores synced with `POST /api/v1/assess`. Updates conic-gradient score ring, dependency bars, and a Chart.js line projection (`#riskChart`). |
| `#messaging` | **Secure Messaging Pipeline** | [`index.html:152-179`](file:///h:/qiskitt/index.html#L152-L179), [`script.js:127-164`](file:///h:/qiskitt/script.js#L127-L164), [`app.py:240-285`](file:///h:/qiskitt/app.py#L240-L285) | 4-stage animated pipeline simulation synced with `POST /api/v1/crypto/messaging/send`: (1) ML-KEM Key establishment, (2) HKDF Shared secret derivation, (3) AES-256-GCM authenticated encryption, (4) Bob reception. |
| `#algorithms` | **Post-Quantum Toolkit** | [`index.html:181-192`](file:///h:/qiskitt/index.html#L181-L192) | Deep-dive cards for FIPS 203 ML-KEM, FIPS 204 ML-DSA, and AES-256, detailing functional flow (`KeyGen → Encaps → Decaps`, etc.) and role distinctions. |
| `#kem-demo` | **ML-KEM Interactive Lab** | [`index.html:193-203`](file:///h:/qiskitt/index.html#L193-L203), [`script.js:165-185`](file:///h:/qiskitt/script.js#L165-L185), [`app.py:157-220`](file:///h:/qiskitt/app.py#L157-L220) | Step-by-step interactive state machine synced with `/api/v1/crypto/kem/*` for Key Generation (1,184-byte PK), Encapsulation (1,088-byte CT), and Decapsulation. |
| `#dsa-demo` | **ML-DSA Signature & Verification Lab** | [`index.html:204-210`](file:///h:/qiskitt/index.html#L204-L210), [`script.js:186-200`](file:///h:/qiskitt/script.js#L186-L200), [`app.py:222-255`](file:///h:/qiskitt/app.py#L222-L255) | Authenticated signing and constant-time verification engine synced with `/api/v1/crypto/dsa/sign` & `verify`. |
| `#benchmark` | **Performance Center** | [`index.html:211-226`](file:///h:/qiskitt/index.html#L211-L226), [`script.js:65-86`](file:///h:/qiskitt/script.js#L65-L86), [`app.py:287-320`](file:///h:/qiskitt/app.py#L287-L320) | Live benchmark data synced with `GET /api/v1/benchmarks` comparing Public Key Size, Signature/Ciphertext Size, and Latency indices across RSA-2048, ECC P-256, ML-KEM-768, and ML-DSA-65. |
| `#file-vault` | **Zero-Knowledge File Vault** | [`index.html:227-285`](file:///h:/qiskitt/index.html#L227-L285), [`script.js:315-460`](file:///h:/qiskitt/script.js#L315-L460) | Dual-mode authenticated file encryption and decryption using PBKDF2 (SHA-256, 100,000 iterations), 16-byte random salt, 12-byte random IV, and AES-256-GCM. |
| `#migration` | **Migration Roadmap Center** | [`index.html:286-300`](file:///h:/qiskitt/index.html#L286-L300), [`script.js:462-495`](file:///h:/qiskitt/script.js#L462-L495), [`app.py:322-355`](file:///h:/qiskitt/app.py#L322-L355) | Sector-tailored 5-phase migration roadmap builder synced with `POST /api/v1/roadmap`. |
| `#advisor` | **AI Security Advisor** | [`index.html:301-320`](file:///h:/qiskitt/index.html#L301-L320), [`script.js:497-545`](file:///h:/qiskitt/script.js#L497-L545), [`app.py:357-415`](file:///h:/qiskitt/app.py#L357-L415) | Live AI advisor engine queried via `POST /api/v1/advisor/query` with verified PQC knowledge bases on Shor's algorithm, ML-KEM, ML-DSA, hybrid migration, and HNDL. |
| `#architecture`| **Platform Architecture** | [`index.html:330-350`](file:///h:/qiskitt/index.html#L330-L350) | Visual architectural blueprint showing Frontend → Flask API (Online · Live Synced) → Cryptography Engine → Analytics Engine → Visualization Layer. |

---

## 2. Technical Stack & Dependencies

- **Backend**: Python 3.15, Flask 3.1.3, Flask-CORS 6.0.5, Cryptography 50.0.2 (AESGCM, HKDF, SHA-256/512).
- **Frontend Core**: Vanilla HTML5 + CSS3 + Vanilla ES6+ JavaScript.
- **Visualizations**: Chart.js v4.4.4.
- **Web Cryptography API**: `crypto.subtle` (PBKDF2, AES-GCM, getRandomValues).
- **Security Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`.

---

## 3. Remediation & Vulnerabilities Addressed

### Vulnerability 1: Data Loss / Unrecoverable File Encryption in File Vault (FIXED)
- **Problem**: Prior implementation generated an ephemeral AES key, encrypted the file, zeroized the key in memory immediately, and downloaded the file. The file was permanently un-decryptable.
- **Resolution**: Implemented authenticated passphrase key derivation using `PBKDF2` (100,000 rounds, 16-byte random salt, 12-byte random IV) and `AES-256-GCM`. Encapsulated metadata into container format `QSEN` (v1) and built a dedicated Decryption tab that authenticates the tag and restores the original file.

### Vulnerability 2: Insecure Deprecated `unescape()` & Fake Base64 in Messaging (FIXED)
- **Problem**: Messaging used `btoa(unescape(encodeURIComponent(message)))` which is deprecated and was only Base64-encoding plain text.
- **Resolution**: Replaced with genuine Web Crypto / Flask `AES-256-GCM` encryption with standard `TextEncoder` and `TextDecoder`, producing authentic authenticated ciphertexts and tags.

### Vulnerability 3: Missing Backend & Desynchronized State (FIXED)
- **Problem**: Section 12 advertised a Flask API, but no backend existed.
- **Resolution**: Built `app.py` with 12 endpoints. Added a live heartbeat monitor (`checkBackendSync`) in the navigation header that switches between `Backend: Synced (Flask v1.0)` and `Standalone Offline Mode`.

### Vulnerability 4: Readability & WCAG AA Accessibility Failures (FIXED)
- **Problem**: Badges, labels, and disclaimers utilized microscopic fonts (`7px`, `8px`, `9px`).
- **Resolution**: Raised all micro-fonts across `style.css` to compliant sizes (11px for badges/meta, 12px for descriptions, 13–15px for body text).

---

## 4. Implementation Status

- [x] Flask Backend Scaffolding (`app.py`) running on port 5000.
- [x] All 12 REST API endpoints implemented and integration tested.
- [x] Frontend-backend automatic synchronization with live status pill.
- [x] Dual-mode File Vault (Authenticated Encryption + Decryption).
- [x] WCAG AA typography and accessibility overhaul.
- [x] Security headers and payload limits configured.
