# QSentinal: Quantum-Safe Readiness & Cryptographic Transition Platform

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![NIST](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%20%7C%20204-purple.svg)
![Architecture](https://img.shields.io/badge/architecture-Zero--Build%20Vanilla%20%2B%20Flask-success.svg)

QSentinal is an enterprise-grade, open-source quantum-safe readiness platform designed to evaluate organizational cryptographic risk, simulate post-quantum algorithms (NIST FIPS 203 ML-KEM and FIPS 204 ML-DSA), and provide actionable migration roadmaps against the threat of **Harvest Now, Decrypt Later (HNDL)**.

---

## Key Features

### 1. Dynamic Quantum Risk Calculator (Mosca's Theorem)
- **Mathematical Assessment:** Live evaluation of exposure applying Mosca's Theorem:
  $$\text{Exposure Condition: } X + Y > Z$$
  where $X$ = Data Retention Shelf-Life, $Y$ = Migration Execution Time, and $Z$ = Estimated Years to a Cryptographically Relevant Quantum Computer (CRQC).
- **Interactive Scoring:** Algorithm vulnerability weighting (RSA, ECC, Classical DH, AES), data sensitivity classifications, network exposure tiers, and industry multipliers.
- **Actionable Output:** Live animated SVG risk dial, compliance tier pill, transparent scoring formula, and tailored NIST algorithm recommendations.

### 2. Client-Side Post-Quantum Hybrid Encryption Pipeline
- **Real Cryptographic Execution:** Utilizes `@noble/post-quantum` and the browser Web Cryptography API (`crypto.subtle`).
- **NIST FIPS 203 ML-KEM:** Key establishment establishing a 256-bit shared secret.
- **HKDF & AES-256-GCM:** Key derivation with HKDF-SHA-256 followed by authenticated AES-256-GCM payload encryption with tag verification.
- **Zero-Knowledge Roundtrip:** Complete encrypt-and-decrypt verification without plaintexts ever leaving the client browser.

### 3. Digital Signatures Lab (NIST FIPS 204 ML-DSA)
- **Lattice-Based Signatures:** ML-DSA-65 key pair generation, message digest signing, and verification.
- **Tamper Simulation:** Interactive verification demonstrating invalidation upon bit-level message tampering.

### 4. Zero-Knowledge File Vault
- **Client-Side File Protection:** High-speed PBKDF2 passphrase key derivation (200,000 rounds SHA-256) and AES-256-GCM authenticated containerization.
- **Portable Format:** Exportable `.qsentinal.enc` protected containers.

### 5. Performance Center & Algorithm Benchmarks
- **Key & Signature Footprints:** Visual size comparisons across Classical RSA-2048, ECC P-256, ML-KEM-768, and ML-DSA-65.
- **Dynamic Charting:** Interactive Chart.js comparative metrics.

### 6. Migration Roadmap Center & AI Security Advisor
- **Phased Transition Plan:** Phase 1 (Inventory & Discovery), Phase 2 (Hybrid Pilots & Agility), Phase 3 (Full PQC Cutover).
- **Contextual Query Engine:** Real-time advisor providing answers on FIPS standards, agility strategies, and timeline planning.

---

## Architecture & Technology Stack

- **Frontend:** Zero-build, pure vanilla architecture (`index.html`, `style.css`, `script.js`). Uses ES Modules loaded via modern CDNs (`esm.sh`). No node build steps, webpack, or bundlers required.
- **Backend API:** Lightweight Flask server (`app.py`) providing simulation endpoints, benchmarks, health monitoring, and security header middleware.
- **Design System:** Custom CSS design system compliant with WCAG AA contrast standards, responsive across desktop and mobile devices down to 360px width.

---

## Getting Started

### Prerequisites
- Python 3.10+
- Modern web browser (Chrome, Firefox, Safari, Edge) with WebCrypto support.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/qsentinal.git
   cd qsentinal
   ```

2. **Set up a Python virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment (optional):**
   ```bash
   cp .env.example .env
   ```

5. **Run the application:**
   ```bash
   python app.py
   ```
   The platform will be available at `http://127.0.0.1:5000/`.

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/status` | Backend health, uptime, and engine capability report |
| `GET` | `/api/v1/benchmarks` | Comparative cryptographic overhead benchmarks |
| `POST` | `/api/v1/crypto/kem/keygen` | Simulates ML-KEM-768 key pair generation |
| `POST` | `/api/v1/crypto/kem/encapsulate` | Generates ciphertext and shared secret |
| `POST` | `/api/v1/crypto/kem/decapsulate` | Recovers shared secret from ciphertext |
| `POST` | `/api/v1/crypto/dsa/sign` | Generates ML-DSA signature over input payload |
| `POST` | `/api/v1/crypto/dsa/verify` | Verifies ML-DSA signature and payload integrity |
| `POST` | `/api/v1/roadmap` | Generates tailored phased migration roadmap |
| `POST` | `/api/v1/advisor/query` | Queries AI security advisory knowledge base |

---

## Security & Best Practices

- **Zero-Knowledge Core:** Sensitive message plaintexts and vault passphrases are never transmitted to any remote server.
- **Production Deployment:** For production deployments behind a reverse proxy (e.g. Nginx, Cloudflare), set `ALLOWED_ORIGIN` in `.env` and serve using a production WSGI server (`gunicorn` or `waitress`).
- **Security Headers:** The Flask backend automatically injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and strict referrer policies.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
