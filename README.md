# Extending PR-RABE for Risk-Adaptive and Secure Cross-Organizational CTI Sharing

**B.Tech Project (BTP) — Phase II**
Department of CSE — Cyber Security, Indian Institute of Information Technology Kottayam

| Team | Roll Number |
|------|-------------|
| Manasa Manoj | 2023BCY0041 |
| Manish Anand | 2023BCY0053 |
| Jadhav Sai | 2023BCY0064 |
| Bhaskar Naik | 2023BCY0031 |

**Guide:** Dr. A Balu

---

## Overview

A full-stack web platform for **privacy-preserving cyber threat intelligence (CTI) sharing** that extends the PR-RABE (Privacy-preserving Revocable Registered Attribute-Based Encryption) scheme with a **risk-adaptive layer**.

The core contribution is an event-driven risk/trust engine that **automatically drives PR-RABE's AGK (Attribute Group Key) revocation**. Unlike the base scheme where revocation is manual, organizations' decryption eligibility changes dynamically as their behavioral trust evolves, without re-encrypting existing ciphertexts.

### Key Features

- **PR-RABE Encryption Pipeline** — KEM-DEM hybrid: AES-256-GCM authenticated encryption with HKDF-SHA256 key derivation, LSSS policy strings auto-generated from record sensitivity
- **Dynamic Trust Scoring** — Four-component weighted trust function (sharing 35%, violations 30%, reliability 20%, base 15%) computed at decryption time
- **Trust Tier Hierarchy** — HIGH (score >= 80) satisfies HIGH/MEDIUM/LOW policies; MEDIUM (>= 50) satisfies MEDIUM/LOW; LOW (< 50) satisfies only LOW
- **Risk-Adaptive Policies** — FIPS 199 high-water mark classification with Bell-LaPadula clearance model
- **Targeted Revocation** — AGK rotation revokes one organization without touching any other member's keys
- **One-Click Key Ceremony** — Complete the entire PR-RABE setup (CRS init, org keygen, aggregate) in a single step
- **Incentive Wallet** — Token-based reward system encouraging CTI sharing contributions
- **AES-256 Fallback Mode** — Full demo functionality on Windows without charm-crypto; real bilinear pairings on Linux/WSL
- **STIX 2.1 Intelligence** — Structured threat bundles (indicators, malware, attack-patterns, identities, observed-data)
- **CTI Correlation** — Cross-organizational indicator linking for campaign reconstruction
- **Knowledge Graph** — Interactive force-directed visualization of threat relationships
- **MITRE ATT&CK Mapping** — Technique heatmap with collaborative filtering predictions

---

## Architecture

The platform implements an **8-stage pipeline** with a continuous feedback loop:

```
CTI Sources (Organizations + OSINT)
        │
   1. CTI Collection ──── Ingest raw threat data (hashes, IPs, domains, TTPs)
        │
   2. Normalization ───── Convert to STIX 2.1 format
        │
   3. CTI Correlation ─── Link related indicators across organizations
        │
   4. Risk Analysis ───── Assess severity (CVSS, EPSS, sector impact)
        │
   5. Trust Profile ───── Compute org trust from behavioral signals ◄──┐
        │                                                                │
   6. Access Decision ─── Map sensitivity × trust → attribute policy    │
        │                                                                │
   7. PR-RABE Encrypt ─── LSSS policy with hidden attributes (AGK)     │
        │                                                                │
   8. Distribution ────── Ciphertext + header to authorized consumers   │
                                                                         │
   Feedback Loop: submissions, violations, behavior ─────────────────────┘
```

---

## Project Structure

```
CTI-BTP/
├── backend/
│   ├── app.py                    # Flask API routes and middleware
│   ├── crypto_engine.py          # AES-256-GCM + HKDF encryption pipeline
│   ├── prrabe_interface.py       # PR-RABE operations and AGK management
│   ├── policy_engine.py          # Risk-adaptive LSSS policy generation
│   ├── trust_engine.py           # Dynamic trust scoring (4 components)
│   ├── incentive_engine.py       # Token reward system for CTI sharing
│   ├── advanced_cti.py           # CTI record management + STIX bundles
│   ├── advanced_cti_processor.py # CTI processing and normalization
│   ├── correlation.py            # Cross-org indicator correlation
│   ├── risk_analysis.py          # CVSS/EPSS threat risk assessment
│   ├── authentication.py         # JWT auth with bcrypt
│   ├── organizations.py          # Organization CRUD + trust tracking
│   ├── database.py               # SQLite connection and schema
│   ├── seed_demo.py              # Database seeding (orgs, users)
│   ├── ai_predictor.py           # ML severity prediction
│   ├── temporal_engine.py        # Dynamic risk decay
│   ├── knowledge_graph.py        # Graph data builder
│   ├── graph_analytics.py        # PageRank centrality
│   ├── pdf_cti_extractor.py      # PDF threat report ingestion
│   ├── crypto/                   # PR-RABE_P cryptographic implementation
│   │   ├── prrabe/               # Core scheme (setup, encrypt, decrypt, AGK)
│   │   ├── service.py            # Crypto service (fallback AES + trust hierarchy)
│   │   ├── demo_simple.py        # Standalone ABE demo
│   │   └── demo_slide19.py       # Proposal slide 19 walkthrough
│   ├── policy_simulation.py      # Synthetic policy engine workload
│   └── tests/                    # Test suite
├── frontend/
│   └── src/
│       ├── App.jsx               # Navigation and app shell
│       ├── DashboardOverview.jsx  # Platform statistics dashboard
│       ├── CTISubmissionForm.jsx  # CTI submission with STIX generation
│       ├── KeyCeremony.jsx       # PR-RABE key ceremony (one-click setup)
│       ├── CryptoSharing.jsx     # PR-RABE encrypt/decrypt interface
│       ├── RevocationDemo.jsx    # AGK revocation demonstration
│       ├── IncentiveWallet.jsx   # Token wallet and reward history
│       ├── AccessControl.jsx     # Organization/user management
│       ├── KnowledgeGraph.jsx    # Threat relationship graph
│       ├── ATTACKNavigator.jsx   # MITRE ATT&CK heatmap
│       ├── TemporalIntelligence.jsx # Threat timeline analysis
│       ├── PDFIntelligence.jsx   # PDF extraction interface
│       ├── LandingPage.jsx       # Public landing page
│       ├── LoginPage.jsx         # Authentication UI
│       └── api.js                # API client with token management
├── requirements.txt              # Python dependencies
├── requirements-crypto.txt       # Optional: charm-crypto (Linux only)
└── README.md
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Flask 3.x (Python 3.11) |
| Frontend | React 18 + Vite |
| Database | SQLite (WAL mode) |
| Encryption | PyCryptodome (AES-256-GCM), HKDF-SHA256 |
| Authentication | JWT + bcrypt |
| CTI Format | STIX 2.1 |
| Visualization | react-force-graph-2d, Lucide Icons |

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+ and npm

### 1. Install dependencies

```bash
cd CTI-BTP
```

**Backend (Python):**

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

**Frontend (Node):**

```bash
cd frontend
npm install
cd ..
```

### 2. Initialize the database and seed demo data

```bash
python -m backend.seed_demo
```

This creates the SQLite database (`data/cti.db`) with:
- 3 organizations: Alpha Bank (Finance), City Hospital (Healthcare), Delta Insurance (Finance)
- 3 demo user accounts (one per organization)
- Trust scores that place each org in a distinct tier for meaningful access control demos

### 3. Start the application

**Terminal 1 — Backend (Flask API on port 5000):**

```bash
python -m backend.app
```

**Terminal 2 — Frontend (Vite dev server on port 5173):**

```bash
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

### 4. Run the Key Ceremony

After logging in, navigate to the **Key Ceremony** tab and click **Complete Full Ceremony**. This one-click action initializes the Common Reference String, generates keys for all organizations, and runs the aggregate step. The system is then ready to encrypt and decrypt CTI records.

### Demo Credentials

| Email | Password | Organization | Sector | Trust Tier |
|-------|----------|-------------|--------|------------|
| alice@alphabank.com | Demo1234! | Alpha Bank | Finance | HIGH (~80) |
| bob@cityhospital.com | Demo1234! | City Hospital | Healthcare | MEDIUM (~56) |
| carol@deltainsurance.com | Demo1234! | Delta Insurance | Finance | LOW (~41) |

> **Tip:** Log in as Alice (HIGH trust) to see full decryption access across all sensitivity levels. Then log in as Bob (MEDIUM) or Carol (LOW) to see restricted access. This demonstrates the trust tier hierarchy where HIGH satisfies HIGH/MEDIUM/LOW policies, MEDIUM satisfies MEDIUM/LOW, and LOW satisfies only LOW.

### Demo Walkthrough

1. **Login** as `alice@alphabank.com` / `Demo1234!`
2. **Key Ceremony** — Click "Complete Full Ceremony" to set up PR-RABE
3. **Submit CTI** — Submit a threat record (e.g., a malware hash or C2 IP)
4. **Crypto Sharing** — Encrypt the record with an attribute policy, then decrypt it
5. **Revocation Demo** — Revoke an attribute from an org and watch decryption fail
6. **Wallet** — Check the token rewards earned from sharing
7. **Access Control** — View org trust scores and user roles
8. **Overview** — See platform-wide statistics

---

## Platform Tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Dashboard with platform statistics, record counts, and org summaries |
| **Submit CTI** | Submit threat intelligence records with automatic STIX 2.1 bundle generation |
| **Organizations** | View all registered organizations with trust scores and sector info |
| **Key Ceremony** | PR-RABE key setup with one-click ceremony (CRS init + keygen + aggregate) |
| **Crypto Sharing** | Encrypt CTI records with LSSS attribute policies and decrypt with org keys |
| **Revocation Demo** | Demonstrate AGK rotation to revoke an org's access to specific attributes |
| **Wallet** | Incentive token balance and reward history for CTI contributions |
| **Access Control** | Organization and user management with trust tier visibility |

---

## Recent Modifications (Phase II)

### One-Click Key Ceremony
Added `/api/prrabe/complete-ceremony` endpoint that performs the full PR-RABE setup in one step: initializes the CRS, generates keys for all registered organizations (with trust-tier attributes), and runs the aggregate. Eliminates the need to log in as each org separately.

### Trust Tier Hierarchy in Fallback Decrypt
Fixed the fallback AES-256 decryption to respect trust tier hierarchy instead of exact attribute matching. A HIGH-trust org can now decrypt records requiring MEDIUM or LOW trust, matching how real ABE policies work with LSSS.

### Dynamic Trust Score Computation
Trust scores are computed at query time using four weighted components:
- **Sharing contribution (35%)** — based on submission count relative to peers
- **Policy violations (30%)** — penalty for compliance failures
- **Data reliability (20%)** — quality of submitted intelligence
- **Base score (15%)** — initial seed from registration

### AES-256 Fallback Mode
When charm-crypto is not available (Windows), the system uses AES-256-GCM with HKDF-SHA256 key derivation as a functional stand-in. The fallback enforces the same attribute policies and trust hierarchy. Real bilinear pairing operations are available on Linux/WSL with charm-crypto installed.

### Incentive Wallet
Token-based reward system that awards tokens when organizations contribute CTI records. Rewards are idempotent (one reward per record) and tracked with full history.

### Stale Record Cleanup
Re-running the key ceremony automatically clears old encrypted records from the database, preventing "record not found" errors from stale in-memory references.

---

## Encryption Details

### KEM-DEM Hybrid Scheme

1. **KEM (Key Encapsulation):** PR-RABE encrypts a random message `m` under an LSSS policy derived from the record's sensitivity and sector
2. **Key Derivation:** HKDF-SHA256 derives a 256-bit Data Encryption Key (DEK) from `m`
3. **DEM (Data Encapsulation):** AES-256-GCM encrypts the STIX payload with the DEK
4. **Decryption:** Only organizations whose attributes satisfy the LSSS policy can recover `m` and derive the DEK

### Policy Generation

Policies are auto-generated from record metadata:
- `(SECTOR:FINANCE AND TRUST:HIGH)` — high-sensitivity finance records
- `(SECTOR:HEALTHCARE AND TRUST:MEDIUM)` — medium-sensitivity health records
- `(TRUST:LOW)` — low-sensitivity records accessible to all trust tiers

---

## Optional: Real PR-RABE with Charm-Crypto (Linux/WSL)

```bash
sudo apt-get install -y libgmp-dev libssl-dev python3-dev flex bison m4 build-essential
wget https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz && tar xzf pbc-1.0.0.tar.gz
cd pbc-1.0.0 && ./configure && make && sudo make install && sudo ldconfig && cd ..
pip install -r requirements-crypto.txt
```

With charm-crypto installed, the system uses real bilinear pairing operations (Type-A SS512 curves) for PR-RABE encryption/decryption instead of the AES-256 fallback.

---

## Base Paper

R. Yang, T. Wang, N. Jin, B. Yang, Y. Zhou, D. Zhang, and X. Xin, "PR-RABE: Privacy-preserving and Revocable Registered Attribute-Based Encryption with lightweight encryption," *Computer Standards & Interfaces*, vol. 98, p. 104158, 2026.

---

## License

This project is developed as part of the B.Tech curriculum at IIIT Kottayam and is intended for academic purposes.
