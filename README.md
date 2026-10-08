# 🏥 Secure Hospital Patient Record Exchange

**A complete, working, demonstrable answer to the CNS hackathon problem statement:**
hospitals exchange sensitive patient reports between doctors and departments, where attackers
may intercept or modify them in transit. This system protects every report with
**hybrid encryption (AES-256-GCM + RSA-OAEP)**, **SHA-256 integrity hashing**, and
**RSA-PSS digital signatures** over a Hospital-CA PKI — with a live MITM simulator,
tamper-evident audit log, and RBAC proving each property on screen.

| | |
|---|---|
| **Frontend** | Angular 17 + TypeScript (standalone components, JWT interceptor, route guards) |
| **Backend** | Django 5 + Django REST Framework + SimpleJWT (short-lived access, rotating refresh) |
| **Crypto** | AES-256-GCM · RSA-2048-OAEP-SHA256 · RSA-2048-PSS-SHA256 · SHA-256 · PBKDF2-HMAC-SHA256 |
| **PKI** | Offline-style Hospital CA issuing certificates over (identity ‖ key fingerprints) |
| **Audit** | Append-only SHA-256 hash-chained log with one-click chain verification |
| **Docs** | `docs/` — architecture, threat model, crypto justification, demo script, evaluation mapping, API reference |

---

## 1. Run it (3 commands, ~4 minutes)

**Prerequisites:** Python 3.10+, Node 18+, `pip`, `npm`. Internet needed once for installs.

```bash
# Terminal 1 — backend → http://127.0.0.1:8000
cd backend
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

```bash
# Terminal 2 — frontend → http://localhost:4200
cd frontend
npm install
npm start
```

Or one shot: `bash scripts/run.sh` (starts both; `bash scripts/stop.sh` stops them).

**Demo accounts (created by `seed_demo`):**

| Username | Password | Role / Department | Use in demo as… |
|---|---|---|---|
| `dr_asha` | `Cardio@123` | Doctor · Cardiology | **Sender** — seals & sends |
| `dr_rohan` | `Radio@123` | Doctor · Radiology | **Recipient** — decrypts & verifies |
| `lab_meera` | `Lab@1234` | Lab · Pathology | **Outsider** — gets 403 (RBAC proof) |
| `pharma_kabir` | `Pharma@123` | Pharmacist · Pharmacy | Extra directory entry |
| `admin` | `Admin@123` | Admin · Administration | Staff registration, full audit view |

Seeded patients: `MRN-1001` Aarav Sharma · `MRN-1002` Diya Patil · `MRN-1003` Kabir Khan.

---

## 2. The 3-click evaluator path (60 seconds to convinced)

1. **Send** — log in as `dr_asha` → *Send Report* → patient `MRN-1001`, recipient
   `dr_rohan` → **Seal & send**. Result shows the SHA-256 digest and `DELIVERED`.
   The database row holds ciphertext + wrapped key + hash + signature. *Plaintext is never stored.*
2. **Verify** — log in as `dr_rohan` → *Inbox* → *Open*. You see the decrypted body plus
   four badges: **AES-GCM tag PASS · SHA-256 PASS · RSA-PSS PASS · CA VALID**.
3. **Attack** — *Attacker Lab* → pick the report → **Flip 1 bit** → *Launch*:
   `TAMPER DETECTED`, caught by all three layers. Then try *Forge signature*,
   *Replay envelope*, *Steal envelope* — each caught, each naming its catcher.

Full 8-minute narration: [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md).

---

## 3. How a report is protected (the sealed envelope, v1)

```
SENDER (dr_asha)                                  SERVER (over TLS)                         RECIPIENT (dr_rohan)
     │                                                  │                                            │
     │  subject + body + patient                        │                                            │
     │─────────────────────────────────────────────────▶│  ① canonical JSON (+ timestamp/nonce/msg_id) │
     │                                                  │  ② digest = SHA-256(canonical)               │
     │                                                  │  ③ DEK ← CSPRNG(256b), iv ← CSPRNG(96b)      │
     │                                                  │  ④ ct = AES-256-GCM(DEK, iv, canonical, AAD) │
     │                                                  │  ⑤ wrapped = RSA-OAEP(recipient_pub, DEK)    │
     │                                                  │  ⑥ sig = RSA-PSS(sender_priv, digest)        │
     │                                                  │  ⑦ STORE {ct, wrapped, iv, digest, sig} ONLY │
     │                                                  │  ⑧ audit APPEND REPORT_SEAL_SEND (chained)   │
     │                                                  │───────────────────────────────────────────▶│  inbox row (metadata only)
     │                                                  │                                            │  ⑨ unwrap DEK (only recipient key works)
     │                                                  │                                            │  ⑩ GCM decrypt → FAILS CLOSED on any bit-flip
     │                                                  │                                            │  ⑪ recompute SHA-256, compare with stored
     │                                                  │                                            │  ⑫ PSS-verify digest with sender public key
     │                                                  │                                            │  ⑬ nonce-cache + AAD + timestamp replay check
     │                                                  │                                            │  ⑭ CA certificate re-validated
     │                                                  │                                            │  ⑮ plaintext shown + REPORT_OPEN_VERIFY_OK
```

Where `AAD = sender ‖ recipient ‖ msg_id ‖ nonce` binds the ciphertext to its context
(the timestamp is bound inside the signed canonical plaintext instead, keeping AAD
byte-stable between seal time and storage). Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

**Security properties, each with on-screen proof:**

| Requirement | Mechanism | Where you see it |
|---|---|---|
| **Confidentiality** | AES-256-GCM bulk + RSA-OAEP key wrap; TLS 1.2+; RBAC need-to-know; ciphertext-only storage | Report detail (only recipient decrypts); Attacker Lab *Steal envelope* → UNREADABLE; outsider → 403 |
| **Integrity** | GCM 128-bit tag + SHA-256 second layer; hash-chained audit log | Verification badges; *Flip 1 bit* → GCM FAIL; Audit → chain INTACT |
| **Authentication** | RSA-PSS signatures + Hospital-CA certificates + JWT + PBKDF2 passwords | CA VALID badge; Keys page fingerprints + certs |
| **Non-repudiation** | Stored PSS signature over digest + hash-chained attribution of every action | Verify-only endpoint; audit entries `REPORT_SEAL_SEND` / `REPORT_OPEN_VERIFY_OK` |
| **Availability** | Stateless DRF API; rate limits; idempotent re-open; SQLite→Postgres path | Throttle settings; repeated opens succeed |

---

## 4. Project layout

```
/mnt/data2/Hospital/
├── README.md                      ← you are here
├── docs/
│   ├── ARCHITECTURE.md            ← components, envelope bytes, sequences, RBAC, deployment
│   ├── THREAT_MODEL.md            ← assets, trust boundaries, STRIDE × 13, residual risks
│   ├── CRYPTO_JUSTIFICATION.md    ← why each primitive, parameters, rejected options, NIST/OWASP map
│   ├── API_REFERENCE.md           ← every endpoint: method, auth, body, responses
│   ├── DEMO_SCRIPT.md             ← 8-minute narration + viva Q&A bank
│   └── EVALUATION_MAPPING.md      ← FA clauses 1–6 → exact evidence locations
├── backend/
│   ├── config/                    ← settings (crypto policy, JWT, throttles, prod hardening)
│   └── secure_exchange/
│       ├── crypto_service.py      ← seal/open, OAEP, PSS, Hospital CA (the heart)
│       ├── models.py              ← Profile, Patient, Report, UsedNonce, AuditLog
│       ├── views.py               ← all API endpoints + RBAC + replay guards
│       ├── audit.py               ← hash-chain append + verify
│       ├── urls.py / serializers.py / admin.py
│       ├── management/commands/seed_demo.py
│       └── tests/test_crypto.py   ← 5 automated proofs (roundtrip, bit-flip, forgery, wrong-key, CA)
├── frontend/src/app/
│   ├── app.component.ts           ← shell: brand, nav, footer
│   ├── pages/                     ← login, dashboard, compose, inbox, report-detail,
│   │                                 patients, keys, audit, attacker-lab, security
│   └── services/                  ← auth.service (JWT), api.service + auth.guard
└── scripts/
    ├── run.sh / stop.sh           ← one-shot launch
    ├── attacker_demo.py           ← offline seal→attack→verify transcript (no server needed)
    └── openssl_interop.sh         ← same primitives via OpenSSL CLI (standards proof)
```

---

## 5. Tests & proofs (run these in front of evaluators)

```bash
cd backend
python manage.py test
# Ran 5 tests in ~1s — OK
# roundtrip · bit-flip detected · forged signature rejected ·
# wrong recipient cannot decrypt · CA issues & verifies

python ../scripts/attacker_demo.py
# == transcript complete: 5/5 behaviours as designed ==

bash ../scripts/openssl_interop.sh
# AES-GCM + RSA-OAEP + RSA-PSS + SHA-256 reproduced with stock OpenSSL
```

Browser E2E (Chrome DevTools, 11/11 green — login→send→open→4 attacks→audit→rotation→RBAC→mobile→Lighthouse 97/100/90) is recorded in the build log; re-run any of it live from the UI.

---

## 6. API at a glance (full reference: `docs/API_REFERENCE.md`)

| Method & path | Auth | What it does |
|---|---|---|
| `POST /api/auth/login/` · `POST /api/auth/refresh/` | — | JWT pair (15-min access, 7-day rotating refresh) |
| `POST /api/auth/register/` | JWT | Create staff → auto-issues dual RSA keypairs + CA cert |
| `GET /api/me/` · `GET /api/users/` · `GET /api/users/<u>/pubkeys/` | JWT | Identity, directory, public keys + fingerprints |
| `POST /api/keys/rotate/` | JWT | New keypair + cert; retired enc key archived for history-decrypt |
| `GET/POST /api/patients/` | JWT | Patient registry (MRN unique) |
| `POST /api/reports/send/` | JWT | Seal envelope → `DELIVERED` |
| `GET /api/reports/inbox/` · `/sent/` · `/search/?q=` | JWT | Own reports only (RBAC) |
| `GET /api/reports/<id>/open/` | JWT recipient | Decrypt + triple-verify; tamper → 409 + quarantine |
| `GET /api/reports/<id>/verify/` | JWT party | Signature-over-digest proof without decrypting |
| `POST /api/lab/attacker/<id>/` | JWT | 6 MITM modes on tampered clones (never mutates storage) |
| `GET /api/audit/` · `GET /api/audit/verify/` | JWT | Log + full chain verification |
| `GET /api/system/security-overview/` | open | Crypto policy, CIA+AN+A map, mitigations (drives UI) |

---

## 7. Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `401` on first login attempt | Old bundle — hard-refresh; current code saves tokens before profile fetch |
| `python manage.py seed_demo` slow | RSA-2048 ×2 per user ×5 users — one-time cost, ~10–20 s |
| Frontend `Cannot GET /api/...` | Backend not running, or proxy mis-pointed — check `proxy.conf.json` → `127.0.0.1:8000` |
| Port 4200 busy | `npx ng serve --port 4300` (proxy still works) |
| `pharma_kabir` can't open a report | Correct — only sender/recipient can (RBAC). That's a feature, demo it. |
| Old reports unreadable after rotation | Impossible by design — retired keys are archived and tried automatically |

**Production hardening roadmap** (say this when asked "what's next"): Postgres + encrypted backups ·
TLS termination with HSTS · HSM-backed offline CA + X.509 · client-side E2E via WebCrypto ·
Argon2id · per-department data partitioning · SIEM shipping of audit chain · formal key-escrow policy.
