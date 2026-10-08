# Architecture — Secure Hospital Patient Record Exchange

This document explains the system the way an evaluator will interrogate it:
**what each part is, what bytes flow between parts, what happens step by step,
and what breaks (safely) when anything is wrong.** For *why these algorithms* see
[`CRYPTO_JUSTIFICATION.md`](CRYPTO_JUSTIFICATION.md); for *who attacks what* see
[`THREAT_MODEL.md`](THREAT_MODEL.md); for *every endpoint* see [`API_REFERENCE.md`](API_REFERENCE.md).

---

## 1. Context: what problem this solves

Hospital staff (doctors, lab technicians, pharmacists across departments) exchange
patient reports — diagnoses, ECG findings, dosages, follow-ups. On a hospital LAN or
the open internet, three things go wrong:

1. **Someone reads what they shouldn't** — eavesdropping on the wire, or a curious
   insider opening another department's reports (loss of *confidentiality*).
2. **Someone changes a report silently** — a flipped dosage digit, a swapped allergy
   line, a truncated finding (loss of *integrity*; clinically dangerous).
3. **Nobody can prove who sent what** — disputes, repudiated orders, unactionable
   audit trails (loss of *authentication* and *non-repudiation*).

The system below makes (1) mathematically infeasible without the recipient's private
key, (2) self-evident on every open, and (3) cryptographically attributable forever —
while keeping the workflow as simple as "compose → inbox → open".

---

## 2. System context diagram

```
                                  ┌─────────────────────────────────────────────┐
                                  │        SECURE HOSPITAL EXCHANGE             │
                                  │                                             │
  ┌──────────┐  HTTPS/TLS   ┌─────▼──────┐   Django + DRF    ┌──────────────┐   │   ┌────────────┐
  │ Angular  │◀────────────▶│  REST API  │◀────────────────▶ │ SQLite (demo)│   │   │ Hospital   │
  │ frontend │   JWT Bearer │ (stateless)│   ORM             │ envelopes +  │   │   │ CA (in-app │
  │ (no keys,│              │            │                   │ audit chain  │   │   │ signing key│
  │ no crypto│              │  crypto_   │                   │              │   │   │ + cert log)│
  │ in JS)   │              │  service   │                   │ NEVER plain- │   │   └────────────┘
  └──────────┘              └────────────┘                   │ text bodies  │
        ▲                                                    └──────────────┘                 │
        │                                                            ▲                        │
        │ doctors / lab / pharmacy / admin                           │                        │
        │ (PBKDF2 passwords, 15-min JWT)                    hash-chained audit appends        │
        └─────────────────────────────────────────────────────────────────────────────────────┘
```

**Deliberate layering decisions:**

- **Crypto lives server-side in one module** (`crypto_service.py`), not scattered across
  views and not in JavaScript. One place to audit, one place to upgrade algorithms,
  one place covered by unit tests. The documented roadmap moves sealing client-side
  (WebCrypto) once the demo PKI matures — the envelope format already supports it.
- **The API is stateless.** Every request carries a JWT; every report row is
  self-contained (ciphertext + wrapped key + hash + signature + context). Any number
  of API workers can serve behind a load balancer with a shared database.
- **The database never sees plaintext.** This is verifiable, not claimed: dump the
  `secure_exchange_report` table and you will find only base64 ciphertext, wrapped
  keys, digests and signatures.

---

## 3. Component catalogue

| Component | File(s) | Responsibility | Knows secrets? |
|---|---|---|---|
| `crypto_service` | `backend/secure_exchange/crypto_service.py` | Keygen, fingerprints, hybrid encrypt/decrypt, PSS sign/verify, seal/open envelope, Hospital CA | Yes — all key operations |
| `Report` (+`Patient`) | `models.py` | Envelope persistence; `aad()` context binding; replay-nonce uniqueness; RBAC relations | Ciphertext only |
| `Profile` | `models.py` | Per-user role/dept, dual keypairs, fingerprint, CA cert, revocation flag, retired-key archive | Private keys (server-custodied, demo) |
| `AuditLog` + `audit.py` | `models.py`, `audit.py` | Hash-chained append + full-chain verify | No |
| Views | `views.py` | Auth, patients, seal/send, open/verify, attacker lab, rotation, audit, RBAC gates | Via `crypto_service` only |
| Angular pages | `frontend/src/app/pages/` | Login, dashboard, compose, inbox, report-detail, patients, keys, audit, attacker-lab, security | JWT in memory/localStorage only |
| `ApiService`/`AuthService` | `frontend/src/app/services/` | HTTP + JWT interceptor + route guard | JWT only |

**Dual keypairs (why two per user):** every profile holds an *encryption* pair
(RSA-OAEP, "who may read for me") and a *signing* pair (RSA-PSS, "proof it was me").
A compromise of one use never kills the other, and rotation/revocation can be scoped.
This is NIST/TCG best practice, not decoration.

---

## 4. The sealed envelope — byte-level anatomy

A stored `Report` row is exactly this (nothing else, nothing secret-adjacent):

```
Report {
  id               UUID            ── primary key, also the audit handle
  patient          FK Patient      ── MRN + name (registry data, not clinical secrets)
  sender           FK User         ── author identity (attribution)
  recipient        FK User         ── the ONLY holder of the unwrap key (need-to-know)
  subject          str≤200         ── routing metadata (visible to sender/recipient/admin)
  ── sealed envelope ──────────────────────────────────────────────────────────
  ciphertext_b64   base64          ── AES-256-GCM(ct) = canonical plaintext + 128-bit tag
  wrapped_dek_b64  base64          ── RSA-OAEP-SHA256(recipient_enc_pub, DEK[32B])
  iv_b64           base64          ── 96-bit CSPRNG GCM nonce, fresh per message
  digest_hex       hex[64]         ── SHA-256(canonical plaintext) — the integrity anchor
  signature_b64    base64          ── RSA-PSS-SHA256(sender_sig_priv, digest) — authorship
  ── replay / context ─────────────────────────────────────────────────────────
  nonce_hex        hex             ── 96-bit CSPRNG, consumed once per recipient
  msg_id           hex unique      ── UUID, binds this envelope to one delivery
  sent_at          timestamp       ── inside canonical plaintext too (signed, not just stored)
  status           enum            ── SEALED → DELIVERED → OPENED / TAMPER_ALERT
  sender_key_version / recipient_key_version ── which key generation sealed/opened it
}
```

The **canonical plaintext** that is hashed, encrypted and signed is deterministic JSON:

```json
{"body":"…","patient_mrn":"MRN-1001","patient_name":"Aarav Sharma",
 "subject":"…","sender":"dr_asha","recipient":"dr_rohan",
 "timestamp":"2026-10-08T…","nonce":"…","msg_id":"…"}
```

Keys sorted, no whitespace — sender and verifier hash *identical bytes*.
`AAD = sender‖recipient‖msg_id‖nonce` is fed to AES-GCM as additional authenticated
data, so a ciphertext cut-pasted into another delivery fails even with the right key.
The timestamp rides inside the signed body (tampering it breaks hash + signature).

---

## 5. Workflows (the six sequences evaluators ask about)

### 5.1 Registration — staff onboarding with PKI

```
admin ──POST /api/auth/register {username,password,role,dept}──▶ server
  1. validate (password ≥ 8, role in {admin,doctor,lab,pharmacist})
  2. create Django user (PBKDF2-HMAC-SHA256, 600k iterations)
  3. generate enc pair + sig pair (RSA-2048, e=65537, CSPRNG)
  4. fingerprint = SHA256(DER(enc_pub))[:32]
  5. Hospital CA issues certificate over (username, dept, enc_fp, sig_pub)
  6. Profile row stored; audit APPEND USER_REGISTER (hash-chained)
◀── {username, role, dept, fingerprint, enc_pub, sig_pub, ca_certificate} ──
```

### 5.2 Send — seal in one atomic call

`POST /api/reports/send/ {patient_mrn, recipient_username, subject, body}`

1. Resolve patient (404 if unknown MRN) and recipient (404 unknown, 409 if revoked, 400 if self-send).
2. Fresh `nonce (12 B)` + `msg_id (UUID)`; canonical JSON built.
3. `digest = SHA-256(canonical)`.
4. `DEK ← CSPRNG(32 B)`, `iv ← CSPRNG(12 B)`; `ct = AES-256-GCM(DEK, iv, canonical, AAD)`.
5. `wrapped = RSA-OAEP-SHA256(recipient_enc_pub, DEK)` — from here on, only the recipient can read.
6. `sig = RSA-PSS-SHA256(sender_sig_priv, digest)` — from here on, authorship is undeniable.
7. Row stored (`DELIVERED`); audit `REPORT_SEAL_SEND` appended. Plaintext is dropped — it never touches disk.

### 5.3 Open — recipient-only decrypt with triple verification

`GET /api/reports/<id>/open/` (must be the recipient; sender gets metadata + verify-only; others get 403 + `REPORT_ACCESS_DENIED` logged)

1. For each candidate key (current enc private, then retired ones from rotation history):
   AES-GCM decrypt with stored AAD. **Any flipped/truncated bit → InvalidTag → next candidate → fail closed.**
2. Recompute `SHA-256(plaintext)`; compare with stored digest (second integrity layer).
3. `RSA-PSS verify(digest)` with sender's public signing key (authenticity + non-repudiation).
4. Replay: `UsedNonce(recipient, nonce)` recorded (re-open by same recipient is idempotent and allowed; cross-recipient replay is impossible via AAD).
5. CA certificate of the sender re-validated (key truly belongs to claimed sender).
6. All pass → `OPENED` + `REPORT_OPEN_VERIFY_OK` + plaintext returned with the four badges.
   Any fail → `TAMPER_ALERT` + `REPORT_TAMPER_DETECTED` + HTTP 409 with forensics.

### 5.4 Verify-only — auditing without decrypting

`GET /api/reports/<id>/verify/` re-checks the RSA-PSS signature over the stored digest
and reports sender fingerprint + status. Auditors and senders confirm authorship
without ever touching the recipient's private key.

### 5.5 Rotation — new keys without losing history

`POST /api/keys/rotate/`: current enc private key is appended to `old_enc_keys`,
fresh dual pairs are generated, fingerprint + CA cert re-issued, `key_version`
increments. `open` tries current then retired keys, so ciphertext sealed to v1 opens
fine under v2 — demonstrated in testing and safe to demo live.

### 5.6 Attacker Lab — controlled MITM on clones

`POST /api/lab/attacker/<id>/ {mode}` never mutates storage. It clones the envelope,
applies one attack, and runs the **real** open pipeline over the clone:

| Mode | Attack emulated | Caught by |
|---|---|---|
| `flip_bit` | wiretap flips one ciphertext bit | AES-GCM tag FAIL (+ hash + sig cascade) |
| `truncate` | packet cutter halves ciphertext | GCM length/tag failure |
| `forge_sig` | signature edited (impersonation) | RSA-PSS INVALID |
| `hash_swap` | stored digest zeroed (metadata tamper) | digest mismatch + signature INVALID |
| `replay_copy` | old envelope delivered twice | UsedNonce cache + AAD binding + timestamp window |
| `wrong_recipient` | thief holds the envelope, no key | RSA-OAEP unwrap impossible → UNREADABLE |

---

## 6. Audit chain — the tamper-evident log

```
entry(seq) = SHA-256( seq ‖ actor ‖ action ‖ details ‖ prev_hash ‖ timestamp )
chain:  GENESIS(0…0) → e1 → e2 → … → head
```

Every security-relevant action appends (`USER_REGISTER`, `PATIENT_CREATE`,
`REPORT_SEAL_SEND`, `REPORT_OPEN_VERIFY_OK`, `REPORT_TAMPER_DETECTED`,
`REPORT_ACCESS_DENIED`, `KEY_ROTATE`, `SEED`). `GET /api/audit/verify/` recomputes
the whole chain; editing, deleting or reordering any row breaks it at exactly one
sequence number, which the UI reports. The log is the system's memory of *who did
what* — it underpins non-repudiation as much as signatures do.

---

## 7. Access control matrix (RBAC + need-to-know)

| Action | Admin | Sender (author) | Recipient | Any other staff | Anonymous |
|---|---|---|---|---|---|
| Register staff | ✅ | ✅ (demo) | ✅ (demo) | ✅ (demo) | ❌ 401 |
| Read patient registry | ✅ | ✅ | ✅ | ✅ | ❌ 401 |
| Send report | ✅ | ✅ | ✅ | ✅ | ❌ 401 |
| List own inbox/sent | ✅ (own) | ✅ (own) | ✅ (own) | ✅ (own) | ❌ 401 |
| **Decrypt** report | ❌ | ❌ (metadata + verify-only) | ✅ | ❌ 403 + logged | ❌ 401 |
| Verify-only signature | ✅ | ✅ own | ✅ own | ❌ 403 | ❌ 401 |
| Attacker Lab on report | ✅ own | ✅ own | ✅ own | ❌ 403 | ❌ 401 |
| Rotate own keys | ✅ | ✅ | ✅ | ✅ (own) | ❌ 401 |
| Audit list / verify | ✅ | ✅ | ✅ | ✅ | ❌ 401 |

The critical row is **decrypt**: only the recipient's private key unwraps the DEK,
so even a database administrator reading raw rows learns nothing, and even an
admin API identity cannot decrypt through the API.

---

## 8. Deployment & scalability

```
                    ┌──────────────┐
  doctors ──TLS──▶  │ reverse proxy│──▶ static Angular (nginx aro dist/)
                    │ (TLS/HSTS)   │──▶ N × Django API workers (stateless, shared DB)
                    └──────────────┘──▶ Postgres (prod) / SQLite (demo)
                                         backups encrypted · audit chain verified by cron
```

- **Stateless API** → horizontal scale behind any load balancer; JWT needs no session affinity.
- **Per-message DEK** → no mass-decrypt: one leaked/stolen DEK exposes one report.
- **Throttle** → 30/min anonymous, 120/min authenticated (brute-force and flood resistance).
- **Idempotent opens** → retries and double-clicks are safe; replay protection is per-recipient.
- **Upgrade seams** → `crypto_service.py` is the single algorithm boundary (bulk cipher,
  KDF, key size all change in one place); `old_enc_keys` makes rotation lossless;
  SQLite→Postgres is a settings change (no code).

**Failure modes (all fail closed):** tampered ciphertext → 409 quarantine, never
partial plaintext · wrong key → unwrap error, nothing returned · revoked recipient →
send refused at seal time · expired JWT → 401, refresh rotation · audit edit →
verify reports the exact broken sequence · CA key loss → certs unverifiable (documented;
prod keeps offline backup + X.509 chain).
