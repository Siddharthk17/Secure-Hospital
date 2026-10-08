# Threat Model — what we defend, against whom, and how you can watch it fail safely

Method: asset-first, then trust boundaries, then STRIDE per data flow. Every threat
ends with **where to see the defence work** — a live UI path, an API call, or a test —
because a mitigation you cannot demonstrate is just a paragraph.

---

## 1. Assets (what is valuable, in order of clinical impact)

1. **Report plaintext** (diagnoses, dosages, allergies) — disclosure harms patients;
   modification harms them worse (wrong treatment).
2. **Decryption private keys** — whoever holds one reads everything sealed to it.
3. **Signing private keys** — whoever holds one can impersonate a doctor.
4. **CA signing key** — whoever holds it can certify impostor keys for anyone.
5. **Audit log** — whoever rewrites it erases accountability.
6. **Credentials & JWTs** — the front door to all of the above.
7. **Availability of the exchange itself** — a down system delays care.

## 2. Attackers (who we assume)

| Attacker | Capability | Example |
|---|---|---|
| **A1 — Network eavesdropper** | Reads all traffic (Wireshark on LAN, open Wi-Fi) | Sees ciphertext only |
| **A2 — Active MITM** | Reads, flips, truncates, replays, injects packets | Bit-flip, truncation, replay |
| **A3 — Forger** | Wants to send/alter reports as someone else, without their keys | Signature forgery, hash swap |
| **A4 — Curious insider** | Valid login, wrong department/patient | Opens another doctor's report |
| **A5 — Credential guesser** | No account; tries passwords / steals tokens | Brute force, token replay |
| **A6 — Log tamperer** | DB/file access; edits history to hide (A2–A5) | Audit row edit/delete |
| **A7 — Key thief** | Steals a private key or an old envelope | Reads that user's mail |

Out of scope (stated honestly in viva): endpoint malware on a doctor's laptop,
physical theft of an unlocked workstation, and quantum attacks on RSA (roadmap:
hybrid post-quantum KEM at the key-wrap layer).

## 3. Trust boundaries

```
  UNTRUSTED                              TRUSTED (server)                      SECRET
  ─────────                              ────────────────                      ──────
  network wire ──TLS──▶ API boundary ──▶ views (RBAC) ──▶ crypto_service ──▶ keys/DEKs
  browser JS (no keys)    JWT check        audit append        DB rows (CT only)
  stolen envelopes        throttle         AAD/replay checks
```

Crossing each boundary requires: TLS cert (wire→API), valid short-lived JWT
(API→views), sender/recipient relationship (views→data), private key material
(data→plaintext). Defence in depth means A2 defeating TLS still faces GCM+PSS,
and A4 passing JWT still faces RBAC + OAEP.

---

## 4. STRIDE analysis (13 threats — each with mechanism, mitigation, live proof)

**S — Spoofing**

| ID | Threat | How it would work here | Mitigation (implemented) | Watch it fail |
|---|---|---|---|---|
| T-S1 | Impersonate a doctor | Send/alter a report claiming to be `dr_asha` | RSA-PSS signature over digest + CA-bound keys; attacker has no signing key | Attacker Lab → *Forge signature* → PSS INVALID |
| T-S2 | Login as someone else | Guess/reuse passwords | PBKDF2-HMAC-SHA256 600k + login throttle (30/min anon) + 15-min JWT | Rapid bad logins → 429; wrong password → 401 |
| T-S3 | Fake key ownership | "Here is dr_asha's *new* public key" (key substitution) | Hospital-CA certificates bind identity‖fingerprints; UI shows fingerprints; rotation re-certifies | Keys page: verify fingerprint out-of-band; forged cert → verify fails |

**T — Tampering**

| ID | Threat | How it would work here | Mitigation | Watch it fail |
|---|---|---|---|---|
| T-T1 | Flip bits on the wire | A2 edits ciphertext in transit (dosage `75mg`→`75Om?…`) | AES-256-GCM 128-bit tag: decrypt **fails closed**, zero partial output | Attacker Lab → *Flip 1 bit* → GCM FAIL, quarantined 409 |
| T-T2 | Truncate / cut-paste | Drop the tail; splice two envelopes | GCM length+tag + AAD context binding + digest compare | *Truncate* → FAIL on all layers |
| T-T3 | Swap stored hash/signature | Edit DB metadata to match forged body | Digest recomputed from decrypted plaintext; signature covers digest; PSS re-verified | *Swap stored hash* → mismatch + PSS INVALID |
| T-T4 | Rewrite history | A6 edits audit rows to hide T-T1…T-S2 | SHA-256 hash chain; verify recomputes every link | Edit DB row → Audit → *Verify* reports broken seq |
| T-T5 | Replay a delivery | Re-send last week's envelope (duplicate dose order) | `UsedNonce(recipient,nonce)` + AAD binding + timestamp window | *Replay envelope* → REJECTED, three reasons listed |

**R — Repudiation**

| ID | Threat | How it would work here | Mitigation | Watch it work |
|---|---|---|---|---|
| T-R1 | "I never sent that" | Sender denies an order | Stored PSS signature + `REPORT_SEAL_SEND` chain entry; verify-only endpoint re-proves authorship without decrypting | Report detail → signature PASS; Audit shows seal entry |

**I — Information disclosure**

| ID | Threat | How it would work here | Mitigation | Watch it fail |
|---|---|---|---|---|
| T-I1 | Sniff the wire | A1 captures everything (Wireshark demo) | TLS + ciphertext-only payloads; DEK never travels in clear | DB/API traffic shows base64 CT only |
| T-I2 | Open someone else's report | A4 clicks a report URL directly | RBAC sender/recipient-only; decryption needs recipient private key anyway | Login `lab_meera` → open → **403 + logged** |
| T-I3 | Read the database | Dump tables / steal backup | Rows hold CT + OAEP-wrapped DEK; unwrap needs recipient key | `sqlite3 hospital_secure.db` → no plaintext anywhere |
| T-I4 | Steal an envelope | A7 holds full message, no keys | Per-message DEK via OAEP to one recipient | *Steal envelope* → UNREADABLE |

**D — Denial of service**

| ID | Threat | How it would work here | Mitigation |
|---|---|---|---|
| T-D1 | Flood the API | Credential stuffing / request flood | Anon 30/min + user 120/min throttles; stateless workers scale horizontally |
| T-D2 | Lock everyone out via rotation | Mass-revoke keys | Revocation is per-user + checked at send; retired keys keep history readable |

**E — Elevation of privilege**

| ID | Threat | How it would work here | Mitigation |
|---|---|---|---|
| T-E1 | Become admin / recipient | JWT tampering, IDOR (`/reports/< чужой-id>/open/`) | JWTs are signed server-side; every object access re-checks sender/recipient/admin; violations logged as `REPORT_ACCESS_DENIED` |

---

## 5. Attack trees (read: cheapest path for the attacker)

**Goal: read a report.** Sniff (T-I1✖ CT only) → steal DB (T-I3✖ CT only) →
steal recipient private key (possible — endpoint security, out of scope) →
guess password + login as recipient (T-S2, throttled + 15-min tokens) →
*cheapest realistic path is the front door, and it is rate-limited, KDF-hardened and audited.*

**Goal: modify a report undetected.** Flip wire bits (T-T1✖ GCM) → edit DB body
(T-T3✖ digest+sig) → forge signature (T-S1✖ no key) → rewrite audit too
(T-T4✖ chain verify) → *every path ends at a check the attacker cannot satisfy
without a private key they don't have.*

That asymmetry — cheap to defend, expensive to attack — is the whole design.

---

## 6. Residual risks (say these out loud; honesty scores)

1. **Server-custodied private keys (demo).** The DB holds user private keys so the
   hackathon runs without client key management. Production moves to HSM/KMS +
   WebCrypto E2E; the envelope format already supports it (seal inputs are just bytes + PEMs).
2. **Single in-app CA key.** File-persisted with `0600`, but one key. Production:
   offline root + online intermediate + X.509 chain + published revocation list
   (the `revoked` flag and send-time check are the hooks).
3. **No forward secrecy on stored mail.** OAEP-encrypted DEKs can be read if the
   recipient key is *later* stolen. Mitigations present: rotation + short-lived
   access; roadmap: periodic re-wrap (re-seal DEKs to fresh keys) and expiry/purge policy.
4. **TLS terminates at the reverse proxy.** Assumed, not bundled; prod checklist in
   `settings.py` (HSTS, secure cookies, `SECURE_SSL_REDIRECT`) activates with `DEBUG=0`.
5. **Classical crypto.** RSA-2048 is not quantum-safe; the wrap layer is the
   designated hybrid-PQ insertion point (e.g., X25519+Kyber KEM) without touching
   the envelope schema.

## 7. Security testing checklist (all executed)

- [x] `manage.py test` — roundtrip, bit-flip kill, forgery reject, wrong-key fail, CA verify
- [x] `attacker_demo.py` — offline 5/5 transcript (no server)
- [x] Browser E2E 11/11 — login→send→open→4 attacks→audit→rotation→RBAC→mobile→Lighthouse
- [x] `openssl_interop.sh` — primitives reproduced in stock OpenSSL (no homebrew crypto)
- [x] RBAC matrix spot-checks incl. 403 + `REPORT_ACCESS_DENIED` logging
- [x] Rotation continuity: v1-sealed report opens after rotating to v2
- [x] Console clean (zero JS errors); mobile 390px layout verified
