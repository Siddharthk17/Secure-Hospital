# Crypto Justification — why this suite, these parameters, and nothing else

One-line version for the viva: **AES-256-GCM gives speed plus tamper-evidence,
RSA-OAEP solves delivery of the per-message key, RSA-PSS proves authorship,
SHA-256 anchors everything else — and every primitive is a boring, standard,
OpenSSL-reproducible choice.** This document is the long version.

---

## 1. Requirements → choices (traceability)

| Security requirement | Chosen mechanism | Why this one (not the neighbour) |
|---|---|---|
| Confidentiality, bulk data | **AES-256-GCM**, 96-bit nonce, 128-bit tag | Authenticated encryption in one pass: confidentiality *and* a tamper tag. CBC/CTR alone detect nothing; GCM fails closed on any modification. 256-bit key = 256-bit margin, HW-accelerated (AES-NI) everywhere. |
| Confidentiality, key delivery | **RSA-2048-OAEP-SHA256** wrapping a fresh 256-bit DEK per message | RSA cannot bulk-encrypt (slow, size-limited) — so it encrypts only the DEK. Fresh DEK per message ⇒ one leak exposes one report. OAEP (not PKCS#1 v1.5) ⇒ no Bleichenbacher/padding-oracle malleability. |
| Authenticity + non-repudiation | **RSA-2048-PSS-SHA256 (MGF1)** over the SHA-256 digest, **separate signing keypair** | PSS is the provably-secure padding (v1.5 has forgery history). Signing the *digest* keeps signatures constant-size. Separate keys ⇒ an encryption compromise is not a signing compromise. |
| Integrity anchor | **SHA-256** over canonical JSON | Collision + preimage resistant, 256-bit output, the same hash anchors fingerprints and the audit chain (one primitive to audit, three jobs done). |
| Passwords | **PBKDF2-HMAC-SHA256, 600k iterations** (Django default; Argon2id-ready) | OWASP/NIST-compliant work factor; salts per user; constant-time compare. Argon2id is the documented upgrade, not a rewrite. |
| Session auth | **JWT: 15-min access + 7-day rotating refresh (blacklisted on rotation)** | Short-lived bearers bound the replay window; rotation + blacklist kills stolen refresh tokens. |
| Freshness / anti-replay | **CSPRNG 96-bit nonce + UUID msg_id + UTC timestamp**, all inside signed body; nonce cache per recipient; AAD binding | Replays are rejected three independent ways; timestamps bound *inside* the signature, not beside it. |
| Audit integrity | **SHA-256 hash chain** over (seq‖actor‖action‖details‖prev‖ts) | No extra infra, no trusted timestamp server; any edit breaks verification at an exact sequence number. |
| Key authenticity (PKI) | **Hospital CA** certifying (identity ‖ enc fingerprint ‖ sig key) | Recipients trust *whose* key it is. Fingerprints shown in UI for out-of-band verification; rotation re-certifies; revocation enforced at send. |

---

## 2. Parameter sheet (exact values, where they live)

| Parameter | Value | Location |
|---|---|---|
| AES key / nonce / tag | 256 bit / 96 bit / 128 bit, fresh per message from `os.urandom` (CSPRNG) | `crypto_service.hybrid_encrypt` |
| RSA key size / exponent | 2048 bit / 65537 (demo; policy documents 3072+ for prod) | `RSA_KEY_SIZE`, `settings.HOSPITAL_CRYPTO_POLICY` |
| OAEP hash / MGF | SHA-256 / MGF1-SHA256, label `None` | `hybrid_encrypt` / `hybrid_decrypt` |
| PSS hash / MGF / salt | SHA-256 / MGF1-SHA256 / `MAX_LENGTH` | `sign_digest_pss` / `verify_digest_pss` |
| Canonical form | JSON, `sort_keys=True`, separators `(`,`, `,`:`, UTF-8 | `canonical_json` |
| AAD | `sender‖recipient‖msg_id‖nonce` (usernames, UUID, hex — byte-stable) | `Report.aad()` + `views._aad_for` |
| PBKDF2 iterations | 600 000 (Django 5 default) | `AUTH_PASSWORD_VALIDATORS` + hasher default |
| JWT lifetimes | access 15 min, refresh 7 days, rotate + blacklist | `SIMPLE_JWT` |
| Throttles | anon 30/min, user 120/min | `REST_FRAMEWORK` |
| CA key file | `backend/hospital_ca_key.pem`, mode `0600` | `crypto_service.get_ca` |

RSA-2048 vs 3072+: 2048 keeps the hackathon demo snappy (keygen ×2 per user at seed,
wrap/unwrap per message) while remaining NIST-acceptable through 2030; the policy
string and this doc both record 3072+ for production, and the size is one constant.

---

## 3. Why the envelope is built in this order

Seal: **canonicalise → hash → fresh DEK+IV → encrypt → wrap → sign → store.**
Each step's output is the next step's input, and verification unwinds it backwards
(decrypt → rehash → verify-signature), so a failure points at exactly one layer:

- GCM fails ⇒ transit/storage tampering (or wrong key) — checked *without* trusting anything else.
- Hash mismatches but GCM passed ⇒ metadata/digest row edited after sealing.
- Signature invalid but hash matches ⇒ forgery attempt with a different key.
- All pass ⇒ the bytes are exactly what the certified sender sealed, for this recipient, in this delivery.

AAD-then-plaintext binding deserves one extra sentence: because the GCM tag covers
`sender‖recipient‖msg_id‖nonce`, an attacker cannot transplant a valid ciphertext
into a different conversation, and because the timestamp lives inside the signed
body, backdating breaks the signature. Context and content are both nailed down.

## 4. Rejected alternatives (examiners ask; answer in one line each)

| Rejected | Reason |
|---|---|
| AES-CBC / CTR without MAC, ECB | No integrity (CBC has padding oracles; ECB leaks patterns). GCM gives AEAD in one primitive. |
| RSA PKCS#1 v1.5 (encryption or signing) | Bleichenbacher decryption oracles / signature forgery history; OAEP and PSS are the modern provable paddings. |
| One keypair for encrypt + sign | Cross-protocol attacks; doubles compromise blast radius. Separation is NIST/TCG practice. |
| MD5 / SHA-1 | Publicly collision-broken (SHAttered et al.). Inadmissible for integrity or signatures. |
| DES / 3DES / RSA-1024 | Below the NIST 112-bit security floor; brute-forceable. |
| Static / reused IV or DEK | Destroys GCM security and cross-message privacy; ours are CSPRNG-fresh per message. |
| Passwords in clear / unsalted fast hash | Credential theft + rainbow tables; PBKDF2+salt+throttle closes it. |
| Long-lived JWTs / no rotation | Stolen-token replay window; 15-min TTL + rotating refresh bounds it. |
| Homebrew ciphers / "secret algorithm" | Unreviewable. Every primitive here runs in stock OpenSSL — see `scripts/openssl_interop.sh`. |

## 5. Standards & compliance mapping

| Source | Requirement | Satisfied by |
|---|---|---|
| NIST SP 800-38D | GCM with 96-bit nonce, ≥128-bit tag | Exact parameters (§2) |
| NIST SP 800-56B / FIPS 186-5 | OAEP-SHA256 key transport; PSS signatures | Exact paddings (§2) |
| NIST SP 800-63B | Salted, iterated, memory-sensible password hashing; throttling; short sessions | PBKDF2 600k + throttles + 15-min JWT |
| OWASP ASVS 6.x (crypto) | No broken algorithms; randomness from CSPRNG; authenticated encryption; key separation; rotation | §§1–2 + rotation history |
| OWASP API Top 10 | Object-level authz (API1), authN (API2), rate limits (API4), audit (API10) | RBAC matrix + JWT + throttles + chain |

## 6. Key management policy (the part most student projects skip)

- **Generation:** RSA-2048, `e=65537`, OS CSPRNG (`cryptography` → OpenSSL). Two pairs per user, never shared across users.
- **Distribution:** public keys via authenticated API + CA certificate; fingerprints displayed for out-of-band (verbal/QR) confirmation.
- **Storage (demo):** server-side DB rows. Stated limitation; prod moves to HSM/KMS + client E2E with zero envelope-format change.
- **Rotation:** one click; retired enc keys archived (`old_enc_keys`) and tried automatically — history stays readable, versions tracked per report.
- **Revocation:** `revoked` flag checked at send time (409); prod publishes the list (CRL/OCSP hooks).
- **CA:** single file-persisted key (`0600`); prod splits into offline root + online intermediate with X.509.
- **Destruction/retention:** roadmap — expiry/purge policy + periodic DEK re-wrap for forward hygiene.

## 7. Randomness statement

All nonces, DEKs, IVs and UUIDs come from the OS CSPRNG (`os.urandom` / `secrets` /
`uuid4`). No userspace PRNG, no timestamps-as-randomness, no `random` module anywhere
near key material. Test suites never fix seeds for security paths.
