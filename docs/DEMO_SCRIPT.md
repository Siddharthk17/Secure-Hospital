# Demo Script — 8 minutes, word for word, with recoveries

**Setup before evaluators arrive:** both servers running (`scripts/run.sh`), frontend on
the projector at `/login`, backend terminal showing `manage.py test` green, DB freshly
seeded (`seed_demo`). Keep `docs/` open in a second window for the "show me" moments.

**Golden rule:** never narrate over a loading spinner. Click, pause one beat, then read
the screen aloud — the UI labels every security property for you.

---

## Minute 0:00–0:30 — Frame the problem in one breath

> "Hospitals move patient reports between doctors and departments, and anyone on that
> path can read or silently rewrite them — a changed dosage digit is a clinical event.
> Our system seals every report so that **only the named recipient can read it**,
> **any modification is caught on opening**, **authorship is provable**, and **every
> action is chained into a tamper-evident audit log**. Three clicks will prove all of it."

*Show:* login page hero + feature row. *Do not* log in yet.

## Minute 0:30–2:00 — Send (confidentiality being created)

1. Log in as `dr_asha / Cardio@123` → *Send Report*.
2. Point at the staff table: "Every recipient already has certified RSA keys — see the fingerprints."
3. Fill: patient `MRN-1001`, recipient `dr_rohan`, subject `ECG review — Aarav Sharma`,
   keep the sample body. Click **Seal & send**.
4. Read the result: "Digest `bd3b50…`, status DELIVERED. That digest is SHA-256 of the
   exact bytes sealed. The database row is ciphertext, a wrapped key, that hash and a
   signature — **no plaintext anywhere**."

*If send fails:* read the error aloud (unknown MRN / revoked recipient are all handled
messages, each is itself a feature — revoked-key refusal is threat T-S3 handled).

## Minute 2:00–3:30 — Receive and verify (integrity + authenticity)

1. Log out, log in as `dr_rohan / Radio@123` → *Inbox* → *Open* the new report.
2. Read the four badges slowly: "**GCM tag PASS** — not one bit changed in transit.
   **SHA-256 PASS** — the plaintext is byte-identical to what Asha sealed.
   **RSA-PSS PASS** — only Asha's signing key could have produced this.
   **CA VALID** — that signing key provably belongs to Asha."
3. Scroll to the body: "And only Rohan could ever see this — decryption needed his
   private key, which never left the server vault."

*If evaluators ask "prove the server can't read it":* offer to dump the DB row
(`sqlite3 hospital_secure.db "select ciphertext_b64 …"`) — base64 noise, no words.

## Minute 3:30–6:00 — Attacker Lab (the part they remember)

Open *Attacker Lab*, select the report, and run the script. Narrate attacker-then-catcher:

1. **Flip 1 bit** → Launch → "TAMPER DETECTED — quarantined. Caught by AES-GCM tag,
   confirmed by hash and signature. This is a wiretap that achieves nothing."
2. **Forge signature** → "PSS INVALID. Impersonating a doctor requires her private
   signing key. There is no 'close enough' in signatures."
3. **Replay envelope** → "REJECTED — nonce already consumed, context-bound, timestamped.
   Re-sending last week's dose order does not create a second order."
4. **Steal envelope** → "UNREADABLE. The thief holds everything except the one thing
   that matters — the recipient's unwrap key."

*If an attack ever shows NOT caught:* that is a defect, say so, and show the forensics
block — the lab prints raw booleans precisely so failures are debuggable, not hidden.

## Minute 6:00–7:00 — Audit and access control (non-repudiation + need-to-know)

1. *Audit* → **Verify chain now** → "INTACT, N entries. Every seal, open, deny and
   rotation is hash-linked — editing any row breaks the chain at an exact sequence number."
2. Log in as `lab_meera / Lab@1234`, paste the report URL → "**403 forbidden:
   sender/recipient only.** Curious insiders meet cryptography *and* access control —
   and the attempt itself is logged."

## Minute 7:00–8:00 — Close with depth (keys, tests, standards, roadmap)

> "Keys: separate encryption and signing pairs per user, SHA-256 fingerprints you can
> verify by phone, one-click rotation that keeps history readable, revocation enforced
> at send time. Tests: `python manage.py test` — five proofs, all green. Standards: no
> homebrew crypto — `scripts/openssl_interop.sh` reproduces every primitive in stock
> OpenSSL. Next: client-side E2E sealing, HSM-backed CA, Postgres, post-quantum wrap."

Then stop talking. Offer the viva bank below before they ask.

---

## Viva Q&A bank (30-second answers)

| Question | Answer |
|---|---|
| Why hybrid, not just RSA / just AES? | RSA can't bulk-encrypt (slow, size-capped); AES can't cross the network safely (no key delivery). AES moves the data, RSA moves the AES key. |
| Why GCM and not CBC? | GCM adds the authentication tag — tampering fails decryption. CBC alone detects nothing (padding oracles). |
| Why PSS and not v1.5? | PSS is provably secure with a security reduction; v1.5 has two decades of padding-forgery history. |
| Why separate enc/sign keys? | Blast-radius isolation + rotation scoping; cross-protocol attacks need shared keys. NIST/TCG practice. |
| How is replay stopped? | Nonce consumed once per recipient + AAD context binding + signed timestamp — three independent gates. |
| Non-recipient reads the DB? | Ciphertext + OAEP-wrapped DEK; unwrap needs the recipient private key. Dump it live. |
| Sender denies sending? | Stored PSS signature + `REPORT_SEAL_SEND` chain entry; verify-only re-proves authorship. |
| What if a key leaks? | Rotation archives history (readable), revocation blocks future sends, per-message DEKs bound the blast radius to… nothing retroactive except that user's mail. |
| Why trust the CA? | Demo CA, stated limitation — fingerprints are shown for out-of-band verification; prod is offline-root X.509. |
| Quantum? | Classical RSA-2048 documented; the wrap layer is the designated hybrid-PQ insertion point. |
| Scale to a real hospital? | Stateless API + Postgres, per-message keys, throttles, idempotent opens — §8 of ARCHITECTURE.md. |
