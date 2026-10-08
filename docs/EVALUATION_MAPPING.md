# Evaluation Mapping — FA clauses 1–6 → exact evidence

The FA notice asks for six things. Below is each clause, what the evaluator is really
checking, and the precise file / screen / command that proves it. Keep this page open
during assessment and jump on demand.

## Clause 1 — Security requirements (C, I, Authentication, Non-repudiation, Availability)

*Checking:* can you name all five and tie each to a mechanism, not a slogan?
*Evidence:*
- `docs/ARCHITECTURE.md` §1 (problem framing) and README §3 (property→mechanism→proof table).
- Live: Security page (`/security`) renders CIA+AN+A rows from
  `GET /api/system/security-overview/` — backend truth, not slides.
- Say the one-breath version from `docs/DEMO_SCRIPT.md` minute 0:00.

## Clause 2 — Threats and vulnerabilities

*Checking:* STRIDE-style thinking with concrete mitigations per threat.
*Evidence:*
- `docs/THREAT_MODEL.md` — assets, trust boundaries, 13-row STRIDE table, attack trees,
  residual risks stated honestly, testing checklist.
- Live: Attacker Lab (`/attacker-lab`) — six MITM modes, each naming its catcher;
  RBAC 403 as `lab_meera`; audit chain verify.
- Code: `backend/secure_exchange/views.py` (gates), `models.py` (`UsedNonce`, `revoked`).

## Clause 3 — Encryption selection and justification

*Checking:* named algorithms + parameters + *why*, plus awareness of what you rejected.
*Evidence:*
- `docs/CRYPTO_JUSTIFICATION.md` — requirement traceability, parameter sheet with file
  pointers, seal-order rationale, rejected-alternatives table, NIST/OWASP mapping,
  key-management policy, randomness statement.
- Code: `backend/secure_exchange/crypto_service.py` (module docstring = the 30-second version).
- Standards proof: `scripts/openssl_interop.sh` (stock OpenSSL, no homebrew crypto).

## Clause 4 — Secure architecture: block diagram + workflow

*Checking:* a diagram you can walk through, plus numbered flows.
*Evidence:*
- `docs/ARCHITECTURE.md` — context diagram, component catalogue, byte-level envelope
  anatomy, six numbered sequences (register, send, open, verify-only, rotate, attacker),
  audit-chain construction, RBAC matrix, deployment + failure modes.
- Live: Security page block diagram; README §3 sequence diagram.
- Workflow in one line: canonicalise → hash → fresh DEK+IV → AES-GCM → OAEP-wrap →
  PSS-sign → store ciphertext only → recipient unwraps → triple-verify → read.

## Clause 5 — Implementation with appropriate tools/languages

*Checking:* running code in suitable stacks, tests, not just diagrams.
*Evidence:*
- Backend: Django 5 + DRF + SimpleJWT + `cryptography` (`backend/`, `requirements.txt`);
  frontend: Angular 17 + TypeScript (`frontend/`, standalone components, guards, interceptors).
- `python manage.py test` — 5/5 green (roundtrip, bit-flip kill, forgery reject,
  wrong-key fail, CA verify) in `secure_exchange/tests/test_crypto.py`.
- `scripts/attacker_demo.py` — offline 5/5 transcript, no server needed.
- `ng build --configuration production` — clean bundle; Sora variable font bundled locally.
- Browser E2E 11/11 (login→send→open→4 attacks→audit→rotation→RBAC→mobile→Lighthouse),
  zero console errors.

## Clause 6 — Demonstration

*Checking:* a confident live run that shows mechanisms, attacks caught, and honesty
about limits.
*Evidence:*
- `docs/DEMO_SCRIPT.md` — minute-by-minute narration with recoveries + 11-question viva bank.
- The 3-click path (README §2): send as Asha → open as Rohan (4 badges) → Attacker Lab.
- Honesty assets: residual risks (`THREAT_MODEL.md` §6), prod roadmap (README §7),
  forensics blocks that would expose a failure instead of hiding it.

## Cross-cutting strengths to mention if asked "what makes this excellent"

Dual enc/sign keypairs · Hospital-CA PKI with fingerprints · rotation with lossless
history · revocation enforced at send · AAD context binding · per-recipient nonce
cache · hash-chained audit with one-click verify · RBAC with logged denials ·
throttled auth + short JWTs · single-algorithm-boundary codebase · OpenSSL interop ·
offline attack transcript · production hardening checklist behind `DEBUG=0`.
