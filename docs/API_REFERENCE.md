# API Reference — every endpoint, method, auth, body, and response

Base URL (dev): `http://127.0.0.1:8000`. Frontend proxy maps `/api/*` here.
Auth (unless marked open): `Authorization: Bearer <access-jwt>`.
Error shape: `{"detail": "…"}` with HTTP 400 / 401 / 403 / 404 / 409 as below.

---

## Authentication & identity

### `POST /api/auth/login/` — open, throttled (anon 30/min)
Request: `{"username": "dr_asha", "password": "Cardio@123"}`
→ `200 {"refresh": "…", "access": "…"}` (access 15 min, refresh 7 days, rotating).
Wrong credentials → `401 {"detail": "No active account found…"}`.

### `POST /api/auth/refresh/` — open
Request: `{"refresh": "…"}` → `200 {"access": "…", "refresh": "…"}` (old refresh blacklisted).

### `POST /api/auth/register/` — JWT (demo: any authenticated user; prod: admin-only)
Request: `{"username": "…", "password": "8+ chars", "role": "doctor|lab|pharmacist|admin", "department": "…"}`
→ `201 {username, role, department, key_fingerprint, enc_public_pem, sig_public_pem, ca_certificate, …}`.
Side effects: dual RSA keypairs generated, CA certificate issued, `USER_REGISTER` audited.
Duplicate username → `400`.

### `GET /api/me/` — JWT
→ your profile: role, department, fingerprint, both public keys, CA cert, key version.

### `GET /api/users/` — JWT
→ directory of non-revoked staff (username, role, dept, fingerprint, key version).

### `GET /api/users/<username>/pubkeys/` — JWT
→ `{enc_public_pem, sig_public_pem, fingerprint, ca_certificate, revoked, key_version}`.
Unknown user → `404`.

### `POST /api/keys/rotate/` — JWT, body `{}`
→ `200 {"detail": "rotated", "key_version": N, "fingerprint": "SHA256:…"}`.
Archives the old encryption key so history still decrypts; re-issues CA cert; audits `KEY_ROTATE`.

---

## Patients

### `GET /api/patients/` — JWT → `[{mrn, full_name, dob, blood_group, allergies, created_at}]`
### `POST /api/patients/` — JWT
Request: `{"mrn": "MRN-1004", "full_name": "…", "dob": "YYYY-MM-DD", "blood_group": "O+", "allergies": "…"}`
→ `201` patient; audits `PATIENT_CREATE`. Duplicate MRN → `400`.

---

## Reports (the core)

### `POST /api/reports/send/` — JWT
Request: `{"patient_mrn": "MRN-1001", "recipient_username": "dr_rohan", "subject": "…", "body": "…≤20000 chars"}`
→ `201 {id, patient_mrn, …, status: "DELIVERED", digest_hex, note}`.
Failures: unknown MRN/recipient `404` · revoked recipient `409` · self-send `400`.
Audits `REPORT_SEAL_SEND`. Plaintext never stored.

### `GET /api/reports/inbox/` · `GET /api/reports/sent/` — JWT
→ own reports, newest first: `id, patient_mrn, patient_name, sender, recipient, subject,
status, sent_at, digest_hex, nonce_hex, msg_id, key versions`.

### `GET /api/reports/search/?q=cardio` — JWT
→ own reports filtered by subject/MRN/patient name.

### `GET /api/reports/<uuid>/open/` — JWT, **recipient only**
- Recipient + intact → `200 {verification: {gcm_tag_ok, hash_ok, signature_ok, aad_bound,
  replay_checked, timestamp_skew_ok, sender_fingerprint, ca_cert_valid}, status: "OPENED",
  report: {canonical plaintext…}, digest_hex}`. Tries current then retired keys; records
  nonce; audits `REPORT_OPEN_VERIFY_OK`.
- Recipient + tampered → `409 {verification, status: "TAMPER_ALERT", error, forensics}`;
  audits `REPORT_TAMPER_DETECTED`.
- Sender (not recipient) → `200 {detail, meta}` (metadata only) — decryption stays recipient-only.
- Anyone else → `403` + audits `REPORT_ACCESS_DENIED`. Unknown id → `404`.

### `GET /api/reports/<uuid>/verify/` — JWT, sender/recipient/admin
→ `{report_id, digest_hex, signature_ok, sender, sender_fingerprint, status, note}` —
authorship proof **without decrypting** (for auditors and senders). Others → `403`.

---

## Attacker Lab (controlled MITM)

### `POST /api/lab/attacker/<uuid>/` — JWT party to the report
Request: `{"mode": "flip_bit|truncate|forge_sig|hash_swap|replay_copy|wrong_recipient"}`
→ `200 {mode, caught: true, by: […], verdict, lesson, forensics?}`.
Runs the real verification pipeline over a tampered **clone**; storage untouched.
Unknown mode → `400`; outsider → `403`.

---

## Audit & system

### `GET /api/audit/` — JWT → last 200 entries (seq, actor, action, details, prev/entry hashes, time).
### `GET /api/audit/verify/` — JWT → `{"ok": true, "checked": N, "head": "…"}` or
`{"ok": false, "checked": N, "broken_at_seq": S}` — recomputes the full chain.
### `GET /api/system/security-overview/` — **open**
→ `{policy, cia_plus, threats_mitigated}` — the same object that drives the
frontend Security page, so the UI can never drift from backend reality.

---

## Worked example (curl — send as Asha, open as Rohan)

```bash
A=$(curl -s -X POST 127.0.0.1:8000/api/auth/login/ -H 'Content-Type: application/json' \
  -d '{"username":"dr_asha","password":"Cardio@123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access'])")
R=$(curl -s -X POST 127.0.0.1:8000/api/auth/login/ -H 'Content-Type: application/json' \
  -d '{"username":"dr_rohan","password":"Radio@123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access'])")
ID=$(curl -s -X POST 127.0.0.1:8000/api/reports/send/ -H "Authorization: Bearer $A" \
  -H 'Content-Type: application/json' \
  -d '{"patient_mrn":"MRN-1001","recipient_username":"dr_rohan","subject":"ECG","body":"Sinus rhythm."}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
curl -s 127.0.0.1:8000/api/reports/$ID/open/ -H "Authorization: Bearer $R" \
  | python3 -m json.tool | head -n 20
```
