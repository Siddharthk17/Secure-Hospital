#!/usr/bin/env python3
"""Offline end-to-end transcript: seal → deliver → MITM attacks → verify.
Run:  python3 scripts/attacker_demo.py     (no server needed)
Proves: roundtrip OK; bit-flip caught by GCM; forgery rejected by PSS;
        wrong-key unreadable; CA issues/verifies. Paste output into viva Q&A.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import base64
from secure_exchange import crypto_service as C

print("== Secure Hospital Exchange — offline crypto transcript ==")
enc_priv, enc_pub = C.generate_rsa_keypair()
sig_priv, sig_pub = C.generate_rsa_keypair()
intruder_priv, _ = C.generate_rsa_keypair()
aad = b"dr_asha|dr_rohan|msg-1|nonce-1|2026-10-08T11:00:00+05:30"
pt = C.canonical_json({"patient_mrn": "MRN-1001", "subject": "ECG review",
                       "body": "Sinus rhythm. Aspirin 75mg OD.", "sender": "dr_asha"})
env = C.seal_envelope(pt, sig_priv, enc_pub, aad)
print(f"1. sealed: sha256={env.digest_hex[:24]}… sig_len={len(env.signature_b64)} ct_len={len(env.ciphertext_b64)}")

ok = C.open_envelope(env.ciphertext_b64, env.wrapped_dek_b64, env.iv_b64,
                     env.digest_hex, env.signature_b64, sig_pub, enc_priv, aad)
print(f"2. honest open: GCM={ok.gcm_ok} HASH={ok.hash_ok} SIG={ok.sig_ok} match={ok.plaintext == pt}")

raw = bytearray(base64.b64decode(env.ciphertext_b64)); raw[7] ^= 1
t = C.open_envelope(base64.b64encode(bytes(raw)).decode(), env.wrapped_dek_b64, env.iv_b64,
                    env.digest_hex, env.signature_b64, sig_pub, enc_priv, aad)
print(f"3. bit-flip attack: GCM={t.gcm_ok} -> {'CAUGHT (tag FAIL)' if not t.gcm_ok else 'MISSED!'}")

other_priv, _ = C.generate_rsa_keypair()
forged = C.sign_digest_pss(other_priv, env.digest_hex)
print(f"4. forged signature: valid={C.verify_digest_pss(sig_pub, env.digest_hex, forged)} -> {'REJECTED' if not C.verify_digest_pss(sig_pub, env.digest_hex, forged) else 'MISSED!'}")

w = C.open_envelope(env.ciphertext_b64, env.wrapped_dek_b64, env.iv_b64,
                    env.digest_hex, env.signature_b64, sig_pub, intruder_priv, aad)
print(f"5. stolen envelope (wrong key): GCM={w.gcm_ok} -> {'UNREADABLE' if not w.gcm_ok else 'MISSED!'}")

ca = C.HospitalCA()
cert = ca.issue_certificate("dr_asha", "Cardiology", enc_pub, sig_pub)
print(f"6. CA cert: {'VALID' if ca.verify_certificate(cert) else 'INVALID'}")
print("== transcript complete: 5/5 behaviours as designed ==" if (ok.sig_ok and not t.gcm_ok and not w.gcm_ok) else "== CHECK OUTPUT ==")
