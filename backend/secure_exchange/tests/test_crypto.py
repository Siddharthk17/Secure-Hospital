"""Crypto proof tests — run with `python manage.py test`. Doubles as viva evidence."""
import base64
from django.test import TestCase
from secure_exchange import crypto_service as C


class EnvelopeTests(TestCase):
    def setUp(self):
        self.enc_priv, self.enc_pub = C.generate_rsa_keypair()
        self.sig_priv, self.sig_pub = C.generate_rsa_keypair()
        self.aad = b"dr_asha|dr_rohan|msgid|nonce|ts"

    def test_roundtrip(self):
        pt = C.canonical_json({"mrn": "MRN-1001", "body": "ECG normal"})
        env = C.seal_envelope(pt, self.sig_priv, self.enc_pub, self.aad)
        res = C.open_envelope(env.ciphertext_b64, env.wrapped_dek_b64, env.iv_b64,
                              env.digest_hex, env.signature_b64,
                              self.sig_pub, self.enc_priv, self.aad)
        self.assertTrue(res.gcm_ok and res.hash_ok and res.sig_ok)
        self.assertEqual(res.plaintext, pt)

    def test_bitflip_detected(self):
        pt = b"critical dosage info"
        env = C.seal_envelope(pt, self.sig_priv, self.enc_pub, self.aad)
        raw = bytearray(base64.b64decode(env.ciphertext_b64))
        raw[5] ^= 1
        tampered = base64.b64encode(bytes(raw)).decode()
        res = C.open_envelope(tampered, env.wrapped_dek_b64, env.iv_b64,
                              env.digest_hex, env.signature_b64,
                              self.sig_pub, self.enc_priv, self.aad)
        self.assertFalse(res.gcm_ok)

    def test_forged_signature_rejected(self):
        pt = b"report"
        env = C.seal_envelope(pt, self.sig_priv, self.enc_pub, self.aad)
        other_priv, _ = C.generate_rsa_keypair()
        forged = C.sign_digest_pss(other_priv, env.digest_hex)
        self.assertFalse(C.verify_digest_pss(self.sig_pub, env.digest_hex, forged))

    def test_wrong_recipient_cannot_decrypt(self):
        pt = b"secret"
        env = C.seal_envelope(pt, self.sig_priv, self.enc_pub, self.aad)
        intruder_priv, _ = C.generate_rsa_keypair()
        res = C.open_envelope(env.ciphertext_b64, env.wrapped_dek_b64, env.iv_b64,
                              env.digest_hex, env.signature_b64,
                              self.sig_pub, intruder_priv, self.aad)
        self.assertFalse(res.gcm_ok)

    def test_ca_issues_and_verifies(self):
        ca = C.HospitalCA()
        cert = ca.issue_certificate("dr_asha", "Cardiology", self.enc_pub, self.sig_pub)
        self.assertIsNotNone(ca.verify_certificate(cert))
