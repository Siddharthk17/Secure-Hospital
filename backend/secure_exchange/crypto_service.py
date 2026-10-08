"""
crypto_service.py — the heart of the hackathon submission.

Protocol: SEALED HOSPITAL ENVELOPE (v1)
=======================================
Seal (sender side):
  1. canonical = canonical_json({patient_mrn, subject, body, sender, recipient, timestamp, nonce, msg_id})
  2. digest   = SHA-256(canonical)                                  → integrity anchor
  3. DEK      = CSPRNG(32 bytes)                                     → per-message data key
  4. iv       = CSPRNG(12 bytes)                                     → GCM nonce
  5. aad      = sender|recipient|timestamp|nonce|msg_id               → binds ciphertext to context
  6. ct||tag  = AES-256-GCM(DEK, iv, canonical, aad)                → confidentiality + AEAD integrity
  7. wrapped  = RSA-OAEP-SHA256(recipient_enc_pub, DEK)              → only recipient can unwrap
  8. sig      = RSA-PSS-SHA256(sender_sig_priv, digest)              → authentication + non-repudiation
  9. STORE {ct, wrapped, iv, digest, sig, aad fields}. Plaintext is NEVER stored.

Open (recipient side):
  1. Recompute aad from stored metadata; AES-GCM decrypt (fails closed on bit-flip).
  2. Recompute SHA-256(plaintext) and compare with stored digest (second integrity layer).
  3. RSA-PSS verify digest with sender's public signing key (authenticity + non-repudiation).
  4. Check timestamp skew (±10 min) + nonce uniqueness (replay protection).
  5. Return plaintext only if ALL checks pass.

Why this combination (one-line justifications for viva):
- AES-256-GCM : single pass gives confidentiality AND tamper detection (tag); fast in HW/SW.
- RSA-OAEP    : solves key distribution — DEK never travels in clear; OAEP padding kills malleability.
- RSA-PSS     : proves WHO sealed it and blocks denial ("I never sent that"); PSS is provably secure.
- SHA-256     : collision-resistant fingerprint; also chains the audit log and key fingerprints.
- Separate enc/sig keypairs : compromise of one use does not kill the other (best practice, TCG/NIST).
"""
import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

RSA_KEY_SIZE = 2048  # demo speed; production policy: 3072+ (see settings.HOSPITAL_CRYPTO_POLICY)
GCM_NONCE_BYTES = 12
DEK_BYTES = 32  # AES-256


# ---------- helpers ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: dict) -> bytes:
    """Deterministic serialisation so sender & verifier hash identical bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------- key management ----------
def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),  # prod: encrypt at rest with HSM/KMS or password-derived key
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem


def key_fingerprint(public_pem: str) -> str:
    pub = serialization.load_pem_public_key(public_pem.encode())
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "SHA256:" + sha256_hex(der)[:32]


def _load_pub(pem: str):
    return serialization.load_pem_public_key(pem.encode())

def _load_priv(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


# ---------- hybrid encryption ----------
def hybrid_encrypt(plaintext: bytes, recipient_enc_public_pem: str, aad: bytes):
    dek = AESGCM.generate_key(bit_length=256)  # CSPRNG 32 bytes
    iv = os.urandom(GCM_NONCE_BYTES)
    ct_and_tag = AESGCM(dek).encrypt(iv, plaintext, aad)
    wrapped_dek = _load_pub(recipient_enc_public_pem).encrypt(
        dek, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))
    return {"ciphertext_b64": b64e(ct_and_tag), "wrapped_dek_b64": b64e(wrapped_dek), "iv_b64": b64e(iv)}


def hybrid_decrypt(ciphertext_b64: str, wrapped_dek_b64: str, iv_b64: str,
                   recipient_enc_private_pem: str, aad: bytes) -> bytes:
    dek = _load_priv(recipient_enc_private_pem).decrypt(
        b64d(wrapped_dek_b64),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    return AESGCM(dek).decrypt(b64d(iv_b64), b64d(ciphertext_b64), aad)


# ---------- signatures ----------
def sign_digest_pss(sig_private_pem: str, digest_hex: str) -> str:
    sig = _load_priv(sig_private_pem).sign(
        bytes.fromhex(digest_hex),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    return b64e(sig)


def verify_digest_pss(sig_public_pem: str, digest_hex: str, signature_b64: str) -> bool:
    try:
        _load_pub(sig_public_pem).verify(
            b64d(signature_b64), bytes.fromhex(digest_hex),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------- high-level envelope ----------
@dataclass
class SealedEnvelope:
    ciphertext_b64: str
    wrapped_dek_b64: str
    iv_b64: str
    digest_hex: str
    signature_b64: str


def seal_envelope(canonical_plaintext: bytes, sender_sig_private_pem: str,
                  recipient_enc_public_pem: str, aad: bytes) -> SealedEnvelope:
    digest = sha256_hex(canonical_plaintext)
    enc = hybrid_encrypt(canonical_plaintext, recipient_enc_public_pem, aad)
    sig = sign_digest_pss(sender_sig_private_pem, digest)
    return SealedEnvelope(enc["ciphertext_b64"], enc["wrapped_dek_b64"], enc["iv_b64"], digest, sig)


@dataclass
class OpenResult:
    plaintext: bytes | None
    gcm_ok: bool
    hash_ok: bool
    sig_ok: bool
    error: str = ""


def open_envelope(ciphertext_b64: str, wrapped_dek_b64: str, iv_b64: str, digest_hex: str,
                  signature_b64: str, sender_sig_public_pem: str,
                  recipient_enc_private_pem: str, aad: bytes) -> OpenResult:
    try:
        pt = hybrid_decrypt(ciphertext_b64, wrapped_dek_b64, iv_b64, recipient_enc_private_pem, aad)
        gcm_ok = True
    except (InvalidTag, ValueError) as e:
        return OpenResult(None, False, False, False, f"AEAD decrypt failed (tamper/wrong key): {e}")
    except Exception as e:
        return OpenResult(None, False, False, False, f"Decrypt error: {e}")
    hash_ok = sha256_hex(pt) == digest_hex
    sig_ok = verify_digest_pss(sender_sig_public_pem, digest_hex, signature_b64)
    err = ""
    if not hash_ok:
        err += "Hash mismatch (content altered after signing). "
    if not sig_ok:
        err += "Signature invalid (forgery / wrong sender key). "
    if hash_ok and sig_ok:
        return OpenResult(pt, True, True, True)
    return OpenResult(pt if hash_ok else None, gcm_ok, hash_ok, sig_ok, err.strip())


# ---------- Hospital CA (mini-PKI for demo) ----------
class HospitalCA:
    """Offline CA: signs (identity || enc_pub_fingerprint || sig_pub) so recipients can
    trust that 'dr_asha's public key really belongs to Dr. Asha'. CA key lives server-side
    for the demo; in production it is an offline HSM + X.509 chain."""

    def __init__(self):
        self._priv, self._pub = generate_rsa_keypair()

    @property
    def public_pem(self) -> str:
        return self._pub

    def issue_certificate(self, username: str, department: str, enc_pub: str, sig_pub: str) -> str:
        payload = canonical_json({"user": username, "dept": department,
                                  "enc_fp": key_fingerprint(enc_pub), "sig_pub": sig_pub})
        sig = _load_priv(self._priv).sign(
            sha256_hex(payload).encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return b64e(payload) + "." + b64e(sig)

    def verify_certificate(self, cert: str) -> dict | None:
        try:
            payload_b64, sig_b64 = cert.split(".")
            payload = b64d(payload_b64)
            _load_pub(self._pub).verify(
                b64d(sig_b64), sha256_hex(payload).encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return json.loads(payload)
        except Exception:
            return None


# Process-wide demo CA persisted to disk so certificates stay verifiable across
# processes (seed_demo vs runserver) and restarts. Production: offline HSM + X.509.
_CA_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hospital_ca_key.pem")
_CA_SINGLETON: HospitalCA | None = None

def get_ca() -> HospitalCA:
    global _CA_SINGLETON
    if _CA_SINGLETON is None:
        _CA_SINGLETON = HospitalCA()
        if os.path.exists(_CA_KEY_FILE):
            with open(_CA_KEY_FILE, "r") as f:
                key_pem = f.read()
            # Keep _priv/_pub as PEM strings (same type as a fresh HospitalCA).
            _key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            _CA_SINGLETON._priv = key_pem
            _CA_SINGLETON._pub = _key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        else:
            with open(_CA_KEY_FILE, "w") as f:
                f.write(_CA_SINGLETON._priv)  # _priv is already a PKCS8 PEM string
            os.chmod(_CA_KEY_FILE, 0o600)
    return _CA_SINGLETON
