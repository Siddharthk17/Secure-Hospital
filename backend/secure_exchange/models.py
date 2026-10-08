"""Database models. Plaintext report bodies are NEVER persisted."""
import uuid
from django.db import models
from django.contrib.auth.models import User

ROLE_CHOICES = [("admin", "Administrator"), ("doctor", "Doctor"),
                ("lab", "Lab Technician"), ("pharmacist", "Pharmacist")]


class Profile(models.Model):
    """One row per user: role, department, dual keypairs, CA certificate."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="doctor")
    department = models.CharField(max_length=80, default="General")
    # Separate keypairs: encryption vs signing (compromise isolation).
    enc_public_pem = models.TextField()
    enc_private_pem = models.TextField()   # demo: server-custodied; prod: HSM / client-side E2E
    sig_public_pem = models.TextField()
    sig_private_pem = models.TextField()
    key_fingerprint = models.CharField(max_length=64)
    ca_certificate = models.TextField(blank=True)
    revoked = models.BooleanField(default=False)
    key_version = models.IntegerField(default=1)
    # Retired encryption private keys (JSON list of PEM strings). Rotation appends
    # here so ciphertext sealed to older versions stays openable (tried in order).
    created_at = models.DateTimeField(auto_now_add=True)
    old_enc_keys = models.TextField(default="[]")

    def __str__(self):
        return f"{self.user.username} ({self.role}/{self.department})"


class Patient(models.Model):
    mrn = models.CharField(max_length=32, unique=True)  # medical record number
    full_name = models.CharField(max_length=120)
    dob = models.DateField(null=True, blank=True)
    blood_group = models.CharField(max_length=8, blank=True)
    allergies = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.mrn} — {self.full_name}"


class Report(models.Model):
    """A sealed envelope row. Only ciphertext + wrapped DEK + hash + signature."""
    STATUS = [("SEALED", "Sealed"), ("DELIVERED", "Delivered"),
              ("OPENED", "Opened & verified"), ("TAMPER_ALERT", "Tamper detected")]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name="reports")
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_reports")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="inbox_reports")
    subject = models.CharField(max_length=200)
    # --- sealed envelope ---
    ciphertext_b64 = models.TextField()
    wrapped_dek_b64 = models.TextField()
    iv_b64 = models.CharField(max_length=64)
    digest_hex = models.CharField(max_length=64)      # SHA-256(canonical plaintext)
    signature_b64 = models.TextField()                # RSA-PSS(sender, digest)
    # --- replay / context binding (also used as AES-GCM AAD) ---
    nonce_hex = models.CharField(max_length=64)
    msg_id = models.CharField(max_length=64, unique=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS, default="SEALED")
    sender_key_version = models.IntegerField(default=1)
    recipient_key_version = models.IntegerField(default=1)

    class Meta:
        ordering = ["-sent_at"]

    def aad(self) -> bytes:
        # Stable context binding: only persisted-verbatim fields (usernames, msg_id,
        # nonce). The timestamp is bound inside the signed canonical plaintext instead,
        # avoiding datetime-format fragility between seal time and stored sent_at.
        return f"{self.sender.username}|{self.recipient.username}|{self.msg_id}|{self.nonce_hex}".encode()


class UsedNonce(models.Model):
    """Replay cache: each (recipient, nonce) may be consumed once."""
    recipient = models.ForeignKey(User, on_delete=models.CASCADE)
    nonce_hex = models.CharField(max_length=64)
    seen_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["recipient", "nonce_hex"], name="unique_nonce_per_recipient")]


class AuditLog(models.Model):
    """Append-only SHA-256 hash-chained log. Any edit breaks the chain."""
    seq = models.BigAutoField(primary_key=True)
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=80)
    details = models.TextField(default="{}")
    prev_hash = models.CharField(max_length=64)
    entry_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["seq"]
