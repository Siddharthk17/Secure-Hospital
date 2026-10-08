from django.contrib import admin
from .models import Profile, Patient, Report, AuditLog, UsedNonce

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "department", "key_fingerprint", "key_version", "revoked")
    list_filter = ("role", "revoked")

@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):
    list_display = ("mrn", "full_name", "blood_group", "created_at")
    search_fields = ("mrn", "full_name")

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("id", "patient", "sender", "recipient", "subject", "status", "sent_at")
    list_filter = ("status",)
    exclude = ("ciphertext_b64", "wrapped_dek_b64", "signature_b64")  # avoid dumping secrets on screen

@admin.register(AuditLog)
class AuditAdmin(admin.ModelAdmin):
    list_display = ("seq", "actor", "action", "created_at")
    readonly_fields = ("seq", "entry_hash", "prev_hash")

admin.site.register(UsedNonce)
