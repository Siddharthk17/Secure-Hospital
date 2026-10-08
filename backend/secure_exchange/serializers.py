from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Patient, Report, Profile, AuditLog

class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    class Meta:
        model = Profile
        fields = ["username", "role", "department", "key_fingerprint",
                  "enc_public_pem", "sig_public_pem", "ca_certificate",
                  "revoked", "key_version"]

class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True, min_length=8)
    role = serializers.ChoiceField(choices=["admin", "doctor", "lab", "pharmacist"], default="doctor")
    department = serializers.CharField(max_length=80, default="General")

class PatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = ["mrn", "full_name", "dob", "blood_group", "allergies", "created_at"]
        read_only_fields = ["created_at"]

class SendReportSerializer(serializers.Serializer):
    patient_mrn = serializers.CharField()
    recipient_username = serializers.CharField()
    subject = serializers.CharField(max_length=200)
    body = serializers.CharField(max_length=20000)

class ReportListSerializer(serializers.ModelSerializer):
    patient_mrn = serializers.CharField(source="patient.mrn")
    patient_name = serializers.CharField(source="patient.full_name")
    sender = serializers.CharField(source="sender.username")
    recipient = serializers.CharField(source="recipient.username")
    class Meta:
        model = Report
        fields = ["id", "patient_mrn", "patient_name", "sender", "recipient",
                  "subject", "status", "sent_at", "digest_hex",
                  "nonce_hex", "msg_id", "sender_key_version", "recipient_key_version"]

class AuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = ["seq", "actor", "action", "details", "prev_hash", "entry_hash", "created_at"]
