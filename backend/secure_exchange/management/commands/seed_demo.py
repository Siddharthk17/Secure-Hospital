"""Seed demo users, patients and sealed sample reports. Run: python manage.py seed_demo"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from secure_exchange.models import Patient, Profile
from secure_exchange import crypto_service as C
from secure_exchange.audit import log_event
from secure_exchange.views import _issue_keys_for

USERS = [
    ("admin", "Admin@123", "admin", "Administration"),
    ("dr_asha", "Cardio@123", "doctor", "Cardiology"),
    ("dr_rohan", "Radio@123", "doctor", "Radiology"),
    ("lab_meera", "Lab@1234", "lab", "Pathology"),
    ("pharma_kabir", "Pharma@123", "pharmacist", "Pharmacy"),
]

PATIENTS = [
    ("MRN-1001", "Aarav Sharma", "1988-04-12", "B+", "Penicillin"),
    ("MRN-1002", "Diya Patil", "1995-09-30", "O-", "None"),
    ("MRN-1003", "Kabir Khan", "1972-01-05", "AB+", "Sulfa drugs"),
]

class Command(BaseCommand):
    help = "Seed demo hospital data"

    def handle(self, *args, **kw):
        for username, pwd, role, dept in USERS:
            u, created = User.objects.get_or_create(username=username)
            u.set_password(pwd)
            u.is_staff = (role == "admin")
            u.is_superuser = (role == "admin")
            u.save()
            if created or not hasattr(u, "profile"):
                Profile.objects.filter(user=u).delete()
                _issue_keys_for(u, role, dept)
                self.stdout.write(f"user {username} ({role}/{dept}) + dual RSA keypairs + CA cert")
        for mrn, name, dob, bg, alg in PATIENTS:
            Patient.objects.get_or_create(mrn=mrn, defaults={
                "full_name": name, "dob": dob, "blood_group": bg, "allergies": alg,
                "created_by": User.objects.get(username="admin")})
        log_event("system", "SEED", {"users": len(USERS), "patients": len(PATIENTS)})
        self.stdout.write(self.style.SUCCESS("Seed complete. Login e.g. dr_asha / Cardio@123"))
