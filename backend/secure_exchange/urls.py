from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (LoginView, register, me, users, user_pubkeys, rotate_keys,
                    patients, send_report, inbox, sent, open_report, verify_only,
                    attacker_lab, audit_list, audit_verify, security_overview, search_reports)

urlpatterns = [
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="refresh"),
    path("auth/register/", register),
    path("me/", me),
    path("users/", users),
    path("users/<str:username>/pubkeys/", user_pubkeys),
    path("keys/rotate/", rotate_keys),
    path("patients/", patients),
    path("reports/send/", send_report),
    path("reports/inbox/", inbox),
    path("reports/sent/", sent),
    path("reports/search/", search_reports),
    path("reports/<uuid:report_id>/open/", open_report),
    path("reports/<uuid:report_id>/verify/", verify_only),
    path("lab/attacker/<uuid:report_id>/", attacker_lab),
    path("audit/", audit_list),
    path("audit/verify/", audit_verify),
    path("system/security-overview/", security_overview),
]
