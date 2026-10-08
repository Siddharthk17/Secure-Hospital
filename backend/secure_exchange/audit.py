"""Append-only hash-chained audit log."""
import hashlib
import json
from .models import AuditLog

GENESIS = "0" * 64

def _hash(seq, actor, action, details, prev_hash, created_at_iso) -> str:
    h = hashlib.sha256()
    h.update(f"{seq}|{actor}|{action}|{details}|{prev_hash}|{created_at_iso}".encode())
    return h.hexdigest()

def log_event(actor: str, action: str, details: dict | None = None):
    details_s = json.dumps(details or {}, sort_keys=True, default=str)
    last = AuditLog.objects.order_by("-seq").first()
    prev = last.entry_hash if last else GENESIS
    entry = AuditLog(actor=actor, action=action, details=details_s, prev_hash=prev, entry_hash="tmp")
    entry.save()  # assigns seq + created_at
    entry.entry_hash = _hash(entry.seq, actor, action, details_s, prev, entry.created_at.isoformat())
    entry.save(update_fields=["entry_hash"])
    return entry

def verify_chain() -> dict:
    prev = GENESIS
    checked = 0
    for e in AuditLog.objects.order_by("seq"):
        expect = _hash(e.seq, e.actor, e.action, e.details, e.prev_hash, e.created_at.isoformat())
        if e.prev_hash != prev or e.entry_hash != expect:
            return {"ok": False, "checked": checked, "broken_at_seq": e.seq}
        prev = e.entry_hash
        checked += 1
    return {"ok": True, "checked": checked, "head": prev}
