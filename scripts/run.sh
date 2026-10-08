#!/usr/bin/env bash
# One-shot launcher for evaluators.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/scripts/stop.sh" 2>/dev/null || true
cd "$ROOT/backend"
pip install -q -r requirements.txt
python manage.py migrate -v 0
python manage.py seed_demo
(python manage.py runserver 127.0.0.1:8000 >/tmp/hosp_backend.log 2>&1 &) 
cd "$ROOT/frontend"
[ -d node_modules ] || npm install
(npm start >/tmp/hosp_frontend.log 2>&1 &)
sleep 2
echo "Backend:  http://127.0.0.1:8000/api/system/security-overview/"
echo "Frontend: http://localhost:4200   (login dr_asha / Cardio@123)"
