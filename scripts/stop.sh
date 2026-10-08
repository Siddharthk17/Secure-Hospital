#!/usr/bin/env bash
pkill -f "manage.py runserver" 2>/dev/null || true
pkill -f "ng serve" 2>/dev/null || true
echo stopped
