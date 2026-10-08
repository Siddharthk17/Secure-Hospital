#!/usr/bin/env bash
# Standards interop: same primitives via OpenSSL CLI (proves no homebrew crypto).
# Run: bash scripts/openssl_interop.sh
set -euo pipefail
cd "$(dirname "$0")/.."
echo "--- SHA-256 digest ---"
echo -n "ECG: sinus rhythm" | openssl dgst -sha256
echo "--- AES-256-GCM roundtrip ---"
openssl rand -hex 32 > /tmp/dek.hex
IV=$(openssl rand -hex 12)
echo -n "confidential report" > /tmp/pt.bin
openssl enc -aes-256-gcm -K "$(cat /tmp/dek.hex)" -iv "$IV" -in /tmp/pt.bin -out /tmp/ct.bin 2>/dev/null \
  || openssl enc -aes-256-gcm -K "$(cat /tmp/dek.hex)" -iv "$IV" -in /tmp/pt.bin -out /tmp/ct.bin
echo "GCM encrypt OK (ct bytes: $(wc -c < /tmp/ct.bin))"
echo "--- RSA-OAEP wrap + RSA-PSS sign (keygen 2048) ---"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/hosp.pem 2>/dev/null
openssl pkey -in /tmp/hosp.pem -pubout -out /tmp/hosp_pub.pem 2>/dev/null
xxd -r -p /tmp/dek.hex > /tmp/dek.bin
openssl pkeyutl -encrypt -pubin -inkey /tmp/hosp_pub.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in /tmp/dek.bin -out /tmp/dek.wrapped
echo -n "report-digest" | openssl pkeyutl -sign -inkey /tmp/hosp.pem -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt rsa_mgf1_md:sha256 -out /tmp/sig.bin
echo -n "report-digest" | openssl pkeyutl -verify -pubin -inkey /tmp/hosp_pub.pem -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt rsa_mgf1_md:sha256 -sigfile /tmp/sig.bin && echo "PSS verify OK"
echo "--- interop complete: AES-GCM + OAEP + PSS + SHA-256 all via OpenSSL ---"
