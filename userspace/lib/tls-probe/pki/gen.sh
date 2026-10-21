#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Regenerates the three DER files the probe's loopback handshake trusts and
# serves: ca.der (a test CA, the only trust anchor), leaf.der (its certificate for
# probe.azos, serverAuth) and leaf_key.der (the leaf's ECDSA P-256 key, PKCS#8).
# TEST KEYS: they exist to be committed and protect nothing. Nothing outside the
# probe's own in-memory handshake and the host test trusts this CA.
#
#     sh userspace/lib/tls-probe/pki/gen.sh      # needs openssl; rewrites the three files
#
# Both certificates are valid for 100 years from the day they are made, and the
# probe checks them at the fixed instant `tls::FIXED_UNIX_SECS`, so the result does
# not depend on the device's clock.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/ca.key"
openssl req -x509 -new -key "$tmp/ca.key" -sha256 -days 36500 -subj "/CN=AzOS tls-probe test CA" \
  -config /dev/stdin -out "$tmp/ca.pem" <<'CNF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = AzOS tls-probe test CA
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/leaf.key"
openssl req -new -key "$tmp/leaf.key" -subj "/CN=probe.azos" -out "$tmp/leaf.csr"
cat > "$tmp/leaf.ext" <<'CNF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:probe.azos
CNF
openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca.key" -CAcreateserial -sha256 -days 36500 \
  -extfile "$tmp/leaf.ext" -out "$tmp/leaf.pem"
openssl x509 -in "$tmp/ca.pem" -outform DER -out ca.der
openssl x509 -in "$tmp/leaf.pem" -outform DER -out leaf.der
openssl pkcs8 -topk8 -nocrypt -in "$tmp/leaf.key" -outform DER -out leaf_key.der
