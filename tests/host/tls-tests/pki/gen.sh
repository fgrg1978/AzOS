#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The server identities the pinned client is tested against: self-signed
# ECDSA P-256 leaves for probe.azos, because a pin is the only trust a client has
# and no CA is involved.
#
#   good.der     valid from 2026-01-01 for a hundred years
#   other.der    the same name, another key (a server that is not the pinned one)
#   expired.der  a third key, valid only on 2020-01-01 (an expired certificate)
#   *_key.der    PKCS#8 keys
#   rsa_key.der  a PKCS#8 RSA key, never presented to a client: tests/rsa.rs hands it to the server
#                configuration, which must refuse it (deny.toml ignores RUSTSEC-2023-0071 on that ground)
#
# TEST KEYS: made to be committed and protect nothing.
#
#     OPENSSL=/opt/homebrew/bin/openssl sh tests/host/tls-tests/pki/gen.sh   # OpenSSL >= 3.4 (-not_before)
set -eu
cd "$(dirname "$0")"
OPENSSL=${OPENSSL:-openssl}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
leaf() {
  name=$1; nb=$2; na=$3
  "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$tmp/$name.key"
  "$OPENSSL" req -x509 -new -key "$tmp/$name.key" -sha256 -subj "/CN=probe.azos" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" -addext "subjectAltName=DNS:probe.azos" \
    -not_before "$nb" -not_after "$na" -out "$tmp/$name.pem"
  "$OPENSSL" x509 -in "$tmp/$name.pem" -outform DER -out "$name.der"
  "$OPENSSL" pkcs8 -topk8 -nocrypt -in "$tmp/$name.key" -outform DER -out "${name}_key.der"
}
leaf good    20260101000000Z 21251231000000Z
leaf other   20260101000000Z 21251231000000Z
leaf expired 20200101000000Z 20200101235959Z
for n in good other expired; do
  printf '%s pin %s\n' "$n" "$("$OPENSSL" x509 -in "$n.der" -inform DER -pubkey -noout | "$OPENSSL" pkey -pubin -outform DER | "$OPENSSL" dgst -sha256 | sed 's/^.*= //')"
done
# Not part of `leaf`: running this script replaces the three leaves above and so their pins in tests/common/mod.rs.
# To make only the RSA key again:
#   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | openssl pkcs8 -topk8 -nocrypt -outform DER -out rsa_key.der
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | "$OPENSSL" pkcs8 -topk8 -nocrypt -outform DER -out rsa_key.der
