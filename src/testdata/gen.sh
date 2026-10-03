#!/bin/sh
# Regenerates the test PKI. Run from this directory.
set -eu
days=36500
ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

ca() { # name subject
    ec "$1.key"
    openssl req -x509 -new -key "$1.key" -out "$1.pem" -days $days -subj "/CN=$2" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
}

leaf() { # name subject san eku
    ec "$1.key"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
    printf 'subjectAltName=%s\nextendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n' "$3" "$4" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days $days \
        -extfile "$1.ext" -out "$1.pem"
    rm "$1.csr" "$1.ext"
}

ca ca "anytls test CA"
ca other-ca "anytls other CA"
rm other-ca.key
leaf server localhost "DNS:localhost,IP:127.0.0.1" serverAuth
leaf client "anytls test client" "DNS:client" clientAuth
ec other.key
rm -f ca.srl ca.key
