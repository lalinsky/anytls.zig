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

# A self-signed leaf that expired in 2001. OpenSSL 3.0 cannot backdate, so
# this uses Python's cryptography package.
ec expired.key
python3 - <<'PY'
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
key = serialization.load_pem_private_key(open("expired.key", "rb").read(), None)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired")])
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(1)
    .not_valid_before(datetime.datetime(2000, 1, 1))
    .not_valid_after(datetime.datetime(2001, 1, 1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
    .sign(key, hashes.SHA256())
)
open("expired.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
PY

rm -f ca.srl ca.key
