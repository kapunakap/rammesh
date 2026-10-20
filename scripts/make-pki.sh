#!/bin/sh
set -eu
umask 077
dest=${1:-pki}
if [ -e "$dest" ]; then echo "Refusing to overwrite existing PKI: $dest" >&2; exit 1; fi
mkdir -m 700 "$dest"
cat > "$dest/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ca
prompt = no
[dn]
CN = RAMMesh private CA
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
openssl ecparam -name prime256v1 -genkey -noout -out "$dest/ca.key"
openssl req -new -x509 -sha256 -days 365 -key "$dest/ca.key" -config "$dest/ca.cnf" -out "$dest/ca.crt"
for role in donor borrower; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$dest/$role.key"
    openssl req -new -sha256 -key "$dest/$role.key" -subj "/CN=rammesh-$role" -out "$dest/$role.csr"
    if [ "$role" = donor ]; then usage=serverAuth; else usage=clientAuth; fi
    cat > "$dest/$role.ext" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = $usage
subjectAltName = DNS:rammesh-$role,DNS:localhost,IP:127.0.0.1,IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
    serial=$(openssl rand -hex 16)
    openssl x509 -req -sha256 -days 30 -in "$dest/$role.csr" -CA "$dest/ca.crt" -CAkey "$dest/ca.key" \
        -set_serial "0x$serial" -extfile "$dest/$role.ext" -out "$dest/$role.crt"
    rm "$dest/$role.csr" "$dest/$role.ext"
done
rm "$dest/ca.cnf"
echo "Created owner-only PKI in $dest (leaf certificates valid for 30 days)."
echo "The donor needs ca.crt, donor.crt and donor.key. A future borrower needs ca.crt, borrower.crt and borrower.key."
echo "Keep ca.key offline; never transfer donor.key to a borrower."
