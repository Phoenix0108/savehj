#!/bin/bash

# Directory for certificates
CERT_DIR="./certs"
mkdir -p $CERT_DIR

# Passphrase for encrypting the private keys (can be modified or prompted for)
PASSPHRASE="mysecurepassword"

# Step 1: Generate the Root Certificate Authority (CA)
echo "Generating Root Certificate Authority (CA)..."
openssl genpkey -algorithm RSA -out $CERT_DIR/ca.key -aes256 -passout pass:$PASSPHRASE
openssl req -key $CERT_DIR/ca.key -new -x509 -out $CERT_DIR/ca.crt -days 3650 -passin pass:$PASSPHRASE -subj "/C=US/ST=State/L=City/O=Company/OU=RootCA/CN=Root CA"

# Step 2: Generate the Server Certificate and Key
echo "Generating Server Certificate and Key..."
openssl genpkey -algorithm RSA -out $CERT_DIR/server.key -aes256 -passout pass:$PASSPHRASE
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr -passin pass:$PASSPHRASE -subj "/C=US/ST=State/L=City/O=Company/OU=Server/CN=localhost"
openssl x509 -req -in $CERT_DIR/server.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -CAcreateserial -out $CERT_DIR/server.crt -days 365 -passin pass:$PASSPHRASE

# Step 3: Generate the Client Certificate and Key
echo "Generating Client Certificate and Key..."
openssl genpkey -algorithm RSA -out $CERT_DIR/client.key -aes256 -passout pass:$PASSPHRASE
openssl req -new -key $CERT_DIR/client.key -out $CERT_DIR/client.csr -passin pass:$PASSPHRASE -subj "/C=US/ST=State/L=City/O=Company/OU=Client/CN=Client"
openssl x509 -req -in $CERT_DIR/client.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -CAcreateserial -out $CERT_DIR/client.crt -days 365 -passin pass:$PASSPHRASE

# Step 4: Change permissions for security
echo "Changing file permissions for security..."
chmod 600 $CERT_DIR/*.key
chmod 644 $CERT_DIR/*.crt
chmod 644 $CERT_DIR/*.csr

# Output success message
echo "Certificates generated successfully in $CERT_DIR"


