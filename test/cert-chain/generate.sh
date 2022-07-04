#!/bin/bash
set -eu

# This script generates three certificates:
# 1. A self-signed root certificate authority
# 2. An intermediate certificate authority
# 3. A leaf certificate, intended for signing/verifying XML signatures

# Generate private key and self-signed certificate for certificate authority
openssl genrsa -out root.key 2048
openssl req -new -key root.key -out root.csr -subj "/CN=root.example.com"
openssl x509 -req -in root.csr -out root.crt -signkey root.key -CAcreateserial -days 3650 -sha256 -extfile config.ext -extensions root

# Generate private key for intermediate certificate
openssl genrsa -out intermediate.key 2048

# Generate intermediate certificate request
openssl req -new -key intermediate.key -out intermediate.csr -subj "/CN=intermediate.example.com"

# Generate intermediate certificate based on request
openssl x509 -req -in intermediate.csr -out intermediate.crt -CA root.crt -CAkey root.key -CAcreateserial -days 3650 -sha256 -extfile config.ext -extensions intermediate

# Generate private key for leaf certificate
openssl genrsa -out leaf.key 2048

# Generate leaf certificate request
openssl req -new -key leaf.key -out leaf.csr -subj "/CN=leaf.example.com"

# Generate leaf certificate based on request
openssl x509 -req -in leaf.csr -out leaf.crt -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -days 3650 -sha256 -extfile config.ext -extensions leaf
