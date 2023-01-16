#!/usr/bin/env python
from functools import partial
from subprocess import call

import OpenSSL.crypto
from asn1crypto.x509 import TbsCertificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

run = partial(call, shell=True, executable="/bin/bash")
message = b"abc"
signatures = {}

pss_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
pkcs_padding = padding.PKCS1v15()

run("openssl req -x509 -nodes -subj '/CN=test' -days 1 -newkey rsa -keyout rsa-key.pem -out rsa-cert.pem")
with open("rsa-cert.pem", "rb") as fh:
    rsa_cert = fh.read()
with open("rsa-key.pem", "rb") as fh:
    rsa_key = serialization.load_pem_private_key(fh.read(), password=None)
signatures[rsa_cert] = rsa_key.sign(message, pkcs_padding, hashes.SHA512())

# Does not work on LibreSSL
run("openssl req -x509 -nodes -subj '/CN=test' -days 1 -newkey rsa-pss -keyout rsapss-key.pem -out rsapss-cert.pem")
with open("rsapss-cert.pem", "rb") as fh:
    rsapss_cert = fh.read()
with open("rsapss-key.pem", "rb") as fh:
    rsapss_key = serialization.load_pem_private_key(fh.read(), password=None)
signatures[rsapss_cert] = rsapss_key.sign(message, pss_padding, hashes.SHA512())

run(
    "openssl req -x509 -nodes -subj '/CN=test' -days 1 -newkey ec:<(openssl ecparam -name secp384r1) -keyout ec-key.pem -out ec-cert.pem"
)
with open("ec-cert.pem", "rb") as fh:
    ec_cert = fh.read()
with open("ec-key.pem", "rb") as fh:
    ec_key = serialization.load_pem_private_key(fh.read(), password=None)
signatures[ec_cert] = ec_key.sign(message, ec.ECDSA(hashes.SHA512()))

run(
    "openssl req -x509 -nodes -subj '/CN=test' -days 1 -newkey dsa:<(openssl dsaparam 2048) -keyout dsa-key.pem -out dsa-cert.pem"
)
with open("dsa-cert.pem", "rb") as fh:
    dsa_cert = fh.read()
with open("dsa-key.pem", "rb") as fh:
    dsa_key = serialization.load_pem_private_key(fh.read(), password=None)
signatures[dsa_cert] = dsa_key.sign(message, hashes.SHA512())

# Does not work on LibreSSL
run("openssl req -x509 -nodes -subj '/CN=test' -days 1 -newkey ed25519 -keyout ed25519-key.pem -out ed25519-cert.pem")
with open("ed25519-cert.pem", "rb") as fh:
    ed25519_cert = fh.read()
with open("ed25519-key.pem", "rb") as fh:
    ed25519_key = serialization.load_pem_private_key(fh.read(), password=None)
signatures[ed25519_cert] = ed25519_key.sign(message)

for cert_pem_bytes, signature in signatures.items():
    cert = x509.load_pem_x509_certificate(cert_pem_bytes)
    pubkey = cert.public_key()
    alg = TbsCertificate.load(cert.tbs_certificate_bytes)["subject_public_key_info"]["algorithm"]
    if alg["algorithm"].native == "rsassa_pss":
        verify_args = [pss_padding, hashes.SHA512()]
    elif alg["algorithm"].native == "rsa":
        verify_args = [pkcs_padding, hashes.SHA512()]
    elif alg["algorithm"].native == "ec":
        verify_args = [ec.ECDSA(hashes.SHA512())]
    elif alg["algorithm"].native == "ed25519":
        verify_args = []
    elif alg["algorithm"].native == "dsa":
        verify_args = [hashes.SHA512()]
    pubkey.verify(signature, message, *verify_args)

    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem_bytes)
        OpenSSL.crypto.verify(cert, signature, message, "sha512")
    except Exception as e:
        print(f"Error in OpenSSL.crypto.verify with {type(pubkey)}: {e}")
