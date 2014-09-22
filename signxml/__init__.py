from __future__ import print_function, unicode_literals

import os, sys, textwrap
from base64 import b64encode, b64decode
from collections import OrderedDict
from importlib import import_module

from eight import *
from lxml import etree
from lxml.etree import Element, SubElement

# TODO: use https://pypi.python.org/pypi/defusedxml/#defusedxml-lxml

XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"

class InvalidSignature(Exception):
    """
    Raised when signature validation fails.
    """

class InvalidCertificate(InvalidSignature):
    """
    Raised when certificate validation fails.
    """

class InvalidInput(ValueError):
    pass

_schema = None

def _get_schema():
    global _schema
    if _schema is None:
        schema_file = os.path.join(os.path.dirname(__file__), "schemas", "xmldsig_schema.xsd")
        with open(schema_file) as fh:
            _schema = etree.XMLSchema(etree.parse(fh))
    return _schema

class xmldsig(object):
    def __init__(self, data, digest_algorithm="sha1"):
        self.digest_alg = digest_algorithm
        self.signature_alg = None
        self.data = data
        self.hash_factory = None

    def _get_payload_c14n(self, enveloped_signature, with_comments):
        if enveloped_signature:
            self.payload = self.data
            if isinstance(self.data, (str, bytes)):
                raise InvalidInput("When using enveloped signature, **data** must be an XML element")
            self._reference_uri = ""
        else:
            self.payload = Element("Object", nsmap={None: XMLDSIG_NS}, Id="object")
            self._reference_uri = "#object"
            if isinstance(self.data, (str, bytes)):
                self.payload.text = self.data
            else:
                self.payload.append(self.data)

        self.sig_root = Element("Signature", xmlns=XMLDSIG_NS)
        self.payload_c14n = etree.tostring(self.payload, method="c14n", with_comments=with_comments, exclusive=True)

    def _get_hash_factory(self, tag, use_pycrypto=False):
        if self.hash_factory is not None:
            return self.hash_factory

        if isinstance(tag, (str, bytes)):
            algorithm = tag
            if "-" in tag:
                algorithm = tag.split("-", 1)[1]
        else:
            if tag.get("Algorithm") is None:
                raise InvalidInput('Expected {} to contain a tag "Algorithm"'.format(tag.text))
            if not tag.get("Algorithm").startswith(XMLDSIG_NS):
                raise InvalidInput("Expected {}#Algorithm to start with {}".format(tag.text, XMLDSIG_NS))
            algorithm = tag.get("Algorithm").split("#", 1)[1]

        if algorithm == "sha1":
            algorithm = "SHA"

        return import_module("Crypto.Hash." + algorithm.upper())

    def sign(self, algorithm="dsa-sha1", key=None, passphrase=None, cert_chain=None, with_comments=False, enveloped_signature=False, hash_factory=None):
        self.signature_alg = algorithm
        self.key = key
        self.hash_factory = hash_factory

        self._get_payload_c14n(enveloped_signature, with_comments)

        hasher = self._get_hash_factory(self.digest_alg)
        self.digest = b64encode(hasher.new(self.payload_c14n).digest())

        signed_info = SubElement(self.sig_root, "SignedInfo", xmlns=XMLDSIG_NS)
        c14n_method = SubElement(signed_info, "CanonicalizationMethod", Algorithm="http://www.w3.org/2006/12/xml-c14n11")
        signature_method = SubElement(signed_info, "SignatureMethod", Algorithm=XMLDSIG_NS + self.signature_alg)
        reference = SubElement(signed_info, "Reference", URI=self._reference_uri)
        if enveloped_signature:
            transforms = SubElement(reference, "Transforms")
            SubElement(transforms, "Transform", Algorithm=XMLDSIG_NS + "enveloped-signature")
        digest_method = SubElement(reference, "DigestMethod", Algorithm=XMLDSIG_NS + self.digest_alg)
        digest_value = SubElement(reference, "DigestValue")
        digest_value.text = self.digest
        signature_value = SubElement(self.sig_root, "SignatureValue")

        signed_info_c14n = etree.tostring(signed_info, method="c14n")
        if self.signature_alg.startswith("hmac-"):
            from Crypto.Hash import HMAC
            signer = HMAC.new(key=self.key,
                              msg=signed_info_c14n,
                              digestmod=self._get_hash_factory(self.signature_alg))
            signature_value.text = b64encode(signer.digest())
            self.sig_root.append(signature_value)
        elif self.signature_alg.startswith("dsa-") or self.signature_alg.startswith("rsa-"):
            from Crypto.PublicKey import RSA, DSA
            from Crypto.Util.number import long_to_bytes
            from Crypto.Signature import PKCS1_v1_5
            from Crypto.Random import random

            SA = DSA if self.signature_alg.startswith("dsa-") else RSA
            if isinstance(self.key, (str, bytes)):
                key = SA.importKey(self.key, passphrase=passphrase)
            else:
                key = self.key

            hasher = self._get_hash_factory(self.signature_alg).new(signed_info_c14n)

            if SA is RSA:
                signature = PKCS1_v1_5.new(key).sign(hasher)
                signature_value.text = b64encode(signature)
            else:
                k = random.StrongRandom().randint(1, key.q - 1)
                signature = key.sign(hasher.digest(), k)
                signature_value.text = b64encode(long_to_bytes(signature[0]) + long_to_bytes(signature[1]))

            key_info = SubElement(self.sig_root, "KeyInfo")
            if cert_chain is None:
                key_value = SubElement(key_info, "KeyValue")
                if SA is RSA:
                    rsa_key_value = SubElement(key_value, "RSAKeyValue")
                    modulus = SubElement(rsa_key_value, "Modulus")
                    modulus.text = b64encode(long_to_bytes(key.n))
                    exponent = SubElement(rsa_key_value, "Exponent")
                    exponent.text = b64encode(long_to_bytes(key.e))
                else:
                    dsa_key_value = SubElement(key_value, "DSAKeyValue")
                    for field in "p", "q", "g", "y":
                        e = SubElement(dsa_key_value, field.upper())
                        e.text = b64encode(long_to_bytes(getattr(key, field)))
            else:
                x509_data = SubElement(key_info, "X509Data")
                for cert in cert_chain:
                    x509_certificate = SubElement(x509_data, "X509Certificate")
                    if isinstance(cert, (str, bytes)):
                        x509_certificate.text = cert
                    else:
                        from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
                        print("BEGIN DUMP")
                        print(dump_certificate(FILETYPE_PEM, cert))
                        print("END DUMP")
                        x509_certificate.text = dump_certificate(FILETYPE_PEM, cert)
        else:
            raise NotImplementedError()

        if enveloped_signature:
            self.payload.append(self.sig_root)
            return self.payload
        else:
            self.sig_root.append(self.payload)
            return self.sig_root

    def verify(self, key=None, validate_schema=True, ca_pem_file=None, ca_path=None):
        self.key = key
        root = etree.fromstring(self.data)

        if root.tag == "{" + XMLDSIG_NS + "}Signature":
            enveloped_signature = False
            signature = root
        else:
            enveloped_signature = True
            signature = self._find(root, "Signature")

        if validate_schema:
            _get_schema().assertValid(signature)

        signed_info = self._find(signature, "SignedInfo")
        c14n_method = self._find(signed_info, "CanonicalizationMethod")
        if c14n_method.get("Algorithm").endswith("#WithComments"):
            with_comments = True
        else:
            with_comments = False
        signed_info_c14n = etree.tostring(signed_info, method="c14n", with_comments=with_comments, exclusive=True)
        reference = self._find(signed_info, "Reference")
        digest_method = self._find(reference, "DigestMethod")
        digest_value = self._find(reference, "DigestValue")

        if enveloped_signature:
            payload = root
            payload.remove(signature)
        else:
            payload = self._find(signature, 'Object[@Id="{}"]'.format(reference.get("URI").lstrip("#")))

        if not digest_method.get("Algorithm").startswith(XMLDSIG_NS):
            raise InvalidInput("Expected DigestMethod#Algorithm to start with "+XMLDSIG_NS)
        payload_c14n = etree.tostring(payload, method="c14n", with_comments=with_comments, exclusive=True)
        if digest_value.text != b64encode(self._get_hash_factory(digest_method).new(payload_c14n).digest()):
            raise InvalidSignature("Digest mismatch")

        signature_method = self._find(signed_info, "SignatureMethod")
        signature_value = self._find(signature, "SignatureValue")
        if not signature_method.get("Algorithm").startswith(XMLDSIG_NS):
            raise InvalidInput("Expected SignatureMethod#Algorithm to start with "+XMLDSIG_NS)

        signature_alg = signature_method.get("Algorithm").split("#", 1)[1]
        if signature_alg.startswith("hmac-sha"):
            if self.key is None:
                raise InvalidInput('Parameter "key" is required when verifying a HMAC signature')
            from Crypto.Hash import HMAC
            signer = HMAC.new(key=self.key,
                              msg=signed_info_c14n,
                              digestmod=self._get_hash_factory(signature_alg))
            if signature_value.text != b64encode(signer.digest()):
                raise InvalidSignature("Signature mismatch (HMAC)")
        elif signature_alg.startswith("dsa-") or signature_alg.startswith("rsa-"):
            from Crypto.PublicKey import RSA, DSA
            from Crypto.Signature import PKCS1_v1_5
            from Crypto.Util.number import bytes_to_long

            hasher = self._get_hash_factory(signature_alg).new(signed_info_c14n)

            key_info = self._find(signature, "KeyInfo")
            key_value = self._find(key_info, "KeyValue", require=False)
            verifiable = hasher
            signature = b64decode(signature_value.text)
            if key_value is None:
                from Crypto.Util.asn1 import DerSequence
                from OpenSSL.crypto import load_certificate, FILETYPE_PEM
                from binascii import a2b_base64

                x509_data = self._find(key_info, "X509Data")
                if x509_data is None:
                    raise InvalidInput("Expected to find either KeyValue or X509Data XML element in KeyInfo")
                certs = [cert.text for cert in self._findall(x509_data, "X509Certificate")]
                def format_pem(cert):
                    return PEM_HEADER + "\n" + textwrap.fill(cert, 64) + "\n" + PEM_FOOTER
                chain = [load_certificate(FILETYPE_PEM, format_pem(cert)) for cert in certs]
                verify_x509_cert_chain(chain, ca_pem_file=ca_pem_file, ca_path=ca_path)

                cert = DerSequence()
                cert.decode(a2b_base64(certs[-1]))
                tbsCertificate = DerSequence()
                tbsCertificate.decode(cert[0])
                subjectPublicKeyInfo = tbsCertificate[6]
                key = PKCS1_v1_5.new(RSA.importKey(subjectPublicKeyInfo))
            elif signature_alg.startswith("dsa-"):
                dsa_key_value = self._find(key_value, "DSAKeyValue")
                p = self._get_long(dsa_key_value, "P")
                q = self._get_long(dsa_key_value, "Q")
                g = self._get_long(dsa_key_value, "G", require=False)
                y = self._get_long(dsa_key_value, "Y")
                key = DSA.construct((y, g, p, q))
                signature = (bytes_to_long(signature[:len(signature)/2]),
                             bytes_to_long(signature[len(signature)/2:]))
                verifiable = hasher.digest()
            else:
                rsa_key_value = self._find(key_value, "RSAKeyValue")
                modulus = self._get_long(rsa_key_value, "Modulus")
                exponent = self._get_long(rsa_key_value, "Exponent")
                key = PKCS1_v1_5.new(RSA.construct((modulus, exponent)))

            if not key.verify(verifiable, signature):
                raise InvalidSignature("Signature mismatch")
        else:
            raise NotImplementedError()

    def _get_long(self, element, query, require=True):
        result = self._find(element, query, require=require)
        if result is not None:
            from Crypto.Util.number import bytes_to_long
            result = bytes_to_long(b64decode(result.text))
        return result

    def _find(self, element, query, require=True):
        result = element.find("xmldsig:" + query, namespaces={"xmldsig": XMLDSIG_NS})
        if require and result is None:
            raise InvalidInput("Expected to find XML element {} in {}".format(query, element.tag))
        return result

    def _findall(self, element, query):
        return element.findall("xmldsig:" + query, namespaces={"xmldsig": XMLDSIG_NS})

def verify_x509_cert_chain(cert_chain, ca_pem_file=None, ca_path=None):
    from OpenSSL import SSL
    from OpenSSL.crypto import load_certificate
    context = SSL.Context(SSL.TLSv1_METHOD)
    if ca_pem_file is None and ca_path is None:
        import certifi
        ca_pem_file = certifi.where()
    context.load_verify_locations(ca_pem_file, capath=ca_path)
    store = context.get_cert_store()
    for cert in cert_chain:
        # The following certificate chain verification code uses an internal pyOpenSSL API with guidance from
        # https://github.com/pyca/pyopenssl/pull/155
        # TODO: Update this to use the public API once the PR lands.
        store_ctx = SSL._lib.X509_STORE_CTX_new()
        _store_ctx = SSL._ffi.gc(store_ctx, SSL._lib.X509_STORE_CTX_free)
        SSL._lib.X509_STORE_CTX_init(store_ctx, store._store, cert._x509, SSL._ffi.NULL)
        result = SSL._lib.X509_verify_cert(_store_ctx)
        SSL._lib.X509_STORE_CTX_cleanup(_store_ctx)
        if result <= 0:
            e = SSL._lib.X509_STORE_CTX_get_error(_store_ctx)
            msg = SSL._ffi.string(SSL._lib.X509_verify_cert_error_string(e))
            raise InvalidCertificate(msg)
        else:
            store.add_cert(cert)
