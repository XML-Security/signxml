from __future__ import print_function, unicode_literals

import hashlib, base64, hmac

from eight import *

from collections import namedtuple, Mapping, Iterable
from lxml import etree
from lxml.etree import Element, SubElement

# TODO: use https://pypi.python.org/pypi/defusedxml/#defusedxml-lxml

XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

class xmldsig(object):
    def __init__(self, data, digest_algorithm="sha1"):
        self.digest_algo = digest_algorithm
        self.signature_algo = None
        self.data = data
        self.hasher = hashlib.new(self.digest_algo)

    def _get_payload_c14n(self, enveloped_signature, with_comments):
        if enveloped_signature:
            self.payload = self.data
            self._reference_uri = ""
        else:
            self.payload = Element("Object", Id="object")
            self._reference_uri = "#object"
            if isinstance(self.data, str):
                self.payload.text = self.data
            else:
                self.payload.append(self.data)
            #self.payload.set("xmlns", XMLDSIG_NS)

        self.sig_root = Element("Signature", xmlns=XMLDSIG_NS)

        self.payload_c14n = etree.tostring(self.payload, method="c14n", with_comments=with_comments, exclusive=True)
        if not enveloped_signature:
            self.payload_c14n = self.payload_c14n.replace("<Object", '<Object xmlns="{}"'.format(XMLDSIG_NS))

    def sign(self, algorithm="dsa-sha1", key=None, passphrase=None, with_comments=False, enveloped_signature=False):
        self.signature_algo = algorithm
        self.key = key

        self._get_payload_c14n(enveloped_signature, with_comments)

        self.hasher.update(self.payload_c14n)
        self.digest = base64.b64encode(self.hasher.digest())

        signed_info = SubElement(self.sig_root, "SignedInfo", xmlns=XMLDSIG_NS)
        canonicalization_method = SubElement(signed_info, "CanonicalizationMethod", Algorithm="http://www.w3.org/2006/12/xml-c14n11")
        signature_method = SubElement(signed_info, "SignatureMethod", Algorithm=XMLDSIG_NS + self.signature_algo)
        reference = SubElement(signed_info, "Reference", URI=self._reference_uri)
        if enveloped_signature:
            transforms = SubElement(reference, "Transforms")
            SubElement(transforms, "Transform", Algorithm=XMLDSIG_NS + "enveloped-signature")
        digest_method = SubElement(reference, "DigestMethod", Algorithm=XMLDSIG_NS + self.digest_algo)
        digest_value = SubElement(reference, "DigestValue")
        digest_value.text = self.digest
        signature_value = SubElement(self.sig_root, "SignatureValue")

        signed_info_payload = etree.tostring(signed_info, method="c14n")
        if self.signature_algo == "hmac-sha1":
            hasher = hmac.new(key=self.key,
                              msg=signed_info_payload,
                              digestmod=hashlib.sha1)
            signature_value.text = base64.b64encode(hasher.digest())
            self.sig_root.append(signature_value)
        elif self.signature_algo in ("dsa-sha1", "rsa-sha1"):
            from Crypto.PublicKey import RSA, DSA
            from Crypto.Hash import SHA
            from Crypto.Util.number import long_to_bytes
            from Crypto.Signature import PKCS1_v1_5
            from Crypto.Random import random

            SA = DSA if self.signature_algo == "dsa-sha1" else RSA
            if isinstance(self.key, str):
                key = SA.importKey(self.key, passphrase=passphrase)
            else:
                key = self.key

            digest = SHA.new(signed_info_payload)

            if SA is RSA:
                signature = PKCS1_v1_5.new(key).sign(digest)
                signature_value.text = base64.b64encode(signature)
            else:
                k = random.StrongRandom().randint(1, key.q - 1)
                signature = key.sign(digest.digest(), k)
                signature_value.text = base64.b64encode(long_to_bytes(signature[0]) + long_to_bytes(signature[1]))

            key_info = SubElement(self.sig_root, "KeyInfo")
            key_value = SubElement(key_info, "KeyValue")

            if SA is RSA:
                rsa_key_value = SubElement(key_value, "RSAKeyValue")
                modulus = SubElement(rsa_key_value, "Modulus")
                modulus.text = base64.b64encode(long_to_bytes(key.n))
                exponent = SubElement(rsa_key_value, "Exponent")
                exponent.text = base64.b64encode(long_to_bytes(key.e))
            else:
                dsa_key_value = SubElement(key_value, "DSAKeyValue")
                for field in "p", "q", "g", "y":
                    e = SubElement(dsa_key_value, field.upper())
                    e.text = base64.b64encode(long_to_bytes(getattr(key, field)))
        else:
            raise NotImplementedError()
        if enveloped_signature:
            self.payload.append(self.sig_root)
            return self.payload
        else:
            self.sig_root.append(self.payload)
            return self.sig_root

    def verify(self):
        pass
