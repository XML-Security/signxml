from __future__ import print_function, unicode_literals

import hashlib, hmac
from base64 import b64encode, b64decode

from eight import *

from lxml import etree
from lxml.etree import Element, SubElement

# TODO: use https://pypi.python.org/pypi/defusedxml/#defusedxml-lxml

XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

class InvalidSignature(Exception):
    """
    Raised when signature validation fails.
    """

class InvalidInput(ValueError):
    pass

class xmldsig(object):
    def __init__(self, data, digest_algorithm="sha1"):
        self.digest_algo = digest_algorithm
        self.signature_algo = None
        self.data = data
        self.hash_factory = None

    def _get_payload_c14n(self, enveloped_signature, with_comments):
        if enveloped_signature:
            self.payload = self.data
            if isinstance(self.data, str):
                raise InvalidInput("When using enveloped signature, **data** must be an XML element")
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

    def sign(self, algorithm="dsa-sha1", key=None, passphrase=None, with_comments=False, enveloped_signature=False, hash_factory=None):
        self.signature_algo = algorithm
        self.key = key
        self.hash_factory = hash_factory

        self._get_payload_c14n(enveloped_signature, with_comments)

        hasher = self.hash_factory() if self.hash_factory else hashlib.sha1()
        hasher.update(self.payload_c14n)
        self.digest = b64encode(hasher.digest())

        signed_info = SubElement(self.sig_root, "SignedInfo", xmlns=XMLDSIG_NS)
        c14n_method = SubElement(signed_info, "CanonicalizationMethod", Algorithm="http://www.w3.org/2006/12/xml-c14n11")
        signature_method = SubElement(signed_info, "SignatureMethod", Algorithm=XMLDSIG_NS + self.signature_algo)
        reference = SubElement(signed_info, "Reference", URI=self._reference_uri)
        if enveloped_signature:
            transforms = SubElement(reference, "Transforms")
            SubElement(transforms, "Transform", Algorithm=XMLDSIG_NS + "enveloped-signature")
        digest_method = SubElement(reference, "DigestMethod", Algorithm=XMLDSIG_NS + self.digest_algo)
        digest_value = SubElement(reference, "DigestValue")
        digest_value.text = self.digest
        signature_value = SubElement(self.sig_root, "SignatureValue")

        signed_info_c14n = etree.tostring(signed_info, method="c14n")
        if self.signature_algo.startswith("hmac-"):
            signer = hmac.new(key=self.key,
                              msg=signed_info_c14n,
                              digestmod=self.hash_factory if self.hash_factory else hashlib.sha1)
            signature_value.text = b64encode(signer.digest())
            self.sig_root.append(signature_value)
        elif self.signature_algo.startswith("dsa-") or self.signature_algo.startswith("rsa-"):
            from Crypto.PublicKey import RSA, DSA
            from Crypto.Util.number import long_to_bytes
            from Crypto.Signature import PKCS1_v1_5
            from Crypto.Random import random

            SA = DSA if self.signature_algo.startswith("dsa-") else RSA
            if isinstance(self.key, str):
                key = SA.importKey(self.key, passphrase=passphrase)
            else:
                key = self.key

            if self.hash_factory is None:
                from Crypto.Hash import SHA
                self.hash_factory = SHA.new

            hasher = self.hash_factory()
            hasher.update(signed_info_c14n)

            if SA is RSA:
                signature = PKCS1_v1_5.new(key).sign(hasher)
                signature_value.text = b64encode(signature)
            else:
                k = random.StrongRandom().randint(1, key.q - 1)
                signature = key.sign(hasher.digest(), k)
                signature_value.text = b64encode(long_to_bytes(signature[0]) + long_to_bytes(signature[1]))

            key_info = SubElement(self.sig_root, "KeyInfo")
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
            raise NotImplementedError()
        if enveloped_signature:
            self.payload.append(self.sig_root)
            return self.payload
        else:
            self.sig_root.append(self.payload)
            return self.sig_root

    def verify(self, key=None):
        self.key = key
        root = etree.fromstring(self.data)

        if root.tag == "{" + XMLDSIG_NS + "}Signature":
            enveloped_signature = False
            signature = root
        else:
            enveloped_signature = True
            signature = self._find(root, "Signature")

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
            # TODO: find a better way to do this
            payload = self._find(signature, 'Object[@Id="{}"]'.format(reference.get("URI").lstrip("#")))

        if not digest_method.get("Algorithm").startswith(XMLDSIG_NS):
            raise InvalidInput("Expected DigestMethod#Algorithm to start with "+XMLDSIG_NS)
        hasher = hashlib.new(digest_method.get("Algorithm").split("#", 1)[1])
        payload_c14n = etree.tostring(payload, method="c14n", with_comments=with_comments, exclusive=True)
        hasher.update(payload_c14n)
        if digest_value.text != b64encode(hasher.digest()):
            raise InvalidSignature("Digest mismatch")

        signature_method = self._find(signed_info, "SignatureMethod")
        signature_value = self._find(signature, "SignatureValue")
        if not signature_method.get("Algorithm").startswith(XMLDSIG_NS):
            raise InvalidInput("Expected SignatureMethod#Algorithm to start with "+XMLDSIG_NS)

        signature_algo = signature_method.get("Algorithm").split("#", 1)[1]
        if signature_algo.startswith("hmac-sha"):
            if self.key is None:
                raise InvalidInput('Parameter "key" is required when verifying a HMAC signature')
            signer = hmac.new(key=self.key,
                              msg=signed_info_c14n,
                              digestmod=getattr(hashlib, signature_algo.split("-")[1]))
            if signature_value.text != b64encode(signer.digest()):
                raise InvalidSignature("Signature mismatch (HMAC)")
        elif signature_algo.startswith("dsa-") or signature_algo.startswith("rsa-"):
            from Crypto.PublicKey import RSA, DSA
            from Crypto.Signature import PKCS1_v1_5
            key_info = self._find(signature, "KeyInfo")
            key_value = self._find(key_info, "KeyValue")
            if signature_algo.startswith("dsa-"):
                dsa_key_value = self._find(key_value, "DSAKeyValue")
                p = self._get_long(dsa_key_value, "P")
                q = self._get_long(dsa_key_value, "Q")
                g = self._get_long(dsa_key_value, "G", require=False)
                y = self._get_long(dsa_key_value, "Y")
                key = DSA.construct((y, g, p, q))
                signature = b64decode(signature_value.text)
            else:
                rsa_key_value = self._find(key_value, "RSAKeyValue")
                modulus = self._get_long(rsa_key_value, "Modulus")
                exponent = self._get_long(rsa_key_value, "Exponent")
                key = PKCS1_v1_5.new(RSA.construct((modulus, exponent)))
                signature = b64decode(signature_value.text)
            if not key.verify(signed_info_c14n, signature):
                raise InvalidSignature("Signature mismatch")

    def _get_long(self, element, query, require=True):
        result = self._find(element, query, require=require)
        if result is not None:
            from Crypto.Util.number import bytes_to_long
            result = bytes_to_long(b64decode(result.text))
        return result

    def _find(self, element, query, require=True):
        result = element.find("xmldsig:" + query, namespaces={"xmldsig": XMLDSIG_NS})
        if require and result is None:
            raise InvalidInput("Expected to find {} in {}".format(query, element.tag))
        return result
