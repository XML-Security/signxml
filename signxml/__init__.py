from __future__ import print_function, unicode_literals

import hashlib, base64, hmac

from eight import *

from collections import namedtuple, Mapping, Iterable
from lxml import etree
from lxml.etree import Element, SubElement

# TODO: use https://pypi.python.org/pypi/defusedxml/#defusedxml-lxml

XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

def pack_bigint(i):
    # See http://stackoverflow.com/questions/14764237
    b = bytearray()
    while i:
        b.append(i & 0xFF)
        i >>= 8
    return b

class xmldsig(object):
    def __init__(self, data, digest_algorithm="sha1"):
        self.digest_algo = digest_algorithm
        self.signature_algo = None
        self.data = data
        self.hasher = hashlib.new(self.digest_algo)

    def _sign_hmac_sha1(self):
        pass

    def _sign_dsa_sha1(self):
        pass

    def _sign_rsa_sha1(self):
        pass

    def sign(self, algorithm="dsa-sha1", key=None, passphrase=None):
        self.signature_algo = algorithm
        self.key = key
        self.payload = Element("Object", Id="object")
        if isinstance(self.data, str):
            self.payload.text = self.data
        else:
            self.payload.append(self.data)
        #self.payload.set("xmlns", XMLDSIG_NS)
        sig_root = Element("Signature", xmlns=XMLDSIG_NS)

        c14n = etree.tostring(self.payload, method="c14n", with_comments=False, exclusive=True)
        c14n = c14n.replace("<Object", '<Object xmlns="{}"'.format(XMLDSIG_NS))
#        print("BEGIN C14N")
#        print(c14n)
#        print("END C14N")
        self.hasher.update(c14n)
        self.digest = base64.b64encode(self.hasher.digest())
#        print(self.digest)

        signed_info = SubElement(sig_root, "SignedInfo", xmlns=XMLDSIG_NS)
        canonicalization_method = SubElement(signed_info, "CanonicalizationMethod", Algorithm="http://www.w3.org/2006/12/xml-c14n11")
        signature_method = SubElement(signed_info, "SignatureMethod", Algorithm=XMLDSIG_NS + self.signature_algo)
        reference = SubElement(signed_info, "Reference", URI="#object")
        digest_method = SubElement(reference, "DigestMethod", Algorithm=XMLDSIG_NS + self.digest_algo)
        digest_value = SubElement(reference, "DigestValue")
        digest_value.text = self.digest
        signature_value = SubElement(sig_root, "SignatureValue")

        signed_info_payload = etree.tostring(signed_info, method="c14n")
        if self.signature_algo == "hmac-sha1":
            #k = 73 65 63 72 65 74
            hasher = hmac.new(key=self.key,
                              msg=signed_info_payload,
                              digestmod=hashlib.sha1)
            signature_value.text = base64.b64encode(hasher.digest())
            sig_root.append(signature_value)
        elif self.signature_algo in ("dsa-sha1", "rsa-sha1"):
            from Crypto.PublicKey import RSA, DSA
            from Crypto.Signature import PKCS1_v1_5
            from Crypto.Hash import SHA
            from Crypto.Util.number import long_to_bytes
            SA = DSA if self.signature_algo == "dsa-sha1" else RSA
            key = SA.importKey(self.key, passphrase=passphrase)
            digest = SHA.new(signed_info_payload)
            signature = PKCS1_v1_5.new(key).sign(digest)

            signature_value.text = base64.b64encode(signature)
            key_info = SubElement(sig_root, "KeyInfo")
            key_value = SubElement(key_info, "KeyValue")
            if SA is RSA:
                rsa_key_value = SubElement(key_value, "RSAKeyValue")
                modulus = SubElement(rsa_key_value, "Modulus")
                modulus.text = base64.b64encode(long_to_bytes(key.n))
                exponent = SubElement(rsa_key_value, "Exponent")
                exponent.text = base64.b64encode(long_to_bytes(key.e))
        else:
            raise NotImplementedError()
        sig_root.append(self.payload)
        return sig_root

    def verify(self):
        pass

#class SigningElement(Element, XMLDSigMixin):
#    pass

#parser = XMLParser(target=TreeBuilder(element_factory=SigningElement))

'''
Digest
Required SHA1
http://www.w3.org/2000/09/xmldsig#sha1
Encoding
Required base64
http://www.w3.org/2000/09/xmldsig#base64
MAC
Required HMAC-SHA1
http://www.w3.org/2000/09/xmldsig#hmac-sha1
Signature
Required DSAwithSHA1 (DSS)
http://www.w3.org/2000/09/xmldsig#dsa-sha1
Recommended RSAwithSHA1
http://www.w3.org/2000/09/xmldsig#rsa-sha1
Canonicalization
Required Canonical XML 1.0(omits comments)
http://www.w3.org/TR/2001/REC-xml-c14n-20010315
Recommended Canonical XML 1.0with Comments
http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments
Required Canonical XML 1.1 (omits comments)
http://www.w3.org/2006/12/xml-c14n11
Recommended Canonical XML 1.1 with Comments
http://www.w3.org/2006/12/xml-c14n11#WithComments
Transform
Optional XSLT
http://www.w3.org/TR/1999/REC-xslt-19991116
Recommended XPath
http://www.w3.org/TR/1999/REC-xpath-19991116
Required Enveloped Signature*
http://www.w3.org/2000/09/xmldsig#enveloped-signature
'''
