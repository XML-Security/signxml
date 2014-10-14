#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function, unicode_literals

import os, sys, unittest, collections, copy, re
from glob import glob

from lxml import etree
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from eight import *

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from signxml import *

def reset_tree(t):
    try:
        t.remove(t.find("ds:Signature", namespaces=namespaces))
    except Exception:
        pass

class TestSignXML(unittest.TestCase):
    def setUp(self):
        self.example_xml_file = os.path.join(os.path.dirname(__file__), "example.xml")
        self.keys = dict(hmac=b"secret",
                         rsa=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
                         dsa=dsa.generate_private_key(key_size=1024, backend=default_backend()),
                         ecdsa=ec.generate_private_key(curve=ec.SECP384R1(), backend=default_backend()))

    def test_basic_signxml_statements(self):
        with self.assertRaisesRegexp(InvalidInput, "must be an XML element"):
            xmldsig("x").sign(enveloped=True)

        tree = etree.parse(self.example_xml_file)
        data = [tree.getroot(), "x y \n z t\n я\n"]
        for da in "sha1", "sha224", "sha256", "sha384", "sha512":
            for sa in "hmac", "dsa", "rsa", "ecdsa":
                for ha in "sha1", "sha256":
                    if (sa == "dsa" and ha == "sha256"):
                        print("FIXME", sa, ha)
                        continue
                    for enveloped_signature in True, False:
                        for with_comments in True, False:
                            for d in data:
                                if isinstance(d, str) and enveloped_signature is True:
                                    continue
                                print(da, sa, ha, "enveloped", enveloped_signature, "comments", with_comments, type(d))
                                reset_tree(d)
                                signed = xmldsig(d, digest_algorithm=da).sign(algorithm="-".join([sa, ha]),
                                                                              key=self.keys[sa],
                                                                              enveloped=enveloped_signature,
                                                                              with_comments=with_comments)
                                # print(etree.tostring(signed))
                                signed_data = etree.tostring(signed)
                                hmac_key = self.keys["hmac"] if sa == "hmac" else None
                                xmldsig(signed_data).verify(hmac_key=hmac_key, require_x509=False)

                                with self.assertRaisesRegexp(InvalidInput, "Expected a X509 certificate based signature"):
                                    xmldsig(signed_data).verify(hmac_key=hmac_key)

                                with self.assertRaisesRegexp(InvalidSignature, "Digest mismatch"):
                                    mangled_sig = signed_data.replace("Austria", "Mongolia").replace("x y", "a b")
                                    xmldsig(mangled_sig).verify(hmac_key=hmac_key, require_x509=False)

                                with self.assertRaisesRegexp(InvalidSignature, "Digest mismatch"):
                                    mangled_sig = signed_data.replace("<ds:DigestValue>", "<ds:DigestValue>!")
                                    xmldsig(mangled_sig).verify(hmac_key=hmac_key, require_x509=False)

                                with self.assertRaises(cryptography.exceptions.InvalidSignature):
                                    sig_value = re.search("<ds:SignatureValue>(.+?)</ds:SignatureValue>", signed_data).group(1)
                                    mangled_sig = re.sub("<ds:SignatureValue>(.+?)</ds:SignatureValue>",
                                                         "<ds:SignatureValue>" + b64encode(b64decode(sig_value)[::-1]) + "</ds:SignatureValue>",
                                                         signed_data)
                                    xmldsig(mangled_sig).verify(hmac_key=hmac_key, require_x509=False)

                                with self.assertRaises(etree.XMLSyntaxError):
                                    xmldsig("").verify(hmac_key=hmac_key, require_x509=False)

                                if sa == "hmac":
                                    with self.assertRaisesRegexp(InvalidSignature, "Signature mismatch"):
                                        xmldsig(signed_data).verify(hmac_key=b"SECRET", require_x509=False)

    def test_x509_certs(self):
        tree = etree.parse(self.example_xml_file)
        ca_pem_file = bytes(os.path.join(os.path.dirname(__file__), "example-ca.pem"))
        with open(os.path.join(os.path.dirname(__file__), "example.pem"), "rb") as fh:
            crt = fh.read()

        with open(os.path.join(os.path.dirname(__file__), "example.key"), "rb") as fh:
            key = fh.read()
        for ha in "sha1", "sha256":
            for enveloped_signature in True, False:
                print(ha, enveloped_signature)
                data = tree.getroot()
                reset_tree(data)
                signed = xmldsig(data).sign(algorithm="rsa-" + ha,
                                            key=key,
                                            cert=crt,
                                            enveloped=enveloped_signature)
                signed_data = etree.tostring(signed)
                xmldsig(signed_data).verify(ca_pem_file=ca_pem_file)
                xmldsig(signed_data).verify(x509_cert=crt)

                with self.assertRaisesRegexp(InvalidCertificate, "unable to get local issuer certificate"):
                    xmldsig(signed_data).verify()
                # TODO: negative: verify with wrong cert, wrong CA

    def test_xmldsig_interop_examples(self):
        ca_pem_file = bytes(os.path.join(os.path.dirname(__file__), "interop", "cacert.pem"))
        for signature_file in glob(os.path.join(os.path.dirname(__file__), "interop", "*.xml")):
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                xmldsig(fh.read()).verify(ca_pem_file=ca_pem_file)

    def test_xmldsig_interop_merlin_23(self):
        #from ssl import DER_cert_to_PEM_cert
        #with open(os.path.join(os.path.dirname(__file__), "interop", "merlin-xmldsig-twenty-three", "ca.crt")) as fh:
        #    ca_pem_file = DER_cert_to_PEM_cert(fh.read())
        for signature_file in glob(os.path.join(os.path.dirname(__file__), "interop", "merlin-xmldsig-twenty-three", "signature*.xml")):
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                try:
                    #xmldsig(fh.read()).verify(ca_pem_file=ca_pem_file, require_x509=False, hmac_key="secret")
                    xmldsig(fh.read()).verify(require_x509=False, hmac_key="secret")
                except Exception as e:
                    if "Expected to find XML element" in str(e) or "EntitiesForbidden" in str(e) or signature_file.endswith("signature-enveloping-hmac-sha1-40.xml") or signature_file.endswith("signature-enveloping-b64-dsa.xml"):
                        print("IGNORED:", type(e), e)
                    else:
                        raise

if __name__ == '__main__':
    unittest.main()
