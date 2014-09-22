#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function, unicode_literals

import os, sys, unittest, collections, copy, re
from lxml import etree
from Crypto.PublicKey import RSA, DSA
from eight import *

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from signxml import *

class TestSignXML(unittest.TestCase):
    def setUp(self):
        self.example_xml_file = os.path.join(os.path.dirname(__file__), "example.xml")
        self.keys = dict(hmac=b"secret",
                         rsa=RSA.generate(1024),
                         dsa=DSA.generate(512))

    def test_basic_signxml_statements(self):
        with self.assertRaisesRegexp(InvalidInput, "must be an XML element"):
            xmldsig("x").sign(enveloped_signature=True)

        tree = etree.parse(self.example_xml_file)
        data = [tree.getroot(), "x y \n z t\n я\n"]
        for sa in "hmac", "dsa", "rsa":
            for ha in "sha1", "sha256":
                for enveloped_signature in True, False:
                    for d in data:
                        if isinstance(d, str) and enveloped_signature is True:
                            continue
                        print(sa, ha, enveloped_signature, type(d))
                        try:
                            d.remove(d.find("Signature"))
                        except:
                            pass
                        signed = xmldsig(d).sign(algorithm="-".join([sa, ha]),
                                                 key=self.keys[sa],
                                                 enveloped_signature=enveloped_signature)
                        # print(etree.tostring(signed))
                        signed_data = etree.tostring(signed)
                        key = self.keys["hmac"] if sa == "hmac" else None
                        xmldsig(signed_data).verify(key=key)

                        with self.assertRaisesRegexp(InvalidSignature, "Digest mismatch"):
                            xmldsig(signed_data.replace("Austria", "Mongolia").replace("x y", "a b")).verify(key=key)

                        with self.assertRaisesRegexp(InvalidSignature, "Digest mismatch"):
                            xmldsig(signed_data.replace("<DigestValue>", "<DigestValue>!")).verify(key=key)

#                        with self.assertRaisesRegexp(InvalidSignature, "Signature mismatch"):
#                            xmldsig(signed_data.replace("<SignatureValue>", "<SignatureValue>z")).verify(key=key)

                        with self.assertRaises(etree.XMLSyntaxError):
                            xmldsig("").verify(key=key)

                        if sa == "hmac":
                            with self.assertRaisesRegexp(InvalidSignature, "Signature mismatch"):
                                xmldsig(signed_data).verify(key=b"SECRET")

    def test_x509_certs(self):
        tree = etree.parse(self.example_xml_file)
        ca_pem_file = os.path.join(os.path.dirname(__file__), "example-ca.pem")
        with open(os.path.join(os.path.dirname(__file__), "example.pem")) as fh:
            crt = "".join(l for l in fh.readlines() if not l.startswith("-----"))
        with open(os.path.join(os.path.dirname(__file__), "example.key")) as fh:
            key = fh.read()
        for ha in "sha1", "sha256":
            for enveloped_signature in True, False:
                signed = xmldsig(tree.getroot()).sign(algorithm="rsa-" + ha,
                                                      key=key,
                                                      cert_chain=[crt],
                                                      enveloped_signature=enveloped_signature)
                signed_data = etree.tostring(signed)
                xmldsig(signed_data).verify(ca_pem_file=ca_pem_file)
                # TODO: verify with external cert (overrides supplied cert)
                # TODO: negative: verify with wrong cert, wrong CA
                            
if __name__ == '__main__':
    unittest.main()
