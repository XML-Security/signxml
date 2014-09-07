#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function, unicode_literals

import os, sys, unittest, collections, copy, re
#import xml.etree.ElementTree as ET
from io import open
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
        tree = etree.parse(self.example_xml_file)
        data = [tree.getroot(), "x y \n z t\n"]
        for alg in "hmac", "dsa", "rsa":
            for enveloped_signature in True, False:
                for d in data:
                    try:
                        d.remove(d.find("Signature"))
                    except:
                        pass
                    if isinstance(d, str) and enveloped_signature is True:
                        continue
                    print("\n----", alg, enveloped_signature, type(d), "-------\n")
                    signed = xmldsig(d).sign(algorithm=alg + "-sha1",
                                             key=self.keys[alg],
                                             enveloped_signature=enveloped_signature)
                    print(etree.tostring(signed))

if __name__ == '__main__':
    unittest.main()
