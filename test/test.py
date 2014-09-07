#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function, unicode_literals

import os, sys, unittest, collections, copy, re
#import xml.etree.ElementTree as ET
from io import open
from lxml import etree

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from signxml import *

class TestSignXML(unittest.TestCase):
    def setUp(self):
        self.example_xml_file = os.path.join(os.path.dirname(__file__), "example.xml")

        #from Crypto.PublicKey import RSA, DSA
        #key = RSA.generate(4096)
        #with open("rsa_key.pem", "wb") as fh:
        #    fh.write(key.exportKey())
        #key = DSA.generate(512)
        #with open("dsa_key.pem", "wb") as fh:
        #    fh.write(key.exportKey())

    def test_basic_signxml_statements(self):
        tree = etree.parse(self.example_xml_file)
#        signature = sign(tree)
        #x = etree.Element(
        k = b"secret"
#        with open("AlicePrivRSASign_epk.txt") as fh:
        with open("rsa_key.pem") as fh:
            rsa_key = fh.read()
#            for line in fh:
#                if line.startswith("-----"):
#                    continue
#                rsa_key += line.strip()
#        print("LINE:", rsa_key)
        rsa_passphrase = "password"
        print(etree.tostring(xmldsig("wat").sign(algorithm="rsa-sha1",
                                                 key=rsa_key,
                                                 passphrase=rsa_passphrase)))
#tree.getroot()).sign()))
#        parser.feed(open(self.example_xml_file).read())
#        tree = parser.close()
#        print(tree.sign())

if __name__ == '__main__':
    unittest.main()
