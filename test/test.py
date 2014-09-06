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

    def test_basic_signxml_statements(self):
        tree = etree.parse(self.example_xml_file)
#        signature = sign(tree)
        #x = etree.Element(
        print(etree.tostring(xmldsig(tree).sign()))
#        parser.feed(open(self.example_xml_file).read())
#        tree = parser.close()
#        print(tree.sign())

if __name__ == '__main__':
    unittest.main()
