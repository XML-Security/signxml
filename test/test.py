#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function

import os, sys, unittest, collections, copy, re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from signxml import *


class TestSignXML(unittest.TestCase):
    def test_basic_signxml_statements(self):
        pass

if __name__ == '__main__':
    unittest.main()
