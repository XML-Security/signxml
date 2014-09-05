import hashlib

from collections import namedtuple, Mapping, Iterable
from lxml import etree, Element
#from lxml import ElementTree, Element, TreeBuilder, XMLParser

# TODO: use https://pypi.python.org/pypi/defusedxml/#defusedxml-lxml

__all__ = ['sign', 'verify']

def build_signature():
    sig_root = Element("Signature")
    

def sign(tree, digest_algorithm="sha1", encoding="base64"):
    c14n = etree.tostring(tree, method="c14n")
    print("C14n:")
    print(c14n)
    hasher = hashlib.new(digest_algorithm)
    hasher.update(c14n)
    print("Digest:")
    print(hasher.hexdigest())

def verify(tree):
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
