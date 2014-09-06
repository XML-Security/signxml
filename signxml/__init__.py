from __future__ import print_function, unicode_literals

import hashlib, base64, hmac

from collections import namedtuple, Mapping, Iterable
from lxml import etree
from lxml.etree import Element

# TODO: use https://pypi.python.org/pypi/defusedxml/#defusedxml-lxml

XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

class xmldsig(object):
    def __init__(self, data, digest_algorithm="sha1", signature_algorithm="hmac-sha1"):
        self.digest_algo = digest_algorithm
        self.signature_algo = signature_algorithm
        self.data = data
        self.hasher = hashlib.new(self.digest_algo)

    def sign(self):
        self.payload = Element("Object", Id="object")
        from collections import OrderedDict
        #self.payload.set("xmlns", XMLDSIG_NS)
        self.payload.text = """some text
  with spaces and CR-LF."""
#        self.payload.append(self.data)
        sig_root = Element("Signature", xmlns=XMLDSIG_NS)

        c14n = etree.tostring(self.payload, method="c14n", with_comments=False, exclusive=True)
        c14n = c14n.replace("<Object", '<Object xmlns="{}"'.format(XMLDSIG_NS))
        print("BEGIN C14N")
        print(c14n)
        print("END C14N")
        self.hasher.update(c14n)
        self.digest = base64.b64encode(self.hasher.digest())
        print(self.digest)

        #print("PARENT:", self.payload.getparent().get("xmlns"))


        signed_info = Element("SignedInfo", xmlns=XMLDSIG_NS)
        sig_root.append(signed_info)
        canonicalization_method = Element("CanonicalizationMethod", Algorithm="http://www.w3.org/2006/12/xml-c14n11")
        signed_info.append(canonicalization_method)
        signature_method = Element("SignatureMethod", Algorithm=XMLDSIG_NS + self.signature_algo)
        signed_info.append(signature_method)
        reference = Element("Reference", URI="#object")
        signed_info.append(reference)
        digest_method = Element("DigestMethod", Algorithm=XMLDSIG_NS + self.digest_algo)
        reference.append(digest_method)
        digest_value = Element("DigestValue")
        digest_value.text = self.digest
        reference.append(digest_value)
        signature_value = Element("SignatureValue")
        if self.signature_algo == "hmac-sha1":
            k = b"secret"
            #k = 73 65 63 72 65 74
            hasher = hmac.new(key=k,
                              msg=etree.tostring(signed_info, method="c14n"),
                              digestmod=hashlib.sha1)
            signature_value.text = base64.b64encode(hasher.digest())
            sig_root.append(signature_value)
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
