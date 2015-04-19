#!/usr/bin/env python
# coding: utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, unittest, collections, copy, re
from glob import glob

from lxml import etree
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from eight import *

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from signxml import *

def reset_tree(t, enveloped=True):
    if not isinstance(t, str):
        for s in t.findall("ds:Signature", namespaces=namespaces):
            if enveloped and s.get("Id") == "placeholder":
                continue
            t.remove(s)

class URIResolver(etree.Resolver):
    def resolve(self, url, id, context):
        print("Resolving URL '%s'" % url)
        return None

parser = etree.XMLParser(load_dtd=True)
parser.resolvers.add(URIResolver())

class TestSignXML(unittest.TestCase):
    def setUp(self):
        self.example_xml_files = (os.path.join(os.path.dirname(__file__), "example.xml"),
                                  os.path.join(os.path.dirname(__file__), "example2.xml"))
        self.keys = dict(hmac=b"secret",
                         rsa=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
                         dsa=dsa.generate_private_key(key_size=1024, backend=default_backend()),
                         ecdsa=ec.generate_private_key(curve=ec.SECP384R1(), backend=default_backend()))

    def test_basic_signxml_statements(self):
        with self.assertRaisesRegexp(InvalidInput, "must be an XML element"):
            xmldsig("x").sign(enveloped=True)

        for da in "sha1", "sha224", "sha256", "sha384", "sha512":
            for sa in "hmac", "dsa", "rsa", "ecdsa":
                for ha in "sha1", "sha256":
                    for enveloped_signature in True, False:
                        for c14n_algorithm in ("http://www.w3.org/2001/10/xml-exc-c14n#",
                                               "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
                                               xmldsig.default_c14n_algorithm):
                            data = [etree.parse(f).getroot() for f in self.example_xml_files]
                            data.append("x y \n z t\n я\n")
                            for d in data:
                                if isinstance(d, str) and enveloped_signature is True:
                                    continue
                                print(da, sa, ha, c14n_algorithm, "enveloped", enveloped_signature, type(d))
                                reset_tree(d, enveloped=enveloped_signature)
                                signed = xmldsig(d, digest_algorithm=da).sign(algorithm="-".join([sa, ha]),
                                                                              key=self.keys[sa],
                                                                              enveloped=enveloped_signature,
                                                                              c14n_algorithm=c14n_algorithm)
                                # print(etree.tostring(signed))
                                signed_data = etree.tostring(signed)
                                hmac_key = self.keys["hmac"] if sa == "hmac" else None
                                xmldsig(signed_data).verify(hmac_key=hmac_key,
                                                            require_x509=False,
                                                            validate_schema=True)

                                xmldsig(signed_data).verify(hmac_key=hmac_key,
                                                            require_x509=False,
                                                            validate_schema=True,
                                                            parser=parser)

                                xmldsig(signed_data).verify(hmac_key=hmac_key,
                                                            require_x509=False,
                                                            validate_schema=True,
                                                            id_attribute="Id")

                                if enveloped_signature is False:
                                    with self.assertRaisesRegexp(InvalidInput, "Unable to resolve reference URI"):
                                        xmldsig(signed_data).verify(hmac_key=hmac_key,
                                                                    require_x509=False,
                                                                    validate_schema=True,
                                                                    id_attribute="X")

                                with self.assertRaisesRegexp(InvalidInput, "Expected a X.509 certificate based signature"):
                                    xmldsig(signed_data).verify(hmac_key=hmac_key)

                                with self.assertRaisesRegexp(InvalidSignature, "Digest mismatch"):
                                    mangled_sig = signed_data.replace(b"Austria", b"Mongolia").replace(b"x y", b"a b")
                                    xmldsig(mangled_sig).verify(hmac_key=hmac_key, require_x509=False)

                                with self.assertRaisesRegexp(InvalidSignature, "Digest mismatch"):
                                    mangled_sig = signed_data.replace(b"<ds:DigestValue>", b"<ds:DigestValue>!")
                                    xmldsig(mangled_sig).verify(hmac_key=hmac_key, require_x509=False)

                                with self.assertRaises(cryptography.exceptions.InvalidSignature):
                                    sig_value = re.search(b"<ds:SignatureValue>(.+?)</ds:SignatureValue>", signed_data).group(1)
                                    mangled_sig = re.sub(b"<ds:SignatureValue>(.+?)</ds:SignatureValue>",
                                                         b"<ds:SignatureValue>" + b64encode(b64decode(sig_value)[::-1]) + b"</ds:SignatureValue>",
                                                         signed_data)
                                    xmldsig(mangled_sig).verify(hmac_key=hmac_key, require_x509=False)

                                with self.assertRaises(etree.XMLSyntaxError):
                                    xmldsig("").verify(hmac_key=hmac_key, require_x509=False)

                                if sa == "hmac":
                                    with self.assertRaisesRegexp(InvalidSignature, "Signature mismatch"):
                                        xmldsig(signed_data).verify(hmac_key=b"SECRET", require_x509=False)

    def test_x509_certs(self):
        tree = etree.parse(self.example_xml_files[0])
        ca_pem_file = os.path.join(os.path.dirname(__file__), "example-ca.pem").encode("utf-8")
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
        ca_pem_file = os.path.join(os.path.dirname(__file__), "interop", "cacert.pem").encode("utf-8")
        for signature_file in glob(os.path.join(os.path.dirname(__file__), "interop", "*.xml")):
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                xmldsig(fh.read()).verify(ca_pem_file=ca_pem_file)

    def test_xmldsig_interop(self):
        def resolver(uri):
            if uri == "document.xml":
                with open(os.path.join(os.path.dirname(__file__), "interop", "phaos-xmldsig-three", uri), "rb") as fh:
                    return fh.read()
            elif uri == "http://www.ietf.org/rfc/rfc3161.txt":
                with open(os.path.join(os.path.dirname(__file__), "rfc3161.txt"), "rb") as fh:
                    return fh.read()
            return None

        #from ssl import DER_cert_to_PEM_cert
        #with open(os.path.join(os.path.dirname(__file__), "interop", "phaos-xmldsig-three", "certs", "dsa-ca-cert.der"), "rb") as fh:
        #    ca_pem_file = DER_cert_to_PEM_cert(fh.read())
        #    with open(os.path.join(os.path.dirname(__file__), "interop", "phaos-xmldsig-three", "certs", "dsa-ca-cert.pem"), "wb") as fh2:
        #        fh2.write(ca_pem_file)

        def get_ca_pem_file(signature_file):
            if "signature-dsa" in signature_file:
                ca_pem_file = os.path.join(os.path.dirname(__file__), "interop", "phaos-xmldsig-three", "certs", "dsa-ca-cert.pem")
            elif "signature-rsa" in signature_file:
                ca_pem_file = os.path.join(os.path.dirname(__file__), "interop", "phaos-xmldsig-three", "certs", "rsa-ca-cert.pem")
            elif "aleksey" in signature_file:
                ca_pem_file = os.path.join(os.path.dirname(__file__), "interop", "aleksey-xmldsig-01", "cacert.pem")
            else:
                return None
            return ca_pem_file.encode("utf-8")

        signature_files = glob(os.path.join(os.path.dirname(__file__), "interop", "*", "signature*.xml"))
        signature_files += glob(os.path.join(os.path.dirname(__file__), "interop", "aleksey*", "*.xml"))
        for signature_file in signature_files:
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                try:
                    sig = fh.read()
                    xmldsig(sig).verify(require_x509=False,
                                        hmac_key="test" if "phaos" in signature_file else "secret",
                                        validate_schema=True,
                                        uri_resolver=resolver,
                                        ca_pem_file=get_ca_pem_file(signature_file))
                    if "HMACOutputLength" in str(sig) or "bad" in signature_file or "expired" in signature_file:
                        raise BaseException("Expected an exception to occur")
                except Exception as e:
                    unsupported_cases = ("xpath-transform", "xslt-transform", "xpointer",
                                         "x509-data-issuer-serial", "x509-data-ski", "x509-data-subject-name",
                                         "x509data")
                    todo_cases = ("signature-big", "enveloping-dsa-x509chain",
                                  "enveloping-sha512-hmac-sha512", "enveloping-sha512-rsa-sha512")
                    if signature_file.endswith("expired-cert.xml"):
                        with self.assertRaisesRegexp(InvalidCertificate, "certificate has expired"):
                            raise
                    elif "md5" in signature_file or "ripemd160" in signature_file:
                        with self.assertRaisesRegexp(InvalidInput, "Algorithm .+ is not recognized"):
                            raise
                    elif "HMACOutputLength" in str(sig):
                        self.assertIsInstance(e, (InvalidSignature, InvalidDigest))
                    elif signature_file.endswith("signature-rsa-enveloped-bad-digest-val.xml"):
                        self.assertIsInstance(e, InvalidDigest)
                    elif signature_file.endswith("signature-rsa-detached-xslt-transform-bad-retrieval-method.xml"):
                        self.assertIsInstance(e, InvalidInput)
                    elif signature_file.endswith("signature-rsa-enveloped-bad-sig.xml"):
                        self.assertIsInstance(e, etree.DocumentInvalid)
                    elif any(x in signature_file for x in unsupported_cases) or "EntitiesForbidden" in str(e):
                        print("Unsupported test case:", type(e), e)
                    elif any(x in signature_file for x in todo_cases) or "Unable to resolve reference" in str(e):
                        print("IGNORED test case:", type(e), e)
                    elif "certificate has expired" in str(e) and ("signature-dsa" in signature_file or "signature-rsa" in signature_file):
                        print("IGNORED:", type(e), e)
                    else:
                        raise

if __name__ == '__main__':
    unittest.main()
