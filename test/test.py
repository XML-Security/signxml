#!/usr/bin/env python
# coding: utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, unittest, itertools, re
from glob import glob
from xml.etree import ElementTree as stdlibElementTree

from lxml import etree
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from eight import *

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from signxml import *

def reset_tree(t, method):
    if not isinstance(t, str):
        for s in t.findall(".//ds:Signature", namespaces=namespaces):
            if method == methods.enveloped and s.get("Id") == "placeholder":
                continue
            s.getparent().remove(s)

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
        with self.assertRaisesRegexp(InvalidInput, "Unknown signature method"):
            xmldsig("x").sign(method=None)

        with self.assertRaisesRegexp(InvalidInput, "must be an XML element"):
            xmldsig("x").sign()

        digest_algs = {"sha1", "sha224", "sha256", "sha384", "sha512"}
        sig_algs = {"hmac", "dsa", "rsa", "ecdsa"}
        hash_algs = {"sha1", "sha256"}
        c14n_algs = {"http://www.w3.org/2001/10/xml-exc-c14n#",
                     "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
                     xmldsig.default_c14n_algorithm}

        all_methods = itertools.product(digest_algs, sig_algs, hash_algs, methods, c14n_algs)
        for digest_alg, sig_alg, hash_alg, method, c14n_alg in all_methods:
            data = [etree.parse(f).getroot() for f in self.example_xml_files]
            # FIXME: data.extend(stdlibElementTree.parse(f).getroot() for f in (self.example_xml_files)
            data.append(stdlibElementTree.parse(self.example_xml_files[0]).getroot())
            data.append("x y \n z t\n я\n")
            for d in data:
                if isinstance(d, str) and method != methods.enveloping:
                    continue
                print(digest_alg, sig_alg, hash_alg, c14n_alg, method, type(d))
                reset_tree(d, method)
                signer = xmldsig(d, digest_algorithm=digest_alg)
                signed = signer.sign(method=method,
                                     algorithm="-".join([sig_alg, hash_alg]),
                                     key=self.keys[sig_alg],
                                     c14n_algorithm=c14n_alg,
                                     reference_uri="URI" if method == methods.detached else None)
                # print(etree.tostring(signed))
                hmac_key = self.keys["hmac"] if sig_alg == "hmac" else None
                verify_kwargs = dict(require_x509=False, hmac_key=hmac_key, validate_schema=True)

                if method == methods.detached:
                    def resolver(uri):
                        if isinstance(d, stdlibElementTree.Element):
                            return etree.fromstring(stdlibElementTree.tostring(d))
                        else:
                            return d
                    verify_kwargs["uri_resolver"] = resolver

                signed_data = etree.tostring(signed)
                xmldsig(signed_data).verify(**verify_kwargs)
                xmldsig(signed_data).verify(parser=parser, **verify_kwargs)
                (_d, _x, _s) = xmldsig(signed_data).verify(id_attribute="Id", **verify_kwargs)

                if _x is not None:
                    # Ensure the signature is not part of the signed data
                    self.assertIsNone(_x.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature"))
                    self.assertNotEqual(_x.tag, "{http://www.w3.org/2000/09/xmldsig#}Signature")

                # Ensure the signature was returned
                self.assertEqual(_s.tag, "{http://www.w3.org/2000/09/xmldsig#}Signature")

                if method == methods.enveloping:
                    with self.assertRaisesRegexp(InvalidInput, "Unable to resolve reference URI"):
                        xmldsig(signed_data).verify(id_attribute="X", **verify_kwargs)

                with self.assertRaisesRegexp(InvalidInput, "Expected a X.509 certificate based signature"):
                    xmldsig(signed_data).verify(hmac_key=hmac_key, uri_resolver=verify_kwargs.get("uri_resolver"))

                if method != methods.detached:
                    with self.assertRaisesRegexp(InvalidSignature, "Digest mismatch"):
                        mangled_sig = signed_data.replace(b"Austria", b"Mongolia").replace(b"x y", b"a b")
                        xmldsig(mangled_sig).verify(**verify_kwargs)

                with self.assertRaises(cryptography.exceptions.InvalidSignature):
                    mangled_sig = signed_data.replace(b"<ds:DigestValue>", b"<ds:DigestValue>!")
                    xmldsig(mangled_sig).verify(**verify_kwargs)

                with self.assertRaises(cryptography.exceptions.InvalidSignature):
                    sig_value = re.search(b"<ds:SignatureValue>(.+?)</ds:SignatureValue>", signed_data).group(1)
                    mangled_sig = re.sub(
                        b"<ds:SignatureValue>(.+?)</ds:SignatureValue>",
                        b"<ds:SignatureValue>" + b64encode(b64decode(sig_value)[::-1]) + b"</ds:SignatureValue>",
                        signed_data
                    )
                    xmldsig(mangled_sig).verify(**verify_kwargs)

                with self.assertRaises(etree.XMLSyntaxError):
                    xmldsig("").verify(hmac_key=hmac_key, require_x509=False)

                if sig_alg == "hmac":
                    with self.assertRaisesRegexp(InvalidSignature, "Signature mismatch"):
                        verify_kwargs["hmac_key"] = b"SECRET"
                        xmldsig(signed_data).verify(**verify_kwargs)

    def test_x509_certs(self):
        from OpenSSL.crypto import load_certificate, FILETYPE_PEM, Error as OpenSSLCryptoError

        tree = etree.parse(self.example_xml_files[0])
        ca_pem_file = os.path.join(os.path.dirname(__file__), "example-ca.pem").encode("utf-8")
        with open(os.path.join(os.path.dirname(__file__), "example.pem"), "rb") as fh:
            crt = fh.read()
        with open(os.path.join(os.path.dirname(__file__), "example.key"), "rb") as fh:
            key = fh.read()
        for hash_alg in "sha1", "sha256":
            for method in methods.enveloped, methods.enveloping:
                print(hash_alg, method)
                data = tree.getroot()
                reset_tree(data, method)
                signed = xmldsig(data).sign(method=method,
                                            algorithm="rsa-" + hash_alg,
                                            key=key,
                                            cert=crt)
                signed_data = etree.tostring(signed)
                xmldsig(signed_data).verify(ca_pem_file=ca_pem_file)
                xmldsig(signed_data).verify(x509_cert=crt)
                xmldsig(signed_data).verify(x509_cert=load_certificate(FILETYPE_PEM, crt))

                with self.assertRaises(OpenSSLCryptoError):
                    xmldsig(signed_data).verify(x509_cert=crt[::-1])

                with self.assertRaisesRegexp(InvalidCertificate, "unable to get local issuer certificate"):
                    xmldsig(signed_data).verify()
                # TODO: negative: verify with wrong cert, wrong CA

    def test_xmldsig_interop_examples(self):
        ca_pem_file = os.path.join(os.path.dirname(__file__), "interop", "cacert.pem").encode("utf-8")
        for signature_file in glob(os.path.join(os.path.dirname(__file__), "interop", "*.xml")):
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                with self.assertRaisesRegexp(InvalidCertificate, "certificate has expired"):
                    xmldsig(fh.read()).verify(ca_pem_file=ca_pem_file)

    def test_xmldsig_interop(self):
        interop_dir = os.path.join(os.path.dirname(__file__), "interop")
        def resolver(uri):
            if uri == "document.xml":
                with open(os.path.join(interop_dir, "phaos-xmldsig-three", uri), "rb") as fh:
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

        def get_x509_cert(signature_file):
            if "windows_store_signature" in signature_file:
                return open(os.path.join(interop_dir, "xml-crypto", "windows_store_certificate.pem")).read()
            elif "pyXMLSecurity" in signature_file:
                return open(os.path.join(interop_dir, "pyXMLSecurity", "test.pem")).read()
            else:
                return None

        def get_ca_pem_file(signature_file):
            if "signature-dsa" in signature_file:
                ca_pem_file = os.path.join(interop_dir, "phaos-xmldsig-three", "certs", "dsa-ca-cert.pem")
            elif "signature-rsa" in signature_file:
                ca_pem_file = os.path.join(interop_dir, "phaos-xmldsig-three", "certs", "rsa-ca-cert.pem")
            elif "aleksey-xmldsig-01-enveloped" in signature_file:
                ca_pem_file = os.path.join(interop_dir, "aleksey-xmldsig-01-enveloped", "cacert.pem")
            elif "aleksey" in signature_file:
                ca_pem_file = os.path.join(interop_dir, "aleksey-xmldsig-01", "cacert.pem")
            elif "wsfederation_metadata" in signature_file:
                ca_pem_file = os.path.join(interop_dir, "xml-crypto", "wsfederation_metadata.pem")
            elif "signature_with_inclusivenamespaces" in signature_file:
                ca_pem_file = os.path.join(interop_dir, "xml-crypto", "signature_with_inclusivenamespaces.pem")
            else:
                return None
            return ca_pem_file.encode("utf-8")

        signature_files = glob(os.path.join(interop_dir, "*", "signature*.xml"))
        signature_files += glob(os.path.join(interop_dir, "aleksey*", "*.xml"))
        signature_files += glob(os.path.join(interop_dir, "xml-crypto", "*.xml"))
        signature_files += glob(os.path.join(interop_dir, "pyXMLSecurity", "*.xml"))
        for signature_file in signature_files:
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                try:
                    sig = fh.read()
                    xmldsig(sig).verify(require_x509=False,
                                        hmac_key="test" if "phaos" in signature_file else "secret",
                                        validate_schema=True,
                                        uri_resolver=resolver,
                                        x509_cert=get_x509_cert(signature_file),
                                        ca_pem_file=get_ca_pem_file(signature_file))
                    if "HMACOutputLength" in sig.decode("utf-8") or "bad" in signature_file or "expired" in signature_file:
                        raise BaseException("Expected an exception to occur")
                except Exception as e:
                    unsupported_cases = ("xpath-transform", "xslt-transform", "xpointer",
                                         "x509-data-issuer-serial", "x509-data-ski", "x509-data-subject-name",
                                         "x509data", "signature-x509-ski", "signature-x509-is")
                    todo_cases = ("signature-big", "enveloping-dsa-x509chain",
                                  "enveloping-sha512-hmac-sha512", "enveloping-sha512-rsa-sha512")
                    if signature_file.endswith("expired-cert.xml"):
                        with self.assertRaisesRegexp(InvalidCertificate, "certificate has expired"):
                            raise
                    elif signature_file.endswith("invalid_enveloped_transform.xml"):
                        self.assertIsInstance(e, InvalidSignature)
                        #with self.assertRaisesRegexp(ValueError, "Can't remove the root signature node"):
                        #    raise
                    elif "md5" in signature_file or "ripemd160" in signature_file:
                        self.assertIsInstance(e, InvalidInput)
                        #with self.assertRaisesRegexp(InvalidInput, "Algorithm .+ is not recognized"):
                        #    raise
                    elif "HMACOutputLength" in sig.decode("utf-8"):
                        self.assertIsInstance(e, (InvalidSignature, InvalidDigest))
                    elif signature_file.endswith("signature-rsa-enveloped-bad-digest-val.xml"):
                        #self.assertIsInstance(e, InvalidDigest)
                        self.assertIsInstance(e, InvalidCertificate)
                    elif signature_file.endswith("signature-rsa-detached-xslt-transform-bad-retrieval-method.xml"):
                        self.assertIsInstance(e, InvalidInput)
                    elif signature_file.endswith("signature-rsa-enveloped-bad-sig.xml"):
                        self.assertIsInstance(e, etree.DocumentInvalid)
                    elif signature_file.endswith("signature-x509-crt.xml"):
                        self.assertIsInstance(e, InvalidCertificate)
                    elif signature_file.endswith("signature-keyname.xml"):
                        self.assertIsInstance(e, InvalidInput)
                    elif signature_file.endswith("signature-x509-sn.xml"):
                        self.assertIsInstance(e, InvalidInput)
                    elif signature_file.endswith("signature-x509-crt-crl.xml"):
                        self.assertIsInstance(e, InvalidCertificate)
                    elif signature_file.endswith("signature-retrievalmethod-rawx509crt.xml"):
                        self.assertIsInstance(e, InvalidInput)
                    elif any(x in signature_file for x in unsupported_cases) or "EntitiesForbidden" in str(e):
                        print("Unsupported test case:", type(e), e)
                    elif any(x in signature_file for x in todo_cases) or "Unable to resolve reference" in str(e):
                        print("IGNORED test case:", type(e), e)
                    elif "certificate has expired" in str(e) and ("signature-dsa" in signature_file or "signature-rsa" in signature_file):
                        print("IGNORED:", type(e), e)
                    else:
                        raise

    def test_signxml_changing_signature_namespace_prefix(self):
        data = etree.parse(self.example_xml_files[0]).getroot()
        signer = xmldsig(data)
        signer.namespaces = dict(digi_sign=namespaces['ds'])
        signed = signer.sign(key=self.keys["rsa"])
        signed_data = etree.tostring(signed)
        expected_match = ("<digi_sign:Signature xmlns:"
                          "digi_sign=\"%s\">") % namespaces['ds']
        self.assertTrue(re.search(expected_match.encode('ascii'), signed_data))

    def test_signxml_changing_signature_namespace_prefix_to_default(self):
        data = etree.parse(self.example_xml_files[0]).getroot()
        signer = xmldsig(data)
        ns = dict()
        ns[None] = namespaces['ds']
        signer.namespaces = ns
        signed = signer.sign(key=self.keys["rsa"])
        signed_data = etree.tostring(signed)
        expected_match = ("<Signature xmlns=\"%s\">") % namespaces['ds']
        self.assertTrue(re.search(expected_match.encode('ascii'), signed_data))

    def test_elementtree_compat(self):
        data = stdlibElementTree.parse(self.example_xml_files[0]).getroot()
        signer = xmldsig(data)
        signed = signer.sign(key=self.keys["rsa"])

if __name__ == '__main__':
    unittest.main()
