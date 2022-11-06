#!/usr/bin/env python

import itertools
import os
import re
import sys
import unittest
from base64 import b64decode, b64encode
from glob import glob
from xml.etree import ElementTree as stdlibElementTree

import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from lxml import etree

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from signxml import (  # noqa
    InvalidCertificate,
    InvalidDigest,
    InvalidInput,
    InvalidSignature,
    VerifyResult,
    XMLSignatureProcessor,
    XMLSigner,
    XMLVerifier,
    digest_algorithms,
    methods,
    namespaces,
)
from signxml.xades import XAdESSigner, XAdESVerifier, XAdESVerifyResult  # noqa


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

interop_dir = os.path.join(os.path.dirname(__file__), "interop")


class LoadExampleKeys:
    def load_example_keys(self):
        with open(os.path.join(os.path.dirname(__file__), "example.pem"), "rb") as fh:
            crt = fh.read()
        with open(os.path.join(os.path.dirname(__file__), "example.key"), "rb") as fh:
            key = fh.read()
        return crt, key


class TestVerifyXML(unittest.TestCase, LoadExampleKeys):
    def test_example_multi(self):
        cert, _ = self.load_example_keys()
        with open(os.path.join(os.path.dirname(__file__), "example.pem")) as fh:
            cert = fh.read()
        example_file = os.path.join(os.path.dirname(__file__), "example-125.xml")
        XMLVerifier().verify(
            data=etree.parse(example_file),
            x509_cert=cert,
            expect_references=2,
        )


class TestSignXML(unittest.TestCase, LoadExampleKeys):
    def setUp(self):
        self.example_xml_files = (
            os.path.join(os.path.dirname(__file__), "example.xml"),
            os.path.join(os.path.dirname(__file__), "example2.xml"),
        )
        self.keys = dict(
            hmac=b"secret",
            rsa=rsa.generate_private_key(public_exponent=65537, key_size=2048),
            dsa=dsa.generate_private_key(key_size=1024),
            ecdsa=ec.generate_private_key(curve=ec.SECP384R1()),
        )

    def test_basic_signxml_statements(self):
        with self.assertRaisesRegex(InvalidInput, "Unknown signature method"):
            signer = XMLSigner(method=None)

        with self.assertRaisesRegex(InvalidInput, "must be an XML element"):
            XMLSigner(signature_algorithm="hmac-sha256").sign("x", key=b"abc")

        digest_algs = {"sha1", "sha224", "sha256", "sha384", "sha512"}
        sig_algs = {"hmac", "dsa", "rsa", "ecdsa"}
        hash_algs = {"sha1", "sha256"}
        c14n_algs = {
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
            XMLSignatureProcessor.default_c14n_algorithm,
        }

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
                signer = XMLSigner(
                    method=method,
                    signature_algorithm="-".join([sig_alg, hash_alg]),
                    digest_algorithm=digest_alg,
                    c14n_algorithm=c14n_alg,
                )
                signed = signer.sign(
                    d, key=self.keys[sig_alg], reference_uri="URI" if method == methods.detached else None
                )
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
                XMLVerifier().verify(signed_data, **verify_kwargs)
                XMLVerifier().verify(signed_data, parser=parser, **verify_kwargs)
                res = XMLVerifier().verify(signed_data, id_attribute="Id", **verify_kwargs)
                self.assertIsInstance(res[0], VerifyResult)
                for attr in "signed_data", "signed_xml", "signature_xml":
                    self.assertTrue(hasattr(res[0], attr))

                if res[0].signed_xml is not None:
                    # Ensure the signature is not part of the signed data
                    self.assertIsNone(res[0].signed_xml.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature"))
                    self.assertNotEqual(res[0].signed_xml.tag, "{http://www.w3.org/2000/09/xmldsig#}Signature")

                # Ensure the signature was returned
                self.assertEqual(res[0].signature_xml.tag, "{http://www.w3.org/2000/09/xmldsig#}Signature")

                if method == methods.enveloping:
                    with self.assertRaisesRegex(InvalidInput, "Unable to resolve reference URI"):
                        XMLVerifier().verify(signed_data, id_attribute="X", **verify_kwargs)

                with self.assertRaisesRegex(InvalidInput, "Expected a X.509 certificate based signature"):
                    XMLVerifier().verify(signed_data, hmac_key=hmac_key, uri_resolver=verify_kwargs.get("uri_resolver"))

                if method != methods.detached:
                    with self.assertRaisesRegex(InvalidSignature, "Digest mismatch"):
                        mangled_sig = signed_data.replace(b"Austria", b"Mongolia").replace(b"x y", b"a b")
                        XMLVerifier().verify(mangled_sig, **verify_kwargs)

                with self.assertRaises(cryptography.exceptions.InvalidSignature):
                    mangled_sig = signed_data.replace(b"<ds:DigestValue>", b"<ds:DigestValue>!")
                    XMLVerifier().verify(mangled_sig, **verify_kwargs)

                with self.assertRaises(cryptography.exceptions.InvalidSignature):
                    sig_value = re.search(b"<ds:SignatureValue>(.+?)</ds:SignatureValue>", signed_data).group(1)
                    mangled_sig = re.sub(
                        b"<ds:SignatureValue>(.+?)</ds:SignatureValue>",
                        b"<ds:SignatureValue>" + b64encode(b64decode(sig_value)[::-1]) + b"</ds:SignatureValue>",
                        signed_data,
                    )
                    XMLVerifier().verify(mangled_sig, **verify_kwargs)

                with self.assertRaises(etree.XMLSyntaxError):
                    XMLVerifier().verify("", hmac_key=hmac_key, require_x509=False)

                if sig_alg == "hmac":
                    with self.assertRaisesRegex(InvalidSignature, "Signature mismatch"):
                        verify_kwargs["hmac_key"] = b"SECRET"
                        XMLVerifier().verify(signed_data, **verify_kwargs)

    def test_x509_certs(self):
        from OpenSSL.crypto import FILETYPE_PEM
        from OpenSSL.crypto import Error as OpenSSLCryptoError
        from OpenSSL.crypto import load_certificate

        tree = etree.parse(self.example_xml_files[0])
        ca_pem_file = os.path.join(os.path.dirname(__file__), "example-ca.pem").encode("utf-8")
        crt, key = self.load_example_keys()
        for hash_alg in "sha1", "sha256":
            for method in methods.enveloped, methods.enveloping:
                print(hash_alg, method)
                data = tree.getroot()
                reset_tree(data, method)
                signer = XMLSigner(method=method, signature_algorithm="rsa-" + hash_alg)
                signed = signer.sign(data, key=key, cert=crt)
                signed_data = etree.tostring(signed)
                XMLVerifier().verify(signed_data, ca_pem_file=ca_pem_file)
                XMLVerifier().verify(signed_data, x509_cert=crt)
                XMLVerifier().verify(signed_data, x509_cert=load_certificate(FILETYPE_PEM, crt))
                XMLVerifier().verify(signed_data, x509_cert=crt, cert_subject_name="*.example.com")

                with self.assertRaises(OpenSSLCryptoError):
                    XMLVerifier().verify(signed_data, x509_cert=crt[::-1])

                with self.assertRaises(InvalidSignature):
                    XMLVerifier().verify(signed_data, x509_cert=crt, cert_subject_name="test")

                with self.assertRaisesRegex(InvalidCertificate, "unable to get local issuer certificate"):
                    XMLVerifier().verify(signed_data)
                # TODO: negative: verify with wrong cert, wrong CA

    def test_xmldsig_interop_examples(self):
        ca_pem_file = os.path.join(os.path.dirname(__file__), "interop", "cacert.pem").encode("utf-8")
        for signature_file in glob(os.path.join(os.path.dirname(__file__), "interop", "*.xml")):
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                with self.assertRaisesRegex(InvalidCertificate, "certificate has expired"):
                    XMLVerifier().verify(fh.read(), ca_pem_file=ca_pem_file)

    def test_xmldsig_interop_TR2012(self):
        def get_x509_cert(**kwargs):
            from cryptography.x509 import load_der_x509_certificate
            from OpenSSL.crypto import X509

            with open(os.path.join(interop_dir, "TR2012", "rsa-cert.der"), "rb") as fh:
                return [X509.from_cryptography(load_der_x509_certificate(fh.read()))]

        signature_files = glob(os.path.join(interop_dir, "TR2012", "signature*.xml"))
        for signature_file in signature_files:
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                try:
                    sig = fh.read()
                    XMLVerifier().verify(
                        sig,
                        require_x509=False,
                        hmac_key="testkey",
                        validate_schema=True,
                        cert_resolver=get_x509_cert if "x509digest" in signature_file else None,
                    )
                    sig.decode("utf-8")
                except Exception as e:
                    if "keyinforeference" in signature_file:
                        print("Unsupported test case:", type(e), e)
                    elif "x509digest" in signature_file:
                        assert isinstance(e, InvalidCertificate)
                    else:
                        raise

    def test_xmldsig_interop(self):
        def resolver(uri):
            if uri == "document.xml":
                with open(os.path.join(interop_dir, "phaos-xmldsig-three", uri), "rb") as fh:
                    return fh.read()
            elif uri == "http://www.ietf.org/rfc/rfc3161.txt":
                with open(os.path.join(os.path.dirname(__file__), "rfc3161.txt"), "rb") as fh:
                    return fh.read()
            return None

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

        def cert_resolver(x509_issuer_name, x509_serial_number, x509_digest):
            with open(os.path.join(interop_dir, "phaos-xmldsig-three", "certs", "rsa-cert.pem")) as fh:
                return [fh.read()]

        signature_files = glob(os.path.join(interop_dir, "*", "signature*.xml"))
        signature_files += glob(os.path.join(interop_dir, "aleksey*", "*.xml"))
        signature_files += glob(os.path.join(interop_dir, "xml-crypto", "*.xml"))
        signature_files += glob(os.path.join(interop_dir, "pyXMLSecurity", "*.xml"))
        for signature_file in signature_files:
            print("Verifying", signature_file)
            with open(signature_file, "rb") as fh:
                try:
                    sig = fh.read()
                    verifier = XMLVerifier()
                    verifier.excise_empty_xmlns_declarations = True
                    verifier.verify(
                        sig,
                        require_x509=False,
                        hmac_key="test" if "phaos" in signature_file else "secret",
                        validate_schema=True,
                        uri_resolver=resolver,
                        x509_cert=get_x509_cert(signature_file),
                        cert_resolver=cert_resolver if "issuer-serial" in signature_file else None,
                        ca_pem_file=get_ca_pem_file(signature_file),
                    )
                    decoded_sig = sig.decode("utf-8")
                    if "HMACOutputLength" in decoded_sig or "bad" in signature_file or "expired" in signature_file:
                        raise BaseException("Expected an exception to occur")
                except Exception as e:
                    unsupported_cases = (
                        "xpath-transform",
                        "xslt-transform",
                        "xpointer",
                        "x509-data-ski",
                        "x509-data-subject-name",
                        "x509data",
                        "signature-x509-ski",
                        "signature-x509-is",
                    )
                    bad_interop_cases = (
                        "signature-big",
                        "enveloping-dsa-x509chain",
                        "enveloping-sha512-hmac-sha512",
                        "enveloping-sha512-rsa-sha512",
                        "enveloping-rsa-x509chain",
                        "enveloping-sha1-rsa-sha1",
                        "enveloping-sha224-rsa-sha224",
                        "enveloping-sha256-rsa-sha256",
                        "enveloping-sha384-rsa-sha384",
                    )
                    if signature_file.endswith("expired-cert.xml") or signature_file.endswith(
                        "wsfederation_metadata.xml"
                    ):  # noqa
                        with self.assertRaisesRegex(InvalidCertificate, "certificate has expired"):
                            raise
                    elif signature_file.endswith("invalid_enveloped_transform.xml"):
                        self.assertIsInstance(e, InvalidSignature)
                        # with self.assertRaisesRegex(ValueError, "Can't remove the root signature node"):
                        #    raise
                    elif "md5" in signature_file or "ripemd160" in signature_file:
                        self.assertIsInstance(e, InvalidInput)
                        # with self.assertRaisesRegex(InvalidInput, "Algorithm .+ is not recognized"):
                        #    raise
                    elif "HMACOutputLength" in sig.decode("utf-8"):
                        self.assertIsInstance(e, (InvalidSignature, InvalidDigest))
                    elif signature_file.endswith("signature-rsa-enveloped-bad-digest-val.xml"):
                        # self.assertIsInstance(e, InvalidDigest)
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
                    elif signature_file.endswith("merlin-xmldsig-twenty-three/signature.xml"):
                        self.assertIsInstance(e, InvalidInput)
                    elif any(x in signature_file for x in unsupported_cases):
                        print("Unsupported test case:", type(e), e)
                    elif any(x in signature_file for x in bad_interop_cases) or "Unable to resolve reference" in str(e):
                        print("Bad interop test case:", type(e), e)
                    elif "certificate has expired" in str(e) and (
                        "signature-dsa" in signature_file or "signature-rsa" in signature_file
                    ):  # noqa
                        print("IGNORED:", type(e), e)
                    elif "TR2012" not in signature_file:
                        raise

    def test_signxml_changing_signature_namespace_prefix(self):
        data = etree.parse(self.example_xml_files[0]).getroot()
        signer = XMLSigner()
        signer.namespaces = dict(digi_sign=namespaces["ds"])
        signed = signer.sign(data, key=self.keys["rsa"])
        signed_data = etree.tostring(signed)
        expected_match = ("<digi_sign:Signature xmlns:" 'digi_sign="%s">') % namespaces["ds"]
        self.assertTrue(re.search(expected_match.encode("ascii"), signed_data))

    def test_signxml_changing_signature_namespace_prefix_to_default(self):
        data = etree.parse(self.example_xml_files[0]).getroot()
        signer = XMLSigner()
        ns = dict()
        ns[None] = namespaces["ds"]
        signer.namespaces = ns
        signed = signer.sign(data, key=self.keys["rsa"])
        signed_data = etree.tostring(signed)
        expected_match = ('<Signature xmlns="%s">') % namespaces["ds"]
        self.assertTrue(re.search(expected_match.encode("ascii"), signed_data))

    def test_elementtree_compat(self):
        data = stdlibElementTree.parse(self.example_xml_files[0]).getroot()
        signer = XMLSigner()
        signer.sign(data, key=self.keys["rsa"])

    def test_reference_uris_and_custom_key_info(self):
        crt, key = self.load_example_keys()

        # Both ID and Id formats. XPath 1 doesn't have case insensitive attribute search
        for d in [
            """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="responseId">
                      <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="assertionId">
                       <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder" />
                      </saml:Assertion>
                     </samlp:Response>""",
            """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Id="responseId">
                      <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xmlns:xs="http://www.w3.org/2001/XMLSchema" Id="assertionId">
                       <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder" />
                      </saml:Assertion>
                      <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xmlns:xs="http://www.w3.org/2001/XMLSchema" Id="assertion2">
                      </saml:Assertion>
                     </samlp:Response>""",
        ]:
            data = etree.fromstring(d)
            reference_uri = ["assertionId", "assertion2"] if "assertion2" in d else "assertionId"
            signed_root = XMLSigner().sign(data, reference_uri=reference_uri, key=key, cert=crt)
            res = XMLVerifier().verify(etree.tostring(signed_root), x509_cert=crt, expect_references=True)
            signed_data_root = res[0].signed_xml
            ref = signed_root.xpath(
                "/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference",
                namespaces={
                    "ds": "http://www.w3.org/2000/09/xmldsig#",
                    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                },
            )
            self.assertEqual("assertionId", ref[0].attrib["URI"][1:])

            self.assertEqual("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion", signed_data_root.tag)

            # Also test with detached signing
            ref_xpath = "/ds:Signature/ds:SignedInfo/ds:Reference"
            signer = XMLSigner(method=methods.detached)
            s = signer.sign(data, reference_uri=reference_uri, key=key, cert=crt)
            self.assertTrue(s.xpath(ref_xpath + "/ds:Transforms", namespaces=namespaces))
            self.assertTrue(s.xpath(ref_xpath + "/ds:DigestMethod", namespaces=namespaces))
            self.assertTrue(s.xpath(ref_xpath + "/ds:DigestValue", namespaces=namespaces))

            self.assertTrue(s.xpath("/ds:Signature/ds:KeyInfo/ds:X509Data", namespaces=namespaces))
            self.assertFalse(s.xpath("/ds:Signature/ds:KeyInfo/ds:KeyValue", namespaces=namespaces))
            s2 = signer.sign(data, reference_uri=reference_uri, key=key, cert=crt, always_add_key_value=True)
            self.assertTrue(s2.xpath("/ds:Signature/ds:KeyInfo/ds:X509Data", namespaces=namespaces))
            self.assertTrue(s2.xpath("/ds:Signature/ds:KeyInfo/ds:KeyValue", namespaces=namespaces))

            # Test setting custom key info
            wsse_ns = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            with open(os.path.join(os.path.dirname(__file__), "wsse_keyinfo.xml")) as fh:
                custom_key_info = etree.fromstring(fh.read())
            s3 = signer.sign(data, reference_uri=reference_uri, key=key, cert=crt, key_info=custom_key_info)
            self.assertTrue(
                s3.xpath(
                    "/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference", namespaces=dict(namespaces, wsse=wsse_ns)
                )
            )

            # Test setting both X509Data and KeyInfo
            s4 = XMLSigner().sign(data, reference_uri=reference_uri, key=key, cert=crt, always_add_key_value=True)
            try:
                XMLVerifier().verify(s4, x509_cert=crt)
            except InvalidSignature as e:
                self.assertIn("Expected to find 1 references, but found 2", str(e))
            expect_refs = etree.tostring(s4).decode().count("<ds:Reference")
            XMLVerifier().verify(s4, x509_cert=crt, ignore_ambiguous_key_info=True, expect_references=expect_refs)

    def test_excision_of_untrusted_comments(self):
        pass  # TODO: test comments excision

    def test_ws_security(self):
        wsse_dir = os.path.join(interop_dir, "ws-security", "ws.js")
        with open(os.path.join(wsse_dir, "examples", "server_public.pem"), "rb") as fh:
            crt = fh.read()
        data = etree.parse(os.path.join(wsse_dir, "test", "unit", "client", "files", "valid wss resp.xml"))
        XMLVerifier().verify(data, x509_cert=crt, validate_schema=False, expect_references=2)

        data = etree.parse(
            os.path.join(wsse_dir, "test", "unit", "client", "files", "invalid wss resp - changed content.xml")
        )
        with self.assertRaisesRegex(InvalidDigest, "Digest mismatch for reference 0"):
            XMLVerifier().verify(data, x509_cert=crt, validate_schema=False, expect_references=2)

    def test_psha1(self):
        from signxml.util import p_sha1

        a, b, c, d = (
            "grrlUUfhuNwlvQzQ4bV6TT3wA8ieZPltIf4+H7nIvCE=",
            "YLABh3ZmZyiO5gvVLZe9J4JPd9w59KGeTFwE85XlzxE=",
            "Wv3QzY84KfgwSkn1z3QV+LXEoo3nPraZPysJYtA3u4c=",
            "g/uYZmYX7rOm/X7UV4usrvjIPCiWMWwNZJL0ejvz6Y4=",
        )
        self.assertEqual(p_sha1(a, b), c)
        self.assertEqual(p_sha1(b, a), d)

    def test_xml_attacks(self):
        for filename in glob(os.path.join(os.path.dirname(__file__), "defusedxml-test-data", "*.xml")):
            with open(filename, "rb") as fh:
                with self.assertRaises((InvalidInput, etree.XMLSyntaxError)):
                    XMLVerifier().verify(fh.read())

    def test_signature_properties_with_detached_method(self):
        doc = etree.Element("Test", attrib={"Id": "mytest"})
        sigprop = etree.Element("{http://somenamespace}MyCustomProperty")
        sigprop.text = "Some Text"
        cert, key = self.load_example_keys()
        signature = XMLSigner(method=methods.detached).sign(
            doc, cert=cert, key=key, reference_uri="#mytest", signature_properties=sigprop
        )
        fulldoc = b"<root>" + etree.tostring(signature) + etree.tostring(doc) + b"</root>"
        XMLVerifier().verify(etree.fromstring(fulldoc), x509_cert=cert, expect_references=2)

    def test_signature_properties_with_detached_method_re_enveloping(self):
        doc = etree.Element("{http://somenamespace}Test", attrib={"Id": "mytest"})
        sigprop = etree.Element("{http://somenamespace}MyCustomProperty")
        sigprop.text = "Some Text"
        cert, key = self.load_example_keys()
        signer = XMLSigner(method=methods.detached, c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
        signer.namespaces["ns0"] = "http://enveloping.namespace"
        signature = signer.sign(doc, cert=cert, key=key, reference_uri="#mytest", signature_properties=sigprop)
        fulldoc = (
            b'<ns0:root xmlns:ns0="http://enveloping.namespace">'
            + etree.tostring(signature)
            + etree.tostring(doc)
            + b"</ns0:root>"
        )
        XMLVerifier().verify(etree.fromstring(fulldoc), x509_cert=cert, expect_references=2)

    def test_payload_c14n(self):
        doc = etree.fromstring('<abc xmlns="http://example.com"><foo xmlns="">bar</foo></abc>')
        self.assertEqual(
            XMLVerifier()._c14n(doc, algorithm=""), b'<abc xmlns="http://example.com"><foo xmlns="">bar</foo></abc>'
        )


class TestXAdES(unittest.TestCase, LoadExampleKeys):
    expect_references = {
        "factura_ejemplo2_32v1.xml": 3,
        "dss1770.xml": 3,
        "xades-fake-counter-signature.xml": 3,
        "Signature-X-SK_DIT-1.xml": 5,
        "Signature-X-HR_FIN-1.xml": 5,
        "TEST_S1a_C1a_InTL_VALID.xml": 3,
        "Signature-X-CZ_SEF-4.xml": 4,
        "Signature-X-FR_NOT-3.xml": 3,
        "Signature-X-CZ_SEF-5.xml": 4,
        "xades-counter-signature-injected.xml": 3,
        "11068_signed.xml": 3,
        "signature_property_signed.xml": 3,
        "nonconformant-Signature-X-ES-100.xml": 3,
        "nonconformant-Signature-X-ES-103.xml": 3,
        "nonconformant-dss1770.xml": 3,
    }
    signature_policy = {
        "Identifier": "urn:sbr:signature-policy:xml:2.0",
        "Description": "Test description",
        "DigestMethod": digest_algorithms.SHA256,
        "DigestValue": "sVHhN1eqNH/PZ1B6h//ehyC1OwRQOrz/tJ3ZYaRrBgA=",
    }
    claimed_roles = ["signer"]
    data_object_format = {"Description": "Important Document", "MimeType": "text/xml"}

    def test_xades_roundtrip(self):
        cert, key = self.load_example_keys()
        with open(os.path.join(os.path.dirname(__file__), "example.xml"), "rb") as fh:
            doc = etree.parse(fh)
        signer = XAdESSigner(
            signature_policy=self.signature_policy,
            claimed_roles=self.claimed_roles,
            data_object_format=self.data_object_format,
        )
        signed_doc = signer.sign(doc, key=key, cert=cert)
        verifier = XAdESVerifier()
        verify_results = verifier.verify(
            signed_doc, x509_cert=cert, expect_references=3, expect_signature_policy=self.signature_policy
        )
        self.assertIsInstance(verify_results[1], XAdESVerifyResult)
        self.assertTrue(hasattr(verify_results[1], "signed_properties"))

    def test_xades_interop_examples(self):
        error_conditions = {
            "altered": InvalidSignature,
            "newlines": InvalidSignature,
            "unsupported-signature-algorithm": InvalidInput,
            "corrupted-cert": etree.DocumentInvalid,  # FIXME - flaky validation
            "cert-v2-wrong-digest": InvalidDigest,
            "wrong-sign-cert-digest": InvalidDigest,
            "nonconformant-X_BE_CONN_10": InvalidDigest,
            "sigPolStore-noDigest": InvalidInput,
        }
        for sig_file in glob(os.path.join(os.path.dirname(__file__), "xades", "*.xml")):
            print("Verifying", sig_file)
            with open(sig_file, "rb") as fh:
                doc = etree.parse(fh)
            cert = doc.find("//{http://www.w3.org/2000/09/xmldsig#}X509Certificate").text
            kwargs = dict(x509_cert=cert, expect_references=self.expect_references.get(os.path.basename(sig_file), 2))
            if "nonconformant" in sig_file:
                kwargs.update(validate_schema=False)
            if "sigPolStore" in sig_file:
                kwargs.update(expect_signature_policy=self.signature_policy)
            for condition, error in error_conditions.items():
                if condition in sig_file:
                    with self.assertRaises(error):
                        XAdESVerifier().verify(doc, **kwargs)
                    break
            else:
                XAdESVerifier().verify(doc, **kwargs)


if __name__ == "__main__":
    unittest.main()
