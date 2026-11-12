"""Modernized xmlsec vectors; unsupported features are reported as skips."""

import sys
import unittest
from base64 import b64decode
from functools import partial
from pathlib import Path
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from lxml import etree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from signxml import (
    CanonicalizationMethod,
    InvalidInput,
    InvalidSignature,
    SignatureConfiguration,
    XMLVerifier,
    namespaces,
)

_fixtures = Path(__file__).parent / "interop-modern"
_transforms = {method.value for method in CanonicalizationMethod} | {
    namespaces.ds + "base64",
    namespaces.ds + "enveloped-signature",
}


def _resolve_uri(uri, folder):
    external = {
        "http://www.w3.org/TR/xml-stylesheet": "xml-stylesheet-2005",
        "http://www.w3.org/Signature/2002/04/xml-stylesheet.b64": "xml-stylesheet-2005.b64",
        "http://www.ietf.org/rfc/rfc3161.txt": "rfc3161.txt",
    }
    path = _fixtures / external[uri] if uri in external else folder / uri
    if path.resolve().is_relative_to(_fixtures.resolve()) and path.is_file():
        return path.read_bytes()
    raise ValueError(f"Unmapped fixture URI: {uri}")


class TestModernInterop(unittest.TestCase):
    def test_vectors(self):
        paths = sorted(_fixtures.glob("*.modern/signature*.xml"))
        self.assertEqual(len(paths), 74)
        checked = 0
        for path in paths:
            with self.subTest(vector=str(path.relative_to(_fixtures))):
                root = etree.fromstring(path.read_bytes(), etree.XMLParser(resolve_entities=False, no_network=True))
                signature = next(root.iter(f"{{{namespaces.ds}}}Signature"))
                if list(root.iter(f"{{{namespaces.ds}}}Manifest")):
                    self.skipTest("Manifest references are not supported")
                if set(root.xpath("//ds:Transform/@Algorithm", namespaces=namespaces)) - _transforms:
                    self.skipTest("XPath/XSLT transforms are not supported")
                certs = [
                    x509.load_der_x509_certificate(b64decode(node.text))
                    for node in signature.findall("ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces)
                ]
                # The upstream chains put the signing certificate first (it also asserts CA=true).
                cert = certs[0] if certs else None
                kwargs = {"uri_resolver": partial(_resolve_uri, folder=path.parent)}
                digest = signature.find("ds:KeyInfo/ds:X509Data/dsig11:X509Digest", namespaces)
                if digest is not None:
                    cert_path = _fixtures / "rsa-4096-cert.pem"
                    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                    self.assertEqual(b64decode(digest.text), cert.fingerprint(hashes.SHA256()))
                    kwargs.update(
                        cert_resolver=Mock(return_value=[cert]),
                        ca_pem_file=str(cert_path),
                        ee_policy=x509.verification.ExtensionPolicy.permit_all(),
                    )
                elif cert is not None:
                    kwargs["x509_cert"] = cert
                elif "hmac-" in signature.find("ds:SignedInfo/ds:SignatureMethod", namespaces).get("Algorithm"):
                    kwargs["hmac_key"] = b"secret"
                elif (
                    signature.find("ds:KeyInfo/ds:KeyValue", namespaces) is None
                    and signature.find("ds:KeyInfo/dsig11:DEREncodedKeyValue", namespaces) is None
                ):
                    self.skipTest(
                        "KeyName, RetrievalMethod, KeyInfoReference and external certificate lookup are not supported here"
                    )
                config = SignatureConfiguration(
                    require_x509=False,
                    expect_references=len(signature.findall("ds:SignedInfo/ds:Reference", namespaces)),
                    verification_time=(
                        cert.not_valid_before_utc + (cert.not_valid_after_utc - cert.not_valid_before_utc) / 2
                    )
                    if cert is not None
                    else None,
                )
                verifier = XMLVerifier()
                verify = partial(verifier.verify, root, expect_config=config, **kwargs)
                if signature.find("ds:SignedInfo/ds:SignatureMethod/ds:HMACOutputLength", namespaces) is not None:
                    with self.assertRaises((InvalidInput, InvalidSignature)):
                        verify()
                elif "bad-" in path.name:
                    with self.assertRaises(InvalidSignature):
                        verify()
                else:
                    verify()
                if digest is not None:
                    kwargs["cert_resolver"].assert_called_once_with(
                        x509_issuer_name=None, x509_serial_number=None, x509_digest=digest.text
                    )
                checked += 1
        self.assertEqual(checked, 52)


if __name__ == "__main__":
    unittest.main()
