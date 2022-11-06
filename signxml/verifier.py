from base64 import b64decode
from dataclasses import dataclass
from typing import Callable, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, utils
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import load_der_public_key
from lxml import etree
from OpenSSL.crypto import FILETYPE_PEM, X509
from OpenSSL.crypto import Error as OpenSSLCryptoError
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import verify as openssl_verify

from .algorithms import DigestAlgorithm, SignatureMethod, digest_algorithm_implementations
from .exceptions import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature  # noqa
from .processor import XMLSignatureProcessor
from .util import (
    _remove_sig,
    add_pem_header,
    bits_to_bytes_unit,
    bytes_to_long,
    ds_tag,
    ensure_bytes,
    namespaces,
    verify_x509_cert_chain,
)


@dataclass
class VerifyResult:
    """
    This is a dataclass representing structured data returned by ``signxml.XMLVerifier.verify()``. The results of a
    verification contain the signed bytes, the parsed signed XML, and the parsed signature XML. Example usage:

        verified_data = signxml.XMLVerifier().verify(input_data).signed_xml
    """

    signed_data: bytes
    "The binary data as it was signed"

    signed_xml: Optional[etree._Element]
    "The signed data parsed as XML (or None if parsing failed)"

    signature_xml: etree._Element
    "The signature element parsed as XML"


class XMLVerifier(XMLSignatureProcessor):
    """
    Create a new XML Signature Verifier object, which can be used to hold configuration information and verify multiple
    pieces of data.
    """

    def _get_signature(self, root):
        if root.tag == ds_tag("Signature"):
            return root
        else:
            return self._find(root, "Signature", anywhere=True)

    def _verify_signature_with_pubkey(
        self, signed_info_c14n, raw_signature, key_value, der_encoded_key_value, signature_alg
    ):
        if der_encoded_key_value is not None:
            key = load_der_public_key(b64decode(der_encoded_key_value.text))

        digest_algorithm_implementation = digest_algorithm_implementations[signature_alg]()
        if signature_alg.name.startswith("ECDSA_"):
            if key_value is not None:
                ec_key_value = self._find(key_value, "dsig11:ECKeyValue")
                named_curve = self._find(ec_key_value, "dsig11:NamedCurve")
                public_key = self._find(ec_key_value, "dsig11:PublicKey")
                key_data = b64decode(public_key.text)[1:]
                x = bytes_to_long(key_data[: len(key_data) // 2])
                y = bytes_to_long(key_data[len(key_data) // 2 :])
                curve_class = self.known_ecdsa_curves[named_curve.get("URI")]
                ecpn = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve_class())  # type: ignore
                key = ecpn.public_key()
            elif not isinstance(key, ec.EllipticCurvePublicKey):
                raise InvalidInput("DER encoded key value does not match specified signature algorithm")
            dss_signature = self._encode_dss_signature(raw_signature, key.key_size)
            key.verify(
                dss_signature, data=signed_info_c14n, signature_algorithm=ec.ECDSA(digest_algorithm_implementation)
            )
        elif signature_alg.name.startswith("DSA_"):
            if key_value is not None:
                dsa_key_value = self._find(key_value, "DSAKeyValue")
                p = self._get_long(dsa_key_value, "P")
                q = self._get_long(dsa_key_value, "Q")
                g = self._get_long(dsa_key_value, "G", require=False)
                y = self._get_long(dsa_key_value, "Y")
                dsapn = dsa.DSAPublicNumbers(y=y, parameter_numbers=dsa.DSAParameterNumbers(p=p, q=q, g=g))
                key = dsapn.public_key()  # type: ignore
            elif not isinstance(key, dsa.DSAPublicKey):
                raise InvalidInput("DER encoded key value does not match specified signature algorithm")
            # TODO: supply meaningful key_size_bits for signature length assertion
            dss_signature = self._encode_dss_signature(raw_signature, len(raw_signature) * 8 / 2)
            key.verify(dss_signature, data=signed_info_c14n, algorithm=digest_algorithm_implementation)
        elif signature_alg.name.startswith("RSA_"):
            if key_value is not None:
                rsa_key_value = self._find(key_value, "RSAKeyValue")
                modulus = self._get_long(rsa_key_value, "Modulus")
                exponent = self._get_long(rsa_key_value, "Exponent")
                key = rsa.RSAPublicNumbers(e=exponent, n=modulus).public_key()
            elif not isinstance(key, rsa.RSAPublicKey):
                raise InvalidInput("DER encoded key value does not match specified signature algorithm")
            key.verify(
                raw_signature,
                data=signed_info_c14n,
                padding=PKCS1v15(),
                algorithm=digest_algorithm_implementation,
            )
        else:
            raise NotImplementedError()

    def _encode_dss_signature(self, raw_signature, key_size_bits):
        want_raw_signature_len = bits_to_bytes_unit(key_size_bits) * 2
        if len(raw_signature) != want_raw_signature_len:
            raise InvalidSignature(
                "Expected %d byte SignatureValue, got %d" % (want_raw_signature_len, len(raw_signature))
            )
        int_len = len(raw_signature) // 2
        r = bytes_to_long(raw_signature[:int_len])
        s = bytes_to_long(raw_signature[int_len:])
        return utils.encode_dss_signature(r, s)

    def _get_inclusive_ns_prefixes(self, transform_node):
        inclusive_namespaces = transform_node.find("./ec:InclusiveNamespaces[@PrefixList]", namespaces=namespaces)
        if inclusive_namespaces is None:
            return None
        else:
            return inclusive_namespaces.get("PrefixList").split(" ")

    def _apply_transforms(self, payload, transforms_node, signature, c14n_algorithm):
        transforms, c14n_applied = [], False
        if transforms_node is not None:
            transforms = self._findall(transforms_node, "Transform")

        for transform in transforms:
            if transform.get("Algorithm") == "http://www.w3.org/2000/09/xmldsig#enveloped-signature":
                _remove_sig(signature, idempotent=True)

        for transform in transforms:
            if transform.get("Algorithm") == "http://www.w3.org/2000/09/xmldsig#base64":
                payload = b64decode(payload.text)

        for transform in transforms:
            algorithm = transform.get("Algorithm")
            if algorithm in self.known_c14n_algorithms:
                inclusive_ns_prefixes = self._get_inclusive_ns_prefixes(transform)
                payload = self._c14n(payload, algorithm=algorithm, inclusive_ns_prefixes=inclusive_ns_prefixes)
                c14n_applied = True

        if not c14n_applied and not isinstance(payload, (str, bytes)):
            payload = self._c14n(payload, algorithm=c14n_algorithm)

        return payload

    def verify(
        self,
        data,
        require_x509: bool = True,
        x509_cert: Optional[Union[str, X509]] = None,
        cert_subject_name: Optional[str] = None,
        cert_resolver: Optional[Callable] = None,
        ca_pem_file: Optional[Union[str, bytes]] = None,
        ca_path: Optional[str] = None,
        hmac_key: Optional[str] = None,
        validate_schema: bool = True,
        parser=None,
        uri_resolver: Optional[Callable] = None,
        id_attribute: Optional[str] = None,
        expect_references: Union[int, bool] = 1,
        ignore_ambiguous_key_info: bool = False,
    ) -> List[VerifyResult]:
        """
        Verify the XML signature supplied in the data and return a list of **VerifyResult** data structures
        representing the data signed by the signature, or raise an exception if the signature is not valid. By default,
        this requires the signature to be generated using a valid X.509 certificate. To enable other means of signature
        validation, set the **require_x509** argument to `False`.

        .. admonition:: See what is signed

         It is important to understand and follow the best practice rule of "See what is signed" when verifying XML
         signatures. The gist of this rule is: if your application neglects to verify that the information it trusts is
         what was actually signed, the attacker can supply a valid signature but point you to malicious data that wasn't
         signed by that signature.

         In SignXML, you can ensure that the information signed is what you expect to be signed by only trusting the
         data returned by the ``verify()`` method. The return value is the XML node or string that was signed. Also,
         depending on the canonicalization method used by the signature, comments in the XML data may not be subject to
         signing, so may need to be untrusted. If so, they are excised from the return value of ``verify()``.

         **Recommended reading:** http://www.w3.org/TR/xmldsig-bestpractices/#practices-applications

        .. admonition:: Establish trust

         If you do not supply any keyword arguments to ``verify()``, the default behavior is to trust **any** valid XML
         signature generated using a valid X.509 certificate trusted by your system's CA store. This means anyone can
         get an SSL certificate and generate a signature that you will trust. To establish trust in the signer, use the
         ``x509_cert`` argument to specify a certificate that was pre-shared out-of-band (e.g. via SAML metadata, as
         shown in :ref:`Verifying SAML assertions <verifying-saml-assertions>`), or ``cert_subject_name`` to specify a
         subject name that must be in the signing X.509 certificate given by the signature (verified as if it were a
         domain name), or ``ca_pem_file``/``ca_path`` to give a custom CA.

        :param data: Signature data to verify
        :type data: String, file-like object, or XML ElementTree Element API compatible object
        :param require_x509:
            If ``True``, a valid X.509 certificate-based signature with an established chain of trust is required to
            pass validation. If ``False``, other types of valid signatures (e.g. HMAC or RSA public key) are accepted.
        :param x509_cert:
            A trusted external X.509 certificate, given as a PEM-formatted string or OpenSSL.crypto.X509 object, to use
            for verification. Overrides any X.509 certificate information supplied by the signature. If left set to
            ``None``, requires that the signature supply a valid X.509 certificate chain that validates against the
            known certificate authorities. Implies **require_x509=True**.
        :param cert_subject_name:
            Subject Common Name to check the signing X.509 certificate against. Implies **require_x509=True**.
        :param cert_resolver:
            Function to use to resolve trusted X.509 certificates when X509IssuerSerial and X509Digest references are
            found in the signature. The function is called with the keyword arguments ``x509_issuer_name``,
            ``x509_serial_number`` and ``x509_digest``, and is expected to return an iterable of one or more
            strings containing a PEM-formatted certificate and a chain of intermediate certificates, if needed.
            Implies **require_x509=True**.
        :param ca_pem_file:
            Filename of a PEM file containing certificate authority information to use when verifying certificate-based
            signatures.
        :param ca_path:
            Path to a directory containing PEM-formatted certificate authority files to use when verifying
            certificate-based signatures. If neither **ca_pem_file** nor **ca_path** is given, the Mozilla CA bundle
            provided by :py:mod:`certifi` will be loaded.
        :param hmac_key: If using HMAC, a string containing the shared secret.
        :param validate_schema: Whether to validate **data** against the XML Signature schema.
        :param parser:
            Custom XML parser instance to use when parsing **data**. The default parser arguments used by SignXML are:
            ``resolve_entities=False``. See https://lxml.de/FAQ.html#how-do-i-use-lxml-safely-as-a-web-service-endpoint.
        :type parser: :py:class:`lxml.etree.XMLParser` compatible parser
        :param uri_resolver:
            Function to use to resolve reference URIs that don't start with "#". The function is called with a single
            string argument containing the URI to be resolved, and is expected to return a lxml.etree node or string.
        :param id_attribute:
            Name of the attribute whose value ``URI`` refers to. By default, SignXML will search for "Id", then "ID".
        :param expect_references:
            Number of references to expect in the signature. If this is not 1, an array of VerifyResults is returned.
            If set to a non-integer, any number of references is accepted (otherwise a mismatch raises an error).
        :param ignore_ambiguous_key_info:
            Ignore the presence of a KeyValue element when X509Data is present in the signature and used for verifying.
            The presence of both elements is an ambiguity and a security hazard. The public key used to sign the
            document is already encoded in the certificate (which is in X509Data), so the verifier must either ignore
            KeyValue or make sure it matches what's in the certificate. SignXML does not implement the functionality
            necessary to match the keys, and throws an InvalidInput error instead. Set this to True to bypass the error
            and validate the signature using X509Data only.

        :raises: :py:class:`cryptography.exceptions.InvalidSignature`
        """
        self.hmac_key = hmac_key
        self.require_x509 = require_x509
        self.x509_cert = x509_cert
        self._parser = parser

        if x509_cert or cert_resolver:
            self.require_x509 = True

        if id_attribute is not None:
            self.id_attributes = (id_attribute,)

        root = self.get_root(data)
        signature_ref = self._get_signature(root)

        # HACK: deep copy won't keep root's namespaces
        signature = self.fromstring(self.tostring(signature_ref))

        if validate_schema:
            self.validate_schema(signature)

        signed_info = self._find(signature, "SignedInfo")
        c14n_method = self._find(signed_info, "CanonicalizationMethod")
        c14n_algorithm = c14n_method.get("Algorithm")
        inclusive_ns_prefixes = self._get_inclusive_ns_prefixes(c14n_method)
        signature_method = self._find(signed_info, "SignatureMethod")
        signature_value = self._find(signature, "SignatureValue")
        signature_alg = SignatureMethod(signature_method.get("Algorithm"))
        raw_signature = b64decode(signature_value.text)
        x509_data = signature.find("ds:KeyInfo/ds:X509Data", namespaces=namespaces)
        key_value = signature.find("ds:KeyInfo/ds:KeyValue", namespaces=namespaces)
        der_encoded_key_value = signature.find("ds:KeyInfo/dsig11:DEREncodedKeyValue", namespaces=namespaces)
        signed_info_c14n = self._c14n(
            signed_info, algorithm=c14n_algorithm, inclusive_ns_prefixes=inclusive_ns_prefixes
        )

        if x509_data is not None or self.require_x509:
            if self.x509_cert is None:
                if x509_data is None:
                    raise InvalidInput("Expected a X.509 certificate based signature")
                certs = [cert.text for cert in self._findall(x509_data, "X509Certificate")]
                if len(certs) == 0:
                    x509_iss = x509_data.find("ds:X509IssuerSerial/ds:X509IssuerName", namespaces=namespaces)
                    x509_sn = x509_data.find("ds:X509IssuerSerial/ds:X509SerialNumber", namespaces=namespaces)
                    x509_digest = x509_data.find("dsig11:X509Digest", namespaces=namespaces)
                    if cert_resolver and any(i is not None for i in (x509_iss, x509_sn, x509_digest)):
                        cert_chain = cert_resolver(
                            x509_issuer_name=x509_iss.text if x509_iss is not None else None,
                            x509_serial_number=x509_sn.text if x509_sn is not None else None,
                            x509_digest=x509_digest.text if x509_digest is not None else None,
                        )
                        if len(cert_chain) == 0:
                            raise InvalidCertificate("No certificate found for given X509 data")
                        if not all(isinstance(c, X509) for c in cert_chain):
                            cert_chain = [load_certificate(FILETYPE_PEM, add_pem_header(cert)) for cert in cert_chain]
                    else:
                        msg = "Expected to find an X509Certificate element in the signature"
                        msg += " (X509SubjectName, X509SKI are not supported)"
                        raise InvalidInput(msg)
                else:
                    cert_chain = [load_certificate(FILETYPE_PEM, add_pem_header(cert)) for cert in certs]
                signing_cert = verify_x509_cert_chain(cert_chain, ca_pem_file=ca_pem_file, ca_path=ca_path)
            elif isinstance(self.x509_cert, X509):
                signing_cert = self.x509_cert
            else:
                signing_cert = load_certificate(FILETYPE_PEM, add_pem_header(self.x509_cert))

            if cert_subject_name and signing_cert.get_subject().commonName != cert_subject_name:
                raise InvalidSignature("Certificate subject common name mismatch")

            if signature_alg.name.startswith("ECDSA"):
                raw_signature = self._encode_dss_signature(raw_signature, signing_cert.get_pubkey().bits())
            try:
                digest_alg_name = digest_algorithm_implementations[signature_alg].name  # type: ignore
                openssl_verify(signing_cert, raw_signature, signed_info_c14n, digest_alg_name)
            except OpenSSLCryptoError as e:
                try:
                    lib, func, reason = e.args[0][0]
                except Exception:
                    reason = e
                raise InvalidSignature("Signature verification failed: {}".format(reason))

            # If both X509Data and KeyValue are present, match one against the other and raise an error on mismatch
            if key_value is not None:
                if (
                    self.check_key_value_matches_cert_public_key(key_value, signing_cert.get_pubkey(), signature_alg)
                    is False
                ):
                    if ignore_ambiguous_key_info is False:
                        raise InvalidInput(
                            "Both X509Data and KeyValue found and they represent different public keys. "
                            "Use verify(ignore_ambiguous_key_info=True) to ignore KeyValue and validate "
                            "using X509Data only."
                        )

            # If both X509Data and DEREncodedKeyValue are present, match one against the other and raise an error on
            # mismatch
            if der_encoded_key_value is not None:
                if (
                    self.check_der_key_value_matches_cert_public_key(
                        der_encoded_key_value, signing_cert.get_pubkey(), signature_alg
                    )
                    is False
                ):
                    if ignore_ambiguous_key_info is False:
                        raise InvalidInput(
                            "Both X509Data and DEREncodedKeyValue found and they represent different "
                            "public keys. Use verify(ignore_ambiguous_key_info=True) to ignore "
                            "DEREncodedKeyValue and validate using X509Data only."
                        )

            # TODO: CN verification goes here
            # TODO: require one of the following to be set: either x509_cert or (ca_pem_file or ca_path) or common_name
            # Use ssl.match_hostname or code from it to perform match
        elif signature_alg.name.startswith("HMAC_"):
            if self.hmac_key is None:
                raise InvalidInput('Parameter "hmac_key" is required when verifying a HMAC signature')

            signer = HMAC(key=ensure_bytes(self.hmac_key), algorithm=digest_algorithm_implementations[signature_alg]())
            signer.update(signed_info_c14n)
            if raw_signature != signer.finalize():
                raise InvalidSignature("Signature mismatch (HMAC)")
        else:
            if key_value is None and der_encoded_key_value is None:
                raise InvalidInput("Expected to find either KeyValue or X509Data XML element in KeyInfo")

            self._verify_signature_with_pubkey(
                signed_info_c14n=signed_info_c14n,
                raw_signature=raw_signature,
                key_value=key_value,
                der_encoded_key_value=der_encoded_key_value,
                signature_alg=signature_alg,
            )

        verify_results: List[VerifyResult] = []
        for reference in self._findall(signed_info, "Reference"):
            copied_root = self.fromstring(self.tostring(root))
            copied_signature_ref = self._get_signature(copied_root)
            transforms = self._find(reference, "Transforms", require=False)
            digest_alg = self._find(reference, "DigestMethod").get("Algorithm")
            digest_value = self._find(reference, "DigestValue")
            payload = self._resolve_reference(copied_root, reference, uri_resolver=uri_resolver)
            payload_c14n = self._apply_transforms(payload, transforms, copied_signature_ref, c14n_algorithm)
            if b64decode(digest_value.text) != self._get_digest(payload_c14n, DigestAlgorithm(digest_alg)):
                raise InvalidDigest(f"Digest mismatch for reference {len(verify_results)} ({reference.get('URI')})")

            # We return the signed XML (and only that) to ensure no access to unsigned data happens
            try:
                payload_c14n_xml = self.fromstring(payload_c14n)
            except etree.XMLSyntaxError:
                payload_c14n_xml = None
            verify_results.append(VerifyResult(payload_c14n, payload_c14n_xml, signature))

        if type(expect_references) is int and len(verify_results) != expect_references:
            msg = "Expected to find {} references, but found {}"
            raise InvalidSignature(msg.format(expect_references, len(verify_results)))

        return verify_results

    def validate_schema(self, signature):
        last_exception = None
        for schema in self.schemas():
            try:
                schema.assertValid(signature)
                return
            except Exception as e:
                last_exception = e
        raise last_exception  # type: ignore

    def check_key_value_matches_cert_public_key(self, key_value, public_key, signature_alg: SignatureMethod):
        if signature_alg.name.startswith("ECDSA_") and isinstance(
            public_key.to_cryptography_key(), ec.EllipticCurvePublicKey
        ):
            ec_key_value = self._find(key_value, "dsig11:ECKeyValue")
            named_curve = self._find(ec_key_value, "dsig11:NamedCurve")
            public_key = self._find(ec_key_value, "dsig11:PublicKey")
            key_data = b64decode(public_key.text)[1:]
            x = bytes_to_long(key_data[: len(key_data) // 2])
            y = bytes_to_long(key_data[len(key_data) // 2 :])
            curve_class = self.known_ecdsa_curves[named_curve.get("URI")]

            pubk_curve = public_key.to_cryptography_key().public_numbers().curve
            pubk_x = public_key.to_cryptography_key().public_numbers().x
            pubk_y = public_key.to_cryptography_key().public_numbers().y

            return curve_class == pubk_curve and x == pubk_x and y == pubk_y

        elif signature_alg.name.startswith("DSA_") and isinstance(public_key.to_cryptography_key(), dsa.DSAPublicKey):
            dsa_key_value = self._find(key_value, "DSAKeyValue")
            p = self._get_long(dsa_key_value, "P")
            q = self._get_long(dsa_key_value, "Q")
            g = self._get_long(dsa_key_value, "G", require=False)

            pubk_p = public_key.to_cryptography_key().public_numbers().p
            pubk_q = public_key.to_cryptography_key().public_numbers().q
            pubk_g = public_key.to_cryptography_key().public_numbers().g

            return p == pubk_p and q == pubk_q and g == pubk_g

        elif signature_alg.name.startswith("RSA_") and isinstance(public_key.to_cryptography_key(), rsa.RSAPublicKey):
            rsa_key_value = self._find(key_value, "RSAKeyValue")
            n = self._get_long(rsa_key_value, "Modulus")
            e = self._get_long(rsa_key_value, "Exponent")

            pubk_n = public_key.to_cryptography_key().public_numbers().n
            pubk_e = public_key.to_cryptography_key().public_numbers().e

            return n == pubk_n and e == pubk_e

        raise NotImplementedError()

    def check_der_key_value_matches_cert_public_key(self, der_encoded_key_value, public_key, signature_alg):
        # TODO: Add a test case for this functionality
        der_public_key = load_der_public_key(b64decode(der_encoded_key_value.text))

        if (
            signature_alg.name.startswith("ECDSA_")
            and isinstance(der_public_key, ec.EllipticCurvePublicKey)
            and isinstance(public_key.to_cryptography_key(), ec.EllipticCurvePublicKey)
        ):
            curve_class = der_public_key.public_numbers().curve
            x = der_public_key.public_numbers().x
            y = der_public_key.public_numbers().y

            pubk_curve = public_key.to_cryptography_key().public_numbers().curve
            pubk_x = public_key.to_cryptography_key().public_numbers().x
            pubk_y = public_key.to_cryptography_key().public_numbers().y

            return curve_class == pubk_curve and x == pubk_x and y == pubk_y

        elif (
            signature_alg.name.startswith("DSA_")
            and isinstance(der_public_key, dsa.DSAPublicKey)
            and isinstance(public_key.to_cryptography_key(), dsa.DSAPublicKey)
        ):
            p = der_public_key.public_numbers().parameter_numbers().p  # type: ignore
            q = der_public_key.public_numbers().parameter_numbers().q  # type: ignore
            g = der_public_key.public_numbers().parameter_numbers().g  # type: ignore

            pubk_p = public_key.to_cryptography_key().public_numbers().p
            pubk_q = public_key.to_cryptography_key().public_numbers().q
            pubk_g = public_key.to_cryptography_key().public_numbers().g

            return p == pubk_p and q == pubk_q and g == pubk_g

        elif (
            signature_alg.name.startswith("RSA_")
            and isinstance(der_public_key, rsa.RSAPublicKey)
            and isinstance(public_key.to_cryptography_key(), rsa.RSAPublicKey)
        ):
            n = der_public_key.public_numbers().n
            e = der_public_key.public_numbers().e

            pubk_n = public_key.to_cryptography_key().public_numbers().n
            pubk_e = public_key.to_cryptography_key().public_numbers().e

            return n == pubk_n and e == pubk_e

        raise NotImplementedError()

    def _get_long(self, element, query, require=True):
        result = self._find(element, query, require=require)
        if result is not None:
            result = bytes_to_long(b64decode(result.text))
        return result
