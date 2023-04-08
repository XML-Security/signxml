"""
Signature and digest algorithms supported by XAdES are described in ETSI TS 119 312.
Digest algorithms:
- SHA-224 FIPS Publication 180-4
- SHA-256 FIPS Publication 180-4
- SHA-384 FIPS Publication 180-4
- SHA-512 FIPS Publication 180-4
- SHA-512/256 FIPS Publication 180-4
- SHA3-256 FIPS Publication 202
- SHA3-384 FIPS Publication 202
- SHA3-512 FIPS Publication 202
Signature algorithms:
- RSA-PKCS#1v1_5 IETF RFC 3447
- RSA-PSS IETF RFC 3447
- DSA (FF-DLOG DSA) FIPS Publication 186-4 [2], ISO/IEC 14888-3
- EC-DSA (EC-DLOG EC-DSA) FIPS Publication 186-4
- EC-SDSA-opt (EC-DLOG EC-Schnorr) ISO/IEC 14888-3
We do not yet support all of them here (issue 206 tracks the implementation of RFC 6931 identifiers required for that).
The main difference with plain XML Signature is that HMAC algorithms are not supported, and SHA1 is deprecated.
"""

import datetime
import os
import secrets
from base64 import b64decode, b64encode
from dataclasses import astuple, dataclass
from functools import wraps
from typing import Dict, List, Optional, Union

from lxml.etree import SubElement, _Element
from OpenSSL.crypto import FILETYPE_ASN1, FILETYPE_PEM, X509, dump_certificate, load_certificate

from .. import SignatureConfiguration, VerifyResult, XMLSignatureProcessor, XMLSigner, XMLVerifier
from ..algorithms import DigestAlgorithm
from ..exceptions import InvalidDigest, InvalidInput
from ..util import SigningSettings, add_pem_header, ds_tag, namespaces, xades_tag


@dataclass(frozen=True)
class XAdESSignatureConfiguration(SignatureConfiguration):
    """
    A subclass of :class:`signxml.SignatureConfiguration`, with default overrides as described below.
    """

    expect_references: Union[int, bool] = 3
    """
    By default, XAdES signatures carry 3 references (the original data reference, the KeyInfo (X.509 certificate)
    reference, and the signed properties reference). Signatures can carry more references if more data or extensions
    are present. Specify the expected number of references here.
    """


@dataclass(frozen=True)
class XAdESSignaturePolicy:
    Identifier: str
    Description: str
    DigestMethod: DigestAlgorithm
    DigestValue: str


@dataclass(frozen=True)
class XAdESDataObjectFormat:
    Description: str = "Default XAdES payload description"
    MimeType: str = "text/xml"


@dataclass(frozen=True)
class XAdESVerifyResult(VerifyResult):
    """
    A subclass of :class:`signxml.VerifyResult`. See VerifyResult for attribute semantics not covered here.
    """

    signed_properties: _Element
    "The XAdES SignedProperties element that was verified as signed by the signature"


class XAdESProcessor(XMLSignatureProcessor):
    schema_files = ["XAdESv141.xsd", "XAdES01903v141-201601.xsd", "XAdES01903v141-201506.xsd"]
    _schema_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "schemas"))


class XAdESSigner(XAdESProcessor, XMLSigner):
    """
    Create a new XAdES Signature Signer object, which can be used to hold configuration information and sign multiple
    pieces of data. This is a subclass of :class:`signxml.XMLSigner`; all of its configuration semantics are supported.

    :param signature_policy:
        If you need your XAdES signature to carry the **SignaturePolicyIdentifier** element, use this parameter to pass
        a :class:`XAdESSignaturePolicy` object carrying strings and the digest method identifier for the element.
    :param claimed_roles:
        If you need your XAdES signature to carry the **SignerRole/ClaimedRoles** element, use this parameter to pass a
        list of strings to use as text for the **ClaimedRole** tags.
    :param data_object_format:
        If you need your XAdES signature to carry the **DataObjectFormat** element, use this parameter to pass a
        :class:`XAdESDataObjectFormat` object carrying the Description and MimeType strings for the element.
    :param xml_signer_args:
        Parameters to pass to the :class:`signxml.XMLSigner` constructor.
    """

    def __init__(
        self,
        signature_policy: Optional[XAdESSignaturePolicy] = None,
        claimed_roles: Optional[List] = None,
        data_object_format: Optional[XAdESDataObjectFormat] = None,
        **xml_signer_args,
    ) -> None:
        super().__init__(**xml_signer_args)
        if self.sign_alg.name.startswith("HMAC_"):
            raise Exception("HMAC signatures are not supported by XAdES")
        self.signature_annotators.append(self._build_xades_ds_object)
        self._tokens_used: Dict[str, bool] = {}
        self.signed_signature_properties_annotators = [
            self.add_signing_time,
            self.add_signing_certificate,
            self.add_signature_policy_identifier,
            self.add_signature_production_place,
            self.add_signer_role,
        ]
        self.signed_data_object_properties_annotators = [
            self.add_data_object_format,
        ]
        self.signature_policy = signature_policy
        self.claimed_roles = claimed_roles
        if data_object_format is None:
            data_object_format = XAdESDataObjectFormat()
        self.data_object_format = data_object_format
        self.namespaces.update(xades=namespaces.xades)

    @wraps(XMLSigner.sign)
    def sign(self, data, always_add_key_value: bool = True, **kwargs) -> _Element:  # type: ignore
        return super().sign(data=data, always_add_key_value=always_add_key_value, **kwargs)

    def _get_token(self, length=4):
        for _ in range(9000):
            token = secrets.token_hex(length).upper()
            if token in self._tokens_used:
                continue
            self._tokens_used[token] = True
            return token

    def _build_xades_ds_object(self, sig_root, signing_settings: SigningSettings):
        ds_object = SubElement(sig_root, ds_tag("Object"), nsmap=self.namespaces)
        sig_root.append(ds_object)
        if "Id" not in sig_root.keys():
            sig_root.set("Id", f"SignXMLSignature{self._get_token()}")
        key_info = self._find(sig_root, "KeyInfo")
        if "Id" not in key_info.keys():
            key_info.set("Id", f"SignXMLCertificate{self._get_token()}")

        qualifying_properties = SubElement(
            ds_object, xades_tag("QualifyingProperties"), nsmap=self.namespaces, Target=f"#{sig_root.get('Id')}"
        )
        signed_properties = SubElement(
            qualifying_properties,
            xades_tag("SignedProperties"),
            nsmap=self.namespaces,
            Id=f"{sig_root.get('Id')}-SignedProperties{self._get_token()}",
        )
        signed_signature_properties = SubElement(
            signed_properties, xades_tag("SignedSignatureProperties"), nsmap=self.namespaces
        )
        for ssp_annotator in self.signed_signature_properties_annotators:
            ssp_annotator(signed_signature_properties, sig_root=sig_root, signing_settings=signing_settings)
        signed_data_object_properties = SubElement(
            signed_properties, xades_tag("SignedDataObjectProperties"), nsmap=self.namespaces
        )
        for dop_annotator in self.signed_data_object_properties_annotators:
            dop_annotator(signed_data_object_properties, sig_root=sig_root, signing_settings=signing_settings)
        self._add_reference_to_signed_info(sig_root, signed_properties, Type="http://uri.etsi.org/01903#SignedProperties")
        self._add_reference_to_signed_info(sig_root, key_info)

    def _add_reference_to_signed_info(self, sig_root, node_to_reference, **attrs):
        signed_info = self._find(sig_root, "SignedInfo")
        reference = SubElement(signed_info, ds_tag("Reference"), nsmap=self.namespaces)
        reference.set("URI", f"#{node_to_reference.get('Id')}")
        for attr_name, attr_value in attrs.items():
            reference.set(attr_name, attr_value)
        SubElement(reference, ds_tag("DigestMethod"), nsmap=self.namespaces, Algorithm=self.digest_alg.value)
        digest_value_node = SubElement(reference, ds_tag("DigestValue"), nsmap=self.namespaces)
        node_to_reference_c14n = self._c14n(node_to_reference, algorithm=self.c14n_alg)
        digest = self._get_digest(node_to_reference_c14n, algorithm=self.digest_alg)
        digest_value_node.text = b64encode(digest).decode()

    def add_signing_time(self, signed_signature_properties, sig_root, signing_settings: SigningSettings):
        signing_time = SubElement(signed_signature_properties, xades_tag("SigningTime"), nsmap=self.namespaces)
        # TODO: make configurable
        utc_iso_ts = datetime.datetime.utcnow().isoformat(timespec="seconds")
        signing_time.text = f"{utc_iso_ts}+00:00"

    def add_signing_certificate(self, signed_signature_properties, sig_root, signing_settings: SigningSettings):
        # TODO: check if we need to support SigningCertificate
        signing_cert_v2 = SubElement(
            signed_signature_properties, xades_tag("SigningCertificateV2"), nsmap=self.namespaces
        )
        for cert in signing_settings.cert_chain:  # type: ignore
            if isinstance(cert, X509):
                loaded_cert = cert
            else:
                loaded_cert = load_certificate(FILETYPE_PEM, add_pem_header(cert))
            der_encoded_cert = dump_certificate(FILETYPE_ASN1, loaded_cert)
            cert_digest_bytes = self._get_digest(der_encoded_cert, algorithm=self.digest_alg)
            cert_node = SubElement(signing_cert_v2, xades_tag("Cert"), nsmap=self.namespaces)
            cert_digest = SubElement(cert_node, xades_tag("CertDigest"), nsmap=self.namespaces)
            SubElement(cert_digest, ds_tag("DigestMethod"), nsmap=self.namespaces, Algorithm=self.digest_alg.value)
            digest_value_node = SubElement(cert_digest, ds_tag("DigestValue"), nsmap=self.namespaces)
            digest_value_node.text = b64encode(cert_digest_bytes).decode()

            # issuer_serial_number = loaded_cert.get_serial_number()
            # issuer_serial_bytes = long_to_bytes(issuer_serial_number)
            # issuer_serial_v2 = SubElement(cert_node, xades_tag("IssuerSerialV2"), nsmap=self.namespaces)
            # issuer_serial_v2.text = b64encode(issuer_serial_bytes).decode()

    def add_signature_policy_identifier(self, signed_signature_properties, sig_root, signing_settings: SigningSettings):
        if self.signature_policy is not None:
            signature_policy_identifier = SubElement(
                signed_signature_properties, xades_tag("SignaturePolicyIdentifier"), nsmap=self.namespaces
            )
            signature_policy_id = SubElement(
                signature_policy_identifier, xades_tag("SignaturePolicyId"), nsmap=self.namespaces
            )
            sig_policy_id = SubElement(signature_policy_id, xades_tag("SigPolicyId"), nsmap=self.namespaces)
            identifier = SubElement(sig_policy_id, xades_tag("Identifier"), nsmap=self.namespaces)
            identifier.text = self.signature_policy.Identifier
            description = SubElement(sig_policy_id, xades_tag("Description"), nsmap=self.namespaces)
            description.text = self.signature_policy.Description
            sig_policy_hash = SubElement(signature_policy_id, xades_tag("SigPolicyHash"), nsmap=self.namespaces)
            digest_alg = DigestAlgorithm(self.signature_policy.DigestMethod)
            SubElement(sig_policy_hash, ds_tag("DigestMethod"), nsmap=self.namespaces, Algorithm=digest_alg.value)
            digest_value_node = SubElement(sig_policy_hash, ds_tag("DigestValue"), nsmap=self.namespaces)
            digest_value_node.text = self.signature_policy.DigestValue

    def add_signature_production_place(self, signed_signature_properties, sig_root, signing_settings: SigningSettings):
        # SignatureProductionPlace or SignatureProductionPlaceV2
        pass

    def add_signer_role(self, signed_signature_properties, sig_root, signing_settings: SigningSettings):
        # SignerRole or SignerRoleV2
        if not self.claimed_roles:
            return
        signer_role = SubElement(signed_signature_properties, xades_tag("SignerRole"), nsmap=self.namespaces)
        claimed_roles = SubElement(signer_role, xades_tag("ClaimedRoles"), nsmap=self.namespaces)
        for claimed_role in self.claimed_roles:
            claimed_role_node = SubElement(claimed_roles, xades_tag("ClaimedRole"), nsmap=self.namespaces)
            claimed_role_node.text = claimed_role

    def add_data_object_format(self, signed_data_object_properties, sig_root, signing_settings: SigningSettings):
        signed_info = self._find(sig_root, "ds:SignedInfo")
        reference = self._find(signed_info, "ds:Reference")
        if "Id" not in reference.keys():
            reference.set("Id", f"SignXMLReference{self._get_token()}")
        data_object_format = SubElement(
            signed_data_object_properties,
            xades_tag("DataObjectFormat"),
            nsmap=self.namespaces,
            ObjectReference=f"#{reference.get('Id')}",
        )
        description = SubElement(data_object_format, xades_tag("Description"), nsmap=self.namespaces)
        description.text = self.data_object_format.Description
        mime_type = SubElement(data_object_format, xades_tag("MimeType"), nsmap=self.namespaces)
        mime_type.text = self.data_object_format.MimeType


class XAdESVerifier(XAdESProcessor, XMLVerifier):
    """
    Create a new XAdES Signature Verifier object, which can be used to verify multiple pieces of data.
    """

    # TODO: document/support SignatureTimeStamp / timestamp attestation
    # SignatureTimeStamp is required by certain profiles but is an unsigned property
    def _verify_signing_time(self, verify_result: VerifyResult):
        pass

    def _verify_cert_digest(self, signing_cert_node, expect_cert):
        for cert in self._findall(signing_cert_node, "xades:Cert"):
            cert_digest = self._find(cert, "xades:CertDigest")
            digest_alg = DigestAlgorithm(self._find(cert_digest, "DigestMethod").get("Algorithm"))
            digest_value = self._find(cert_digest, "DigestValue")
            # check spec for specific method of retrieving cert
            der_encoded_cert = dump_certificate(FILETYPE_ASN1, expect_cert)

            if b64decode(digest_value.text) != self._get_digest(der_encoded_cert, algorithm=digest_alg):
                raise InvalidDigest("Digest mismatch for certificate digest")

    def _verify_cert_digests(self, verify_result: VerifyResult):
        x509_data = verify_result.signature_xml.find("ds:KeyInfo/ds:X509Data", namespaces=namespaces)
        cert_from_key_info = load_certificate(
            FILETYPE_PEM, add_pem_header(self._find(x509_data, "X509Certificate").text)
        )
        signed_signature_props = self._find(verify_result.signed_xml, "xades:SignedSignatureProperties")
        signing_cert = self._find(signed_signature_props, "xades:SigningCertificate", require=False)
        signing_cert_v2 = self._find(signed_signature_props, "xades:SigningCertificateV2", require=False)
        if signing_cert is None and signing_cert_v2 is None:
            raise InvalidInput("Expected to find XML element xades:SigningCertificate or xades:SigningCertificateV2")
        if signing_cert is not None and signing_cert_v2 is not None:
            raise InvalidInput("Expected to find exactly one of xades:SigningCertificate or xades:SigningCertificateV2")
        if signing_cert is not None:
            self._verify_cert_digest(signing_cert, expect_cert=cert_from_key_info)
        elif signing_cert_v2 is not None:
            self._verify_cert_digest(signing_cert_v2, expect_cert=cert_from_key_info)

    def _verify_signature_policy(self, verify_result: VerifyResult, expect_signature_policy: XAdESSignaturePolicy):
        signed_signature_props = self._find(verify_result.signed_xml, "xades:SignedSignatureProperties")
        signature_policy_id = signed_signature_props.find(
            "xades:SignaturePolicyIdentifier/xades:SignaturePolicyId", namespaces=namespaces
        )
        if signature_policy_id is not None:
            sig_policy_id = self._find(signature_policy_id, "xades:SigPolicyId")
            identifier = self._find(sig_policy_id, "xades:Identifier")
            if identifier.text != expect_signature_policy.Identifier:
                raise InvalidInput(
                    f"Expected to find signature policy identifier {expect_signature_policy.Identifier}, "
                    f"but found {identifier.text}"
                )
            sig_policy_hash = self._find(signature_policy_id, "xades:SigPolicyHash")
            digest_alg = DigestAlgorithm(self._find(sig_policy_hash, "DigestMethod").get("Algorithm"))
            if digest_alg != expect_signature_policy.DigestMethod:
                raise InvalidInput(
                    f"Expected to find signature digest algorithm {expect_signature_policy.DigestMethod}, "
                    f"but found {digest_alg}"
                )
            digest_value = self._find(sig_policy_hash, "DigestValue")
            if b64decode(digest_value.text) != b64decode(expect_signature_policy.DigestValue):
                raise InvalidInput("Digest mismatch for signature policy hash")

    def _verify_signed_properties(self, verify_result):
        self._verify_signing_time(verify_result)
        self._verify_cert_digests(verify_result)
        if self.expect_signature_policy:
            self._verify_signature_policy(
                verify_result=verify_result, expect_signature_policy=self.expect_signature_policy
            )
        return self._find(verify_result.signed_xml, "xades:SignedSignatureProperties")

    def verify(  # type: ignore
        self,
        data,
        *,
        expect_signature_policy: Optional[XAdESSignaturePolicy] = None,
        expect_config: XAdESSignatureConfiguration = XAdESSignatureConfiguration(),
        **xml_verifier_args,
    ) -> List[XAdESVerifyResult]:
        """
        Verify the XAdES signature supplied in the data and return a list of :class:`XAdESVerifyResult` data structures
        representing the data signed by the signature, or raise an exception if the signature is not valid. This method
        is a wrapper around :meth:`signxml.XMLVerifier.verify`; see its documentation for more details and arguments it
        supports.

        :param expect_signature_policy:
            If you need to assert that the verified XAdES signature carries specific data in the
            **SignaturePolicyIdentifier** element, use this parameter to pass a :class:`XAdESSignaturePolicy` object
            carrying strings and the digest method identifier for the element.
        :param expect_config:
            Expected signature configuration. Pass a :class:`XAdESSignatureConfiguration` object to describe expected
            properties of the verified signature. Signatures with unexpected configurations will fail validation.
        :param xml_verifier_args:
            Parameters to pass to :meth:`signxml.XMLVerifier.verify`.
        """
        self.expect_signature_policy = expect_signature_policy
        if expect_config.require_x509 is not True:
            raise InvalidInput("XAdES signatures require X509")
        verify_results = super().verify(data, expect_config=expect_config, **xml_verifier_args)
        if not isinstance(verify_results, list):
            raise InvalidInput("Expected to find multiple references in signature")
        for i, verify_result in enumerate(verify_results):
            if verify_result.signed_xml is None:
                continue
            if verify_result.signed_xml.tag == xades_tag("SignedProperties"):
                verify_results[i] = XAdESVerifyResult(  # type: ignore
                    *astuple(verify_result), signed_properties=self._verify_signed_properties(verify_result)
                )
                break
        else:
            raise InvalidInput("Expected to find a xades:SignedProperties element")

        # TODO: assert all mandatory signed properties are set
        return verify_results  # type: ignore
