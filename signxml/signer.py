from base64 import b64encode
from dataclasses import dataclass, replace
from typing import List, Optional, Union

from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, utils
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS, PKCS1v15
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from lxml.etree import Element, SubElement, _Element
from OpenSSL.crypto import FILETYPE_PEM, X509, dump_certificate

from .algorithms import (
    CanonicalizationMethod,
    DigestAlgorithm,
    SignatureConstructionMethod,
    SignatureMethod,
    digest_algorithm_implementations,
)
from .exceptions import InvalidInput
from .processor import XMLSignatureProcessor
from .util import (
    SigningSettings,
    _remove_sig,
    bits_to_bytes_unit,
    ds_tag,
    dsig11_tag,
    ec_tag,
    ensure_bytes,
    iterate_pem,
    long_to_bytes,
    namespaces,
    strip_pem_header,
)


@dataclass(frozen=True)
class SignatureReference:
    """
    A container representing a signature reference (pointer to data covered by the signature). A signature can include
    one or more references. The integrity of each reference is attested by including the digest (hash) of its value.
    """

    URI: str
    """
    The reference URI, for example ``#elementId`` to refer to an element whose Id attribute is set to ``elementId``.
    """

    c14n_method: Optional[CanonicalizationMethod] = None
    """
    Use this parameter to set a canonicalization method for the reference value that is distinct from that for the
    signature itself.
    """

    inclusive_ns_prefixes: Optional[List] = None
    """
    When using exclusive XML canonicalization, use this parameter to provide a list of XML namespace prefixes whose
    declarations should be preserved when canonicalizing the reference value (**InclusiveNamespaces PrefixList**).
    """


class XMLSigner(XMLSignatureProcessor):
    """
    Create a new XML Signature Signer object, which can be used to hold configuration information and sign multiple
    pieces of data.

    :param method:
        ``signxml.methods.enveloped``, ``signxml.methods.enveloping``, or ``signxml.methods.detached``. See
        :class:`SignatureConstructionMethod` for details.
    :param signature_algorithm:
        Algorithm that will be used to generate the signature. See :class:`SignatureMethod` for the list of algorithm
        IDs supported.
    :param digest_algorithm:
        Algorithm that will be used to hash the data during signature generation. See :class:`DigestAlgorithm` for the
        list of algorithm IDs supported.
    :param c14n_algorithm:
        Algorithm that will be used to canonicalize (serialize in a reproducible way) the XML that is signed. See
        :class:`CanonicalizationMethod` for the list of algorithm IDs supported.
    """

    signature_annotators: List
    """
    A list of callables that will be called at signature creation time to annotate the content to be signed before
    signing. You can use this to register a custom signature decorator as follows:

    .. code-block:: python

        def my_annotator(sig_root, signing_settings):
            ...
            sig_root.append(my_custom_node)

        signer = XMLSigner()
        signer.signature_annotators.append(my_annotator)
        signed = signer.sign(data, ...)
    """

    def __init__(
        self,
        method: SignatureConstructionMethod = SignatureConstructionMethod.enveloped,
        signature_algorithm: Union[SignatureMethod, str] = SignatureMethod.RSA_SHA256,
        digest_algorithm: Union[DigestAlgorithm, str] = DigestAlgorithm.SHA256,
        c14n_algorithm: Union[CanonicalizationMethod, str] = CanonicalizationMethod.CANONICAL_XML_1_1,
    ):
        if method is None or method not in SignatureConstructionMethod:
            raise InvalidInput(f"Unknown signature construction method {method}")
        self.construction_method = method
        if isinstance(signature_algorithm, str) and "#" not in signature_algorithm:
            self.sign_alg = SignatureMethod.from_fragment(signature_algorithm)
        else:
            self.sign_alg = SignatureMethod(signature_algorithm)
        if isinstance(digest_algorithm, str) and "#" not in digest_algorithm:
            self.digest_alg = DigestAlgorithm.from_fragment(digest_algorithm)
        else:
            self.digest_alg = DigestAlgorithm(digest_algorithm)
        self.check_deprecated_methods()
        self.c14n_alg = CanonicalizationMethod(c14n_algorithm)
        self.namespaces = dict(ds=namespaces.ds)
        self._parser = None
        self.signature_annotators = [self._add_key_info]

    def check_deprecated_methods(self):
        if "SHA1" in self.sign_alg.name or "SHA1" in self.digest_alg.name:
            msg = "SHA1-based algorithms are not supported in the default configuration because they are not secure"
            raise InvalidInput(msg)

    def sign(
        self,
        data,
        *,
        key: Optional[Union[str, bytes, rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]] = None,
        passphrase: Optional[bytes] = None,
        cert: Optional[Union[str, List[str], List[X509]]] = None,
        reference_uri: Optional[Union[str, List[str], List[SignatureReference]]] = None,
        key_name: Optional[str] = None,
        key_info: Optional[_Element] = None,
        id_attribute: Optional[str] = None,
        always_add_key_value: bool = False,
        inclusive_ns_prefixes: Optional[List[str]] = None,
        signature_properties: Optional[Union[_Element, List[_Element]]] = None,
    ) -> _Element:
        """
        Sign the data and return the root element of the resulting XML tree.

        :param data: Data to sign
        :type data: String, file-like object, or XML ElementTree Element API compatible object
        :param key:
            Key to be used for signing. When signing with a certificate or RSA/DSA/ECDSA key, this can be a string/bytes
            containing a PEM-formatted key, or a :class:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
            :class:`cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`, or
            :class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey` object. When signing with a
            HMAC, this should be a string containing the shared secret.
        :param passphrase: Passphrase to use to decrypt the key, if any.
        :param cert:
            X.509 certificate to use for signing. This should be a string containing a PEM-formatted certificate, or an
            array of strings or :class:`OpenSSL.crypto.X509` objects containing the certificate and a chain of
            intermediate certificates.
        :param reference_uri:
            Custom reference URI or list of reference URIs to incorporate into the signature. When ``method`` is set to
            ``detached`` or ``enveloped``, reference URIs are set to this value and only the referenced elements are
            signed. To specify extra options specific to each reference URI, pass a list of one or more
            :class:`SignatureReference` objects.
        :param key_name: Add a KeyName element in the KeyInfo element that may be used by the signer to communicate a
            key identifier to the recipient. Typically, KeyName contains an identifier related to the key pair used to
            sign the message.
        :param key_info:
            A custom KeyInfo element to insert in the signature. Use this to supply ``<wsse:SecurityTokenReference>``
            or other custom key references. An example value can be found here:
            https://github.com/XML-Security/signxml/blob/master/test/wsse_keyinfo.xml
        :param id_attribute:
            Name of the attribute whose value ``URI`` refers to. By default, SignXML will search for "Id", then "ID".
        :param always_add_key_value:
            Write the key value to the KeyInfo element even if a X509 certificate is present. Use of this parameter
            is discouraged, as it introduces an ambiguity and a security hazard. The public key used to sign the
            document is already encoded in the certificate (which is in X509Data), so the verifier must either ignore
            KeyValue or make sure it matches what's in the certificate. This parameter is provided for compatibility
            purposes only.
        :param inclusive_ns_prefixes:
            Provide a list of XML namespace prefixes whose declarations should be preserved when canonicalizing the
            signature (**InclusiveNamespaces PrefixList**).

            To specify this value separately for reference canonicalizaition, pass a list of one or more
            :class:`SignatureReference` objects as the ``reference_uri`` keyword argument, and set the
            ``inclusive_ns_prefixes`` attribute on those objects.
        :param signature_properties:
            One or more Elements that are to be included in the SignatureProperies section when using the detached
            method.

        :returns:
            A :class:`lxml.etree._Element` object representing the root of the XML tree containing the signature and
            the payload data.

        To specify the location of an enveloped signature within **data**, insert a
        ``<ds:Signature Id="placeholder"></ds:Signature>`` element in **data** (where
        "ds" is the ``http://www.w3.org/2000/09/xmldsig#`` namespace). This element will
        be replaced by the generated signature, and excised when generating the digest.
        """
        if id_attribute is not None:
            self.id_attributes = (id_attribute,)

        if isinstance(cert, (str, bytes)):
            cert_chain = list(iterate_pem(cert))
        else:
            cert_chain = cert  # type: ignore

        input_references = self._preprocess_reference_uri(reference_uri)

        signing_settings = SigningSettings(
            key=None,
            key_name=key_name,
            key_info=key_info,
            always_add_key_value=always_add_key_value,
            cert_chain=cert_chain,
        )

        if key is None:
            raise InvalidInput('Parameter "key" is required')
        elif not self.sign_alg.name.startswith("HMAC_"):
            if isinstance(key, (str, bytes)):
                signing_settings.key = load_pem_private_key(ensure_bytes(key), password=passphrase)
            else:
                signing_settings.key = key

        sig_root, doc_root, c14n_inputs, references = self._unpack(data, input_references)

        if self.construction_method == SignatureConstructionMethod.detached and signature_properties is not None:
            references.append(SignatureReference(URI="#prop"))
            if signature_properties is not None and not isinstance(signature_properties, list):
                signature_properties = [signature_properties]
            signature_properties_el = self._build_signature_properties(signature_properties)
            c14n_inputs.append(signature_properties_el)

        signed_info_node, signature_value_node = self._build_sig(
            sig_root,
            references=references,
            c14n_inputs=c14n_inputs,
            inclusive_ns_prefixes=inclusive_ns_prefixes,
        )

        for signature_annotator in self.signature_annotators:
            signature_annotator(sig_root, signing_settings=signing_settings)

        signed_info_c14n = self._c14n(
            signed_info_node, algorithm=self.c14n_alg, inclusive_ns_prefixes=inclusive_ns_prefixes
        )
        if self.sign_alg.name.startswith("HMAC_"):
            signer = HMAC(key=key, algorithm=digest_algorithm_implementations[self.sign_alg]())  # type: ignore
            signer.update(signed_info_c14n)
            signature_value_node.text = b64encode(signer.finalize()).decode()
            sig_root.append(signature_value_node)
        elif any(self.sign_alg.name.startswith(i) for i in ["DSA_", "RSA_", "ECDSA_", "SHA"]):
            hash_alg = digest_algorithm_implementations[self.sign_alg]()
            if self.sign_alg.name.startswith("DSA_"):
                signature = signing_settings.key.sign(signed_info_c14n, algorithm=hash_alg)
            elif self.sign_alg.name.startswith("ECDSA_"):
                signature = signing_settings.key.sign(
                    signed_info_c14n, signature_algorithm=ec.ECDSA(algorithm=hash_alg)
                )
            elif self.sign_alg.name.startswith("RSA_"):
                signature = signing_settings.key.sign(signed_info_c14n, padding=PKCS1v15(), algorithm=hash_alg)
            elif self.sign_alg.name.startswith("SHA"):
                # See https://www.rfc-editor.org/rfc/rfc9231.html#section-2.3.10
                padding = PSS(mgf=MGF1(algorithm=hash_alg), salt_length=hash_alg.digest_size)
                signature = signing_settings.key.sign(signed_info_c14n, padding=padding, algorithm=hash_alg)
            else:
                raise NotImplementedError()
            if self.sign_alg.name.startswith("DSA_") or self.sign_alg.name.startswith("ECDSA_"):
                # Note: The output of the DSA and ECDSA signers is a DER-encoded ASN.1 sequence of two DER integers.
                (r, s) = utils.decode_dss_signature(signature)
                int_len = bits_to_bytes_unit(signing_settings.key.key_size)
                signature = long_to_bytes(r, blocksize=int_len) + long_to_bytes(s, blocksize=int_len)

            signature_value_node.text = b64encode(signature).decode()
        else:
            raise NotImplementedError()

        if self.construction_method == SignatureConstructionMethod.enveloping:
            for c14n_input in c14n_inputs:
                doc_root.append(c14n_input)

        if self.construction_method == SignatureConstructionMethod.detached and signature_properties is not None:
            sig_root.append(signature_properties_el)

        return doc_root if self.construction_method == SignatureConstructionMethod.enveloped else sig_root

    def _preprocess_reference_uri(self, reference_uris):
        if reference_uris is None:
            return None
        if isinstance(reference_uris, (str, bytes)):
            reference_uris = [reference_uris]
        references = list(
            ref if isinstance(ref, SignatureReference) else SignatureReference(URI=ref) for ref in reference_uris
        )
        return references

    def _add_key_info(self, sig_root, signing_settings: SigningSettings):
        if self.sign_alg.name.startswith("HMAC_"):
            return
        if signing_settings.key_info is None:
            key_info = SubElement(sig_root, ds_tag("KeyInfo"))
            if signing_settings.key_name is not None:
                keyname = SubElement(key_info, ds_tag("KeyName"))
                keyname.text = signing_settings.key_name

            if signing_settings.cert_chain is None or signing_settings.always_add_key_value:
                self._serialize_key_value(signing_settings.key, key_info)

            if signing_settings.cert_chain is not None:
                x509_data = SubElement(key_info, ds_tag("X509Data"))
                for cert in signing_settings.cert_chain:
                    x509_certificate = SubElement(x509_data, ds_tag("X509Certificate"))
                    if isinstance(cert, (str, bytes)):
                        x509_certificate.text = strip_pem_header(cert)
                    else:
                        x509_certificate.text = strip_pem_header(dump_certificate(FILETYPE_PEM, cert))
        else:
            sig_root.append(signing_settings.key_info)

    def _get_c14n_inputs_from_references(self, doc_root, references: List[SignatureReference]):
        c14n_inputs, new_references = [], []
        for reference in references:
            uri = reference.URI if reference.URI.startswith("#") else "#" + reference.URI
            c14n_inputs.append(self.get_root(self._resolve_reference(doc_root, {"URI": uri})))
            new_references.append(SignatureReference(URI=uri, c14n_method=reference.c14n_method))
        return c14n_inputs, new_references

    def _unpack(self, data, references: List[SignatureReference]):
        sig_root = Element(ds_tag("Signature"), nsmap=self.namespaces)
        if self.construction_method == SignatureConstructionMethod.enveloped:
            if isinstance(data, (str, bytes)):
                raise InvalidInput("When using enveloped signature, **data** must be an XML element")
            doc_root = self.get_root(data)
            c14n_inputs = [self.get_root(data)]
            if references is not None:
                # Only sign the referenced element(s)
                c14n_inputs, references = self._get_c14n_inputs_from_references(doc_root, references)

            signature_placeholders = self._findall(doc_root, "Signature[@Id='placeholder']", xpath=".//")
            if len(signature_placeholders) == 0:
                doc_root.append(sig_root)
            elif len(signature_placeholders) == 1:
                sig_root = signature_placeholders[0]
                del sig_root.attrib["Id"]
                for c14n_input in c14n_inputs:
                    placeholders = self._findall(c14n_input, "Signature[@Id='placeholder']", xpath=".//")
                    if placeholders:
                        assert len(placeholders) == 1
                        _remove_sig(placeholders[0])
            else:
                raise InvalidInput("Enveloped signature input contains more than one placeholder")

            if references is None:
                # Set default reference URIs based on signed data ID attribute values
                references = []
                for c14n_input in c14n_inputs:
                    payload_id = c14n_input.get("Id", c14n_input.get("ID"))
                    uri = "#{}".format(payload_id) if payload_id is not None else ""
                    references.append(SignatureReference(URI=uri))
        elif self.construction_method == SignatureConstructionMethod.detached:
            doc_root = self.get_root(data)
            if references is None:
                uri = "#{}".format(data.get("Id", data.get("ID", "object")))
                references = [SignatureReference(URI=uri)]
                c14n_inputs = [self.get_root(data)]
            try:
                c14n_inputs, references = self._get_c14n_inputs_from_references(doc_root, references)
            except InvalidInput:  # Dummy reference URI
                c14n_inputs = [self.get_root(data)]
        elif self.construction_method == SignatureConstructionMethod.enveloping:
            doc_root = sig_root
            c14n_inputs = [Element(ds_tag("Object"), nsmap=self.namespaces, Id="object")]
            if isinstance(data, (str, bytes)):
                c14n_inputs[0].text = data
            else:
                c14n_inputs[0].append(self.get_root(data))
            references = [SignatureReference(URI="#object")]
        return sig_root, doc_root, c14n_inputs, references

    def _build_transforms_for_reference(self, *, transforms_node: _Element, reference: SignatureReference):
        if self.construction_method == SignatureConstructionMethod.enveloped:
            SubElement(transforms_node, ds_tag("Transform"), Algorithm=SignatureConstructionMethod.enveloped.value)
            SubElement(transforms_node, ds_tag("Transform"), Algorithm=reference.c14n_method.value)  # type: ignore
        else:
            c14n_xform = SubElement(
                transforms_node, ds_tag("Transform"), Algorithm=reference.c14n_method.value  # type: ignore
            )
            if reference.inclusive_ns_prefixes:
                SubElement(
                    c14n_xform, ec_tag("InclusiveNamespaces"), PrefixList=" ".join(reference.inclusive_ns_prefixes)
                )

    def _build_sig(self, sig_root, references, c14n_inputs, inclusive_ns_prefixes):
        signed_info = SubElement(sig_root, ds_tag("SignedInfo"), nsmap=self.namespaces)
        sig_c14n_method = SubElement(signed_info, ds_tag("CanonicalizationMethod"), Algorithm=self.c14n_alg.value)
        if inclusive_ns_prefixes:
            SubElement(sig_c14n_method, ec_tag("InclusiveNamespaces"), PrefixList=" ".join(inclusive_ns_prefixes))

        SubElement(signed_info, ds_tag("SignatureMethod"), Algorithm=self.sign_alg.value)
        for i, reference in enumerate(references):
            if reference.c14n_method is None:
                reference = replace(reference, c14n_method=self.c14n_alg)
            if reference.inclusive_ns_prefixes is None:
                reference = replace(reference, inclusive_ns_prefixes=inclusive_ns_prefixes)
            reference_node = SubElement(signed_info, ds_tag("Reference"), URI=reference.URI)
            transforms = SubElement(reference_node, ds_tag("Transforms"))
            self._build_transforms_for_reference(transforms_node=transforms, reference=reference)
            SubElement(reference_node, ds_tag("DigestMethod"), Algorithm=self.digest_alg.value)
            digest_value = SubElement(reference_node, ds_tag("DigestValue"))
            payload_c14n = self._c14n(
                c14n_inputs[i], algorithm=reference.c14n_method, inclusive_ns_prefixes=reference.inclusive_ns_prefixes
            )
            digest = self._get_digest(payload_c14n, algorithm=self.digest_alg)
            digest_value.text = b64encode(digest).decode()
        signature_value = SubElement(sig_root, ds_tag("SignatureValue"))
        return signed_info, signature_value

    def _build_signature_properties(self, signature_properties):
        # FIXME: make this use the annotator API
        obj = Element(ds_tag("Object"), attrib={"Id": "prop"}, nsmap=self.namespaces)
        signature_properties_el = Element(ds_tag("SignatureProperties"))
        for i, el in enumerate(signature_properties):
            signature_property = Element(
                ds_tag("SignatureProperty"),
                attrib={
                    "Id": el.attrib.pop("Id", f"sigprop{i}"),
                    "Target": el.attrib.pop("Target", f"#sigproptarget{i}"),
                },
            )
            signature_property.append(el)
            signature_properties_el.append(signature_property)
        obj.append(signature_properties_el)
        return obj

    def _serialize_key_value(self, key, key_info_node):
        """
        Add the public components of the key to the signature (see https://www.w3.org/TR/xmldsig-core2/#sec-KeyValue).
        """
        key_value = SubElement(key_info_node, ds_tag("KeyValue"))
        if self.sign_alg.name.startswith("RSA_") or self.sign_alg.name.startswith("SHA"):
            rsa_key_value = SubElement(key_value, ds_tag("RSAKeyValue"))
            modulus = SubElement(rsa_key_value, ds_tag("Modulus"))
            modulus.text = b64encode(long_to_bytes(key.public_key().public_numbers().n)).decode()
            exponent = SubElement(rsa_key_value, ds_tag("Exponent"))
            exponent.text = b64encode(long_to_bytes(key.public_key().public_numbers().e)).decode()
        elif self.sign_alg.name.startswith("DSA_"):
            dsa_key_value = SubElement(key_value, ds_tag("DSAKeyValue"))
            for field in "p", "q", "g", "y":
                e = SubElement(dsa_key_value, ds_tag(field.upper()))

                if field == "y":
                    key_params = key.public_key().public_numbers()
                else:
                    key_params = key.parameters().parameter_numbers()

                e.text = b64encode(long_to_bytes(getattr(key_params, field))).decode()
        elif self.sign_alg.name.startswith("ECDSA_"):
            ec_key_value = SubElement(key_value, dsig11_tag("ECKeyValue"), nsmap=dict(dsig11=namespaces.dsig11))
            named_curve = SubElement(  # noqa:F841
                ec_key_value, dsig11_tag("NamedCurve"), URI=self.known_ecdsa_curve_oids[key.curve.name]
            )
            public_key = SubElement(ec_key_value, dsig11_tag("PublicKey"))
            x = key.public_key().public_numbers().x
            y = key.public_key().public_numbers().y
            public_key.text = b64encode(long_to_bytes(4) + long_to_bytes(x) + long_to_bytes(y)).decode()
