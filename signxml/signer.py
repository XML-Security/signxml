from base64 import b64encode
from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from lxml.etree import Element, SubElement
from OpenSSL.crypto import FILETYPE_PEM, dump_certificate

from .algorithms import DigestAlgorithm, SignatureMethod, SignatureType, digest_algorithm_implementations
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


class XMLSigner(XMLSignatureProcessor):
    """
    Create a new XML Signature Signer object, which can be used to hold configuration information and sign multiple
    pieces of data.

    :param method:
        ``signxml.methods.enveloped``, ``signxml.methods.enveloping``, or ``signxml.methods.detached``. See the list
        of signature types under `XML Signature Syntax and Processing Version 2.0, Definitions
        <http://www.w3.org/TR/xmldsig-core2/#sec-Definitions>`_.
    :param signature_algorithm:
        Algorithm that will be used to generate the signature, composed of the signature algorithm and the digest
        algorithm, separated by a hyphen. All algorithm IDs listed under the `Algorithm Identifiers and
        Implementation Requirements <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature
        1.1 standard are supported.
    :param digest_algorithm: Algorithm that will be used to hash the data during signature generation. All algorithm IDs
        listed under the `Algorithm Identifiers and Implementation Requirements
        <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature 1.1 standard are supported.
    """

    def __init__(
        self,
        method: SignatureType = SignatureType.enveloped,
        signature_algorithm: Union[SignatureMethod, str] = SignatureMethod.RSA_SHA256,
        digest_algorithm: Union[DigestAlgorithm, str] = DigestAlgorithm.SHA256,
        c14n_algorithm=XMLSignatureProcessor.default_c14n_algorithm,
    ):
        if method is None or method not in SignatureType:
            raise InvalidInput("Unknown signature method {}".format(method))
        self.signature_type = method
        if isinstance(signature_algorithm, str) and "#" not in signature_algorithm:
            self.sign_alg = SignatureMethod.from_fragment(signature_algorithm)
        else:
            self.sign_alg = SignatureMethod(signature_algorithm)
        if isinstance(digest_algorithm, str) and "#" not in digest_algorithm:
            self.digest_alg = DigestAlgorithm.from_fragment(digest_algorithm)
        else:
            self.digest_alg = DigestAlgorithm(digest_algorithm)
        assert c14n_algorithm in self.known_c14n_algorithms
        self.c14n_alg = c14n_algorithm
        self.namespaces = dict(ds=namespaces.ds)
        self._parser = None
        self.signature_annotators = [self._add_key_info]

    def sign(
        self,
        data,
        key=None,
        passphrase=None,
        cert=None,
        reference_uri=None,
        key_name=None,
        key_info=None,
        id_attribute=None,
        always_add_key_value=False,
        payload_inclusive_ns_prefixes=frozenset(),
        signature_inclusive_ns_prefixes=frozenset(),
        signature_properties=None,
    ):
        """
        Sign the data and return the root element of the resulting XML tree.

        :param data: Data to sign
        :type data: String, file-like object, or XML ElementTree Element API compatible object
        :param key:
            Key to be used for signing. When signing with a certificate or RSA/DSA/ECDSA key, this can be a string/bytes
            containing a PEM-formatted key, or a :py:class:`cryptography.hazmat.primitives.interfaces.RSAPrivateKey`,
            :py:class:`cryptography.hazmat.primitives.interfaces.DSAPrivateKey`, or
            :py:class:`cryptography.hazmat.primitives.interfaces.EllipticCurvePrivateKey` object. When signing with a
            HMAC, this should be a string containing the shared secret.
        :type key:
            string, bytes, :py:class:`cryptography.hazmat.primitives.interfaces.RSAPrivateKey`,
            :py:class:`cryptography.hazmat.primitives.interfaces.DSAPrivateKey`, or
            :py:class:`cryptography.hazmat.primitives.interfaces.EllipticCurvePrivateKey` object
        :param passphrase: Passphrase to use to decrypt the key, if any.
        :type passphrase: string
        :param cert:
            X.509 certificate to use for signing. This should be a string containing a PEM-formatted certificate, or an
            array of strings or OpenSSL.crypto.X509 objects containing the certificate and a chain of intermediate
            certificates.
        :type cert: string, array of strings, or array of OpenSSL.crypto.X509 objects
        :param reference_uri:
            Custom reference URI or list of reference URIs to incorporate into the signature. When ``method`` is set to
            ``detached`` or ``enveloped``, reference URIs are set to this value and only the referenced elements are
            signed.
        :type reference_uri: string or list
        :param key_name: Add a KeyName element in the KeyInfo element that may be used by the signer to communicate a
            key identifier to the recipient. Typically, KeyName contains an identifier related to the key pair used to
            sign the message.
        :type key_name: string
        :param key_info:
            A custom KeyInfo element to insert in the signature. Use this to supply ``<wsse:SecurityTokenReference>``
            or other custom key references. An example value can be found here:
            https://github.com/XML-Security/signxml/blob/master/test/wsse_keyinfo.xml
        :type key_info: :py:class:`lxml.etree.Element`
        :param id_attribute:
            Name of the attribute whose value ``URI`` refers to. By default, SignXML will search for "Id", then "ID".
        :type id_attribute: string
        :param always_add_key_value:
            Write the key value to the KeyInfo element even if a X509 certificate is present. Use of this parameter
            is discouraged, as it introduces an ambiguity and a security hazard. The public key used to sign the
            document is already encoded in the certificate (which is in X509Data), so the verifier must either ignore
            KeyValue or make sure it matches what's in the certificate. This parameter is provided for compatibility
            purposes only.
        :type always_add_key_value: boolean
        :param payload_inclusive_ns_prefixes:
            Provide a list of XML namespace prefixes whose declarations should be preserved when canonicalizing the
            content referenced by the signature (**InclusiveNamespaces PrefixList**).
        :type inclusive_ns_prefixes: list
        :param signature_inclusive_ns_prefixes:
            Provide a list of XML namespace prefixes whose declarations should be preserved when canonicalizing the
            signature itself (**InclusiveNamespaces PrefixList**).
        :type signature_inclusive_ns_prefixes: list
        :param signature_properties:
            One or more Elements that are to be included in the SignatureProperies section when using the detached
            method.
        :type signature_properties: :py:class:`lxml.etree.Element` or list of :py:class:`lxml.etree.Element` s

        :returns:
            A :py:class:`lxml.etree.Element` object representing the root of the XML tree containing the signature and
            the payload data.

        To specify the location of an enveloped signature within **data**, insert a
        ``<ds:Signature Id="placeholder"></ds:Signature>`` element in **data** (where
        "ds" is the "http://www.w3.org/2000/09/xmldsig#" namespace). This element will
        be replaced by the generated signature, and excised when generating the digest.
        """
        if id_attribute is not None:
            self.id_attributes = (id_attribute,)

        if isinstance(cert, (str, bytes)):
            cert_chain = list(iterate_pem(cert))
        else:
            cert_chain = cert

        if isinstance(reference_uri, (str, bytes)):
            reference_uris = [reference_uri]
        else:
            reference_uris = reference_uri

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

        sig_root, doc_root, c14n_inputs, reference_uris = self._unpack(data, reference_uris)

        if self.signature_type == SignatureType.detached and signature_properties is not None:
            reference_uris.append("#prop")
            if signature_properties is not None and not isinstance(signature_properties, list):
                signature_properties = [signature_properties]
            signature_properties_el = self._build_signature_properties(signature_properties)
            c14n_inputs.append(signature_properties_el)

        signed_info_node, signature_value_node = self._build_sig(
            sig_root,
            reference_uris,
            c14n_inputs,
            sig_insp=signature_inclusive_ns_prefixes,
            payload_insp=payload_inclusive_ns_prefixes,
        )

        for signature_annotator in self.signature_annotators:
            signature_annotator(sig_root, signing_settings=signing_settings)

        signed_info_c14n = self._c14n(
            signed_info_node, algorithm=self.c14n_alg, inclusive_ns_prefixes=signature_inclusive_ns_prefixes
        )
        if self.sign_alg.name.startswith("HMAC_"):
            signer = HMAC(key=key, algorithm=digest_algorithm_implementations[self.sign_alg]())
            signer.update(signed_info_c14n)
            signature_value_node.text = b64encode(signer.finalize()).decode()
            sig_root.append(signature_value_node)
        elif any(self.sign_alg.name.startswith(i) for i in ["DSA_", "RSA_", "ECDSA_"]):
            hash_alg = digest_algorithm_implementations[self.sign_alg]()
            if self.sign_alg.name.startswith("DSA_"):
                signature = signing_settings.key.sign(signed_info_c14n, algorithm=hash_alg)
            elif self.sign_alg.name.startswith("ECDSA_"):
                signature = signing_settings.key.sign(
                    signed_info_c14n, signature_algorithm=ec.ECDSA(algorithm=hash_alg)
                )
            elif self.sign_alg.name.startswith("RSA_"):
                signature = signing_settings.key.sign(signed_info_c14n, padding=PKCS1v15(), algorithm=hash_alg)
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

        if self.signature_type == SignatureType.enveloping:
            for c14n_input in c14n_inputs:
                doc_root.append(c14n_input)

        if self.signature_type == SignatureType.detached and signature_properties is not None:
            sig_root.append(signature_properties_el)

        return doc_root if self.signature_type == SignatureType.enveloped else sig_root

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

    def _get_c14n_inputs_from_reference_uris(self, doc_root, reference_uris):
        c14n_inputs, new_reference_uris = [], []
        for reference_uri in reference_uris:
            if not reference_uri.startswith("#"):
                reference_uri = "#" + reference_uri
            c14n_inputs.append(self.get_root(self._resolve_reference(doc_root, {"URI": reference_uri})))
            new_reference_uris.append(reference_uri)
        return c14n_inputs, new_reference_uris

    def _unpack(self, data, reference_uris):
        sig_root = Element(ds_tag("Signature"), nsmap=self.namespaces)
        if self.signature_type == SignatureType.enveloped:
            if isinstance(data, (str, bytes)):
                raise InvalidInput("When using enveloped signature, **data** must be an XML element")
            doc_root = self.get_root(data)
            c14n_inputs = [self.get_root(data)]
            if reference_uris is not None:
                # Only sign the referenced element(s)
                c14n_inputs, reference_uris = self._get_c14n_inputs_from_reference_uris(doc_root, reference_uris)

            signature_placeholders = self._findall(doc_root, "Signature[@Id='placeholder']", anywhere=True)
            if len(signature_placeholders) == 0:
                doc_root.append(sig_root)
            elif len(signature_placeholders) == 1:
                sig_root = signature_placeholders[0]
                del sig_root.attrib["Id"]
                for c14n_input in c14n_inputs:
                    placeholders = self._findall(c14n_input, "Signature[@Id='placeholder']", anywhere=True)
                    if placeholders:
                        assert len(placeholders) == 1
                        _remove_sig(placeholders[0])
            else:
                raise InvalidInput("Enveloped signature input contains more than one placeholder")

            if reference_uris is None:
                # Set default reference URIs based on signed data ID attribute values
                reference_uris = []
                for c14n_input in c14n_inputs:
                    payload_id = c14n_input.get("Id", c14n_input.get("ID"))
                    reference_uris.append("#{}".format(payload_id) if payload_id is not None else "")
        elif self.signature_type == SignatureType.detached:
            doc_root = self.get_root(data)
            if reference_uris is None:
                reference_uris = ["#{}".format(data.get("Id", data.get("ID", "object")))]
                c14n_inputs = [self.get_root(data)]
            try:
                c14n_inputs, reference_uris = self._get_c14n_inputs_from_reference_uris(doc_root, reference_uris)
            except InvalidInput:  # Dummy reference URI
                c14n_inputs = [self.get_root(data)]
        elif self.signature_type == SignatureType.enveloping:
            doc_root = sig_root
            c14n_inputs = [Element(ds_tag("Object"), nsmap=self.namespaces, Id="object")]
            if isinstance(data, (str, bytes)):
                c14n_inputs[0].text = data
            else:
                c14n_inputs[0].append(self.get_root(data))
            reference_uris = ["#object"]
        return sig_root, doc_root, c14n_inputs, reference_uris

    def _build_sig(self, sig_root, reference_uris, c14n_inputs, sig_insp, payload_insp):
        signed_info = SubElement(sig_root, ds_tag("SignedInfo"), nsmap=self.namespaces)
        sig_c14n_method = SubElement(signed_info, ds_tag("CanonicalizationMethod"), Algorithm=self.c14n_alg)
        if sig_insp:
            SubElement(sig_c14n_method, ec_tag("InclusiveNamespaces"), PrefixList=" ".join(sig_insp))

        SubElement(signed_info, ds_tag("SignatureMethod"), Algorithm=self.sign_alg.value)
        for i, reference_uri in enumerate(reference_uris):
            reference = SubElement(signed_info, ds_tag("Reference"), URI=reference_uri)
            transforms = SubElement(reference, ds_tag("Transforms"))
            if self.signature_type == SignatureType.enveloped:
                SubElement(transforms, ds_tag("Transform"), Algorithm=namespaces.ds + "enveloped-signature")
                SubElement(transforms, ds_tag("Transform"), Algorithm=self.c14n_alg)
            else:
                c14n_xform = SubElement(transforms, ds_tag("Transform"), Algorithm=self.c14n_alg)
                if payload_insp:
                    SubElement(c14n_xform, ec_tag("InclusiveNamespaces"), PrefixList=" ".join(payload_insp))

            SubElement(reference, ds_tag("DigestMethod"), Algorithm=self.digest_alg.value)
            digest_value = SubElement(reference, ds_tag("DigestValue"))
            payload_c14n = self._c14n(c14n_inputs[i], algorithm=self.c14n_alg, inclusive_ns_prefixes=payload_insp)
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
                    "Id": el.attrib.pop("Id", "sigprop{}".format(i)),
                    "Target": el.attrib.pop("Target", "#sigproptarget{}".format(i)),
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
        if self.sign_alg.name.startswith("RSA_"):
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
