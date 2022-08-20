import os.path
from base64 import b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from lxml import etree
from lxml.etree import Element, SubElement
from signxml import (
    InvalidInput,
    XMLSignatureProcessor,
    _remove_sig,
    ds_tag,
    dsig11_tag,
    ensure_str,
    iterate_pem,
    long_to_bytes,
    namespaces,
    strip_pem_header,
)


class XMLEnvelopedEnvelopingSigner(XMLSignatureProcessor):
    """
    A class that signs multiple data by putting the signature enveloped in the
    first data item, and enveloping the others.
    """
    def __init__(self, signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                 c14n_algorithm=XMLSignatureProcessor.default_c14n_algorithm):
        self.sign_alg = signature_algorithm
        assert self.sign_alg in self.known_signature_digest_tags or self.sign_alg in self.known_hmac_digest_tags
        assert digest_algorithm in self.known_digest_tags
        self.digest_alg = digest_algorithm
        assert c14n_algorithm in self.known_c14n_algorithms
        self.c14n_alg = c14n_algorithm
        self.namespaces = dict(ds=namespaces.ds)
        self._parser = None

    def sign(self, data, key=None, passphrase=None, cert=None, key_name=None, key_info=None, id_attribute=None):
        """
        Sign the data and return the root element of the resulting XML tree.

        :param data: Data to sign - must be a sequence of items to sign.
        :type data_others: Sequence of String, file-like object, or XML ElementTree Element API compatible object
        :param key:
            Key to be used for signing. When signing with a certificate or RSA/DSA/ECDSA key, this can be a string
            containing a PEM-formatted key, or a :py:class:`cryptography.hazmat.primitives.interfaces.RSAPublicKey`,
            :py:class:`cryptography.hazmat.primitives.interfaces.DSAPublicKey`, or
            :py:class:`cryptography.hazmat.primitives.interfaces.EllipticCurvePublicKey` object. When signing with a
            HMAC, this should be a string containing the shared secret.
        :type key:
            string, :py:class:`cryptography.hazmat.primitives.interfaces.RSAPublicKey`,
            :py:class:`cryptography.hazmat.primitives.interfaces.DSAPublicKey`, or
            :py:class:`cryptography.hazmat.primitives.interfaces.EllipticCurvePublicKey` object
        :param passphrase: Passphrase to use to decrypt the key, if any.
        :type passphrase: string
        :param cert:
            X.509 certificate to use for signing. This should be a string containing a PEM-formatted certificate, or an
            array of strings or OpenSSL.crypto.X509 objects containing the certificate and a chain of intermediate
            certificates.
        :type cert: string, array of strings, or array of OpenSSL.crypto.X509 objects
        :param key_name: Add a KeyName element in the KeyInfo element that may be used by the signer to communicate a
            key identifier to the recipient. Typically, KeyName contains an identifier related to the key pair used to
            sign the message.
        :type key_name: string
        :param key_info: A custom KeyInfo element to insert in the signature. Use this to supply
            ``<wsse:SecurityTokenReference>`` or other custom key references.
        :type key_info: :py:class:`lxml.etree.Element`
        :param id_attribute:
            Name of the attribute whose value ``URI`` refers to. By default, SignXML will search for "Id", then "ID".
        :type id_attribute: string

        :returns:
            A :py:class:`lxml.etree.Element` object representing the root of the XML tree containing the signature and
            the payload data.

        To specify the location of an enveloped signature within **data**, insert a
        ``<ds:Signature Id="placeholder"></ds:Signature>`` element in **data** (where
        "ds" is the "http://www.w3.org/2000/09/xmldsig#" namespace). This element will
        be replaced by the generated signature, and excised when generating the digest.
        """
        if id_attribute is not None:
            self.id_attributes = (id_attribute, )

        if isinstance(cert, (str, bytes)):
            cert_chain = list(iterate_pem(cert))
        else:
            cert_chain = cert

        sig_root, doc_root, c14n_inputs, reference_uris = self._unpack(data)
        signed_info_element, signature_value_element = self._build_sig(sig_root, reference_uris, c14n_inputs)

        if key is None:
            raise InvalidInput('Parameter "key" is required')

        signed_info_c14n = self._c14n(signed_info_element, algorithm=self.c14n_alg)
        if self.sign_alg.startswith("hmac-"):
            from cryptography.hazmat.primitives.hmac import HMAC
            signer = HMAC(key=key,
                          algorithm=self._get_hmac_digest_method_by_tag(self.sign_alg),
                          backend=default_backend())
            signer.update(signed_info_c14n)
            signature_value_element.text = ensure_str(b64encode(signer.finalize()))
            sig_root.append(signature_value_element)
        elif any(self.sign_alg.startswith(i) for i in ["dsa-", "rsa-", "ecdsa-"]):
            if isinstance(key, (str, bytes)):
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_private_key,
                )
                key = load_pem_private_key(key, password=passphrase, backend=default_backend())

            hash_alg = self._get_signature_digest_method_by_tag(self.sign_alg)
            if self.sign_alg.startswith("dsa-"):
                signature = key.sign(signed_info_c14n, algorithm=hash_alg)
            elif self.sign_alg.startswith("ecdsa-"):
                signature = key.sign(signed_info_c14n, signature_algorithm=ec.ECDSA(algorithm=hash_alg))
            elif self.sign_alg.startswith("rsa-"):
                signature = key.sign(signed_info_c14n, padding=PKCS1v15(), algorithm=hash_alg)
            else:
                raise NotImplementedError()
            if self.sign_alg.startswith("dsa-"):
                # Note: The output of the DSA signer is a DER-encoded ASN.1 sequence of two DER integers.
                from asn1crypto.algos import DSASignature
                decoded_signature = DSASignature.load(signature).native
                r = decoded_signature['r']
                s = decoded_signature['s']
                signature = long_to_bytes(r).rjust(32, b"\0") + long_to_bytes(s).rjust(32, b"\0")

            signature_value_element.text = ensure_str(b64encode(signature))

            if key_info is None:
                key_info = SubElement(sig_root, ds_tag("KeyInfo"))
                if key_name is not None:
                    keyname = SubElement(key_info, ds_tag("KeyName"))
                    keyname.text = key_name

                if cert_chain is None:
                    self._serialize_key_value(key, key_info)
                else:
                    x509_data = SubElement(key_info, ds_tag("X509Data"))
                    for cert in cert_chain:
                        x509_certificate = SubElement(x509_data, ds_tag("X509Certificate"))
                        if isinstance(cert, (str, bytes)):
                            x509_certificate.text = strip_pem_header(cert)
                        else:
                            from OpenSSL.crypto import FILETYPE_PEM, dump_certificate
                            x509_certificate.text = strip_pem_header(dump_certificate(FILETYPE_PEM, cert))
            else:
                sig_root.append(key_info)
        else:
            raise NotImplementedError()

        for c14n_input in c14n_inputs[1:]:
            sig_root.append(c14n_input)
        return doc_root

    def _unpack(self, data):
        sig_root = Element(ds_tag("Signature"), nsmap=self.namespaces)

        if isinstance(data[0], (str, bytes)):
            raise InvalidInput("First data item **must** be an XML element")

        doc_root = self.get_root(data[0])

        c14n_inputs = [self.get_root(data[0])]

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

        reference_uris = []
        for c14n_input in c14n_inputs:
            payload_id = None
            for id_attribute in self.id_attributes:
                payload_id = c14n_input.get(id_attribute)
                if payload_id:
                    break
            reference_uris.append('#{}'.format(payload_id) if payload_id else '')

        index = 1
        for enveloped_data in data[1:]:
            c14n_inputs.append(Element(ds_tag("Object"), nsmap=self.namespaces, Id="object-{}".format(index)))
            if isinstance(enveloped_data, (str, bytes)):
                c14n_inputs[index].text = enveloped_data
            else:
                c14n_inputs[index].append(self.get_root(enveloped_data))
            reference_uris.append('#object-{}'.format(index))
            index += 1

        return sig_root, doc_root, c14n_inputs, reference_uris

    def _build_sig(self, sig_root, reference_uris, c14n_inputs):
        signed_info = SubElement(sig_root, ds_tag("SignedInfo"), nsmap=self.namespaces)
        c14n_method = SubElement(signed_info, ds_tag("CanonicalizationMethod"), Algorithm=self.c14n_alg)  # noqa:F841
        if self.sign_alg.startswith("hmac-"):
            algorithm_id = self.known_hmac_digest_tags[self.sign_alg]
        else:
            algorithm_id = self.known_signature_digest_tags[self.sign_alg]
        signature_method = SubElement(signed_info, ds_tag("SignatureMethod"), Algorithm=algorithm_id)  # noqa:F841
        for i, reference_uri in enumerate(reference_uris):
            reference = SubElement(signed_info, ds_tag("Reference"), URI=reference_uri)
            if i == 0:
                transforms = SubElement(reference, ds_tag("Transforms"))
                SubElement(transforms, ds_tag("Transform"), Algorithm=namespaces.ds + "enveloped-signature")
                SubElement(transforms, ds_tag("Transform"), Algorithm=self.c14n_alg)
            digest_method = SubElement(reference, ds_tag("DigestMethod"),  # noqa:F841
                                       Algorithm=self.known_digest_tags[self.digest_alg])
            digest_value = SubElement(reference, ds_tag("DigestValue"))
            payload_c14n = self._c14n(c14n_inputs[i], algorithm=self.c14n_alg)
            digest = self._get_digest(payload_c14n, self._get_digest_method_by_tag(self.digest_alg))
            digest_value.text = digest
        signature_value = SubElement(sig_root, ds_tag("SignatureValue"))
        return signed_info, signature_value

    def _serialize_key_value(self, key, key_info_element):
        key_value = SubElement(key_info_element, ds_tag("KeyValue"))
        if self.sign_alg.startswith("rsa-"):
            rsa_key_value = SubElement(key_value, ds_tag("RSAKeyValue"))
            modulus = SubElement(rsa_key_value, ds_tag("Modulus"))
            modulus.text = ensure_str(b64encode(long_to_bytes(key.public_key().public_numbers().n)))
            exponent = SubElement(rsa_key_value, ds_tag("Exponent"))
            exponent.text = ensure_str(b64encode(long_to_bytes(key.public_key().public_numbers().e)))
        elif self.sign_alg.startswith("dsa-"):
            dsa_key_value = SubElement(key_value, ds_tag("DSAKeyValue"))
            for field in "p", "q", "g", "y":
                e = SubElement(dsa_key_value, ds_tag(field.upper()))

                if field == "y":
                    key_params = key.public_key().public_numbers()
                else:
                    key_params = key.parameters().parameter_numbers()

                e.text = ensure_str(b64encode(long_to_bytes(getattr(key_params, field))))
        elif self.sign_alg.startswith("ecdsa-"):
            ec_key_value = SubElement(key_value, dsig11_tag("ECKeyValue"), nsmap=dict(dsig11=namespaces.dsig11))
            named_curve = SubElement(ec_key_value, dsig11_tag("NamedCurve"),  # noqa:F841
                                     URI=self.known_ecdsa_curve_oids[key.curve.name])
            public_key = SubElement(ec_key_value, dsig11_tag("PublicKey"))
            x = key.public_key().public_numbers().x
            y = key.public_key().public_numbers().y
            public_key.text = ensure_str(b64encode(long_to_bytes(4) + long_to_bytes(x) + long_to_bytes(y)))


if __name__ == '__main__':
    signer = XMLEnvelopedEnvelopingSigner()

    with open(os.path.join(os.path.dirname(__file__), "test", "example.pem"), "rb") as fh:
        crt = fh.read()
    with open(os.path.join(os.path.dirname(__file__), "test", "example.key"), "rb") as fh:
        key = fh.read()

    data = [
        etree.parse(os.path.join(os.path.dirname(__file__), "test", "example2.xml")),
        etree.parse(os.path.join(os.path.dirname(__file__), "test", "example.xml")),
    ]

    signed_data = signer.sign(data, key=key, cert=crt)
    signed_data_str = etree.tostring(signed_data)
    with open(os.path.join(os.path.dirname(__file__), "test", "example-125.xml"), "wb") as fh:
        fh.write(signed_data_str)
