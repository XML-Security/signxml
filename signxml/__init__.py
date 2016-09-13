from __future__ import absolute_import, division, print_function, unicode_literals

from base64 import b64encode, b64decode
from enum import Enum

from eight import str, bytes
from lxml import etree
from lxml.etree import Element, SubElement
from defusedxml.lxml import fromstring

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import Hash, SHA1, SHA224, SHA256, SHA384, SHA512
from cryptography.hazmat.backends import default_backend

from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder

from .exceptions import InvalidSignature, InvalidDigest, InvalidCertificate, InvalidInput, RedundantCert
from .util import (bytes_to_long, long_to_bytes, strip_pem_header, add_pem_header, ensure_bytes, ensure_str, Namespace,
                   XMLProcessor, DERSequenceOfIntegers, iterate_pem)
from collections import namedtuple

methods = Enum("Methods", "enveloped enveloping detached")

namespaces = Namespace(
    ds="http://www.w3.org/2000/09/xmldsig#",
    dsig11="http://www.w3.org/2009/xmldsig11#",
    dsig2="http://www.w3.org/2010/xmldsig2#",
    ec="http://www.w3.org/2001/10/xml-exc-c14n#",
    dsig_more="http://www.w3.org/2001/04/xmldsig-more#",
    xenc="http://www.w3.org/2001/04/xmlenc#",
    xenc11="http://www.w3.org/2009/xmlenc11#"
)

def ds_tag(tag):
    return "{" + namespaces.ds + "}" + tag

def dsig11_tag(tag):
    return "{" + namespaces.dsig11 + "}" + tag

def _remove_sig(signature):
    """
    Remove the signature node from payload keeping any tail element.
    This is needed for eneveloped signatures.

    :param payload: Payload to remove signature from
    :type data: XML ElementTree Element
    :param signature: Signature to remove from payload
    :type digest_algorithm: XML ElementTree Element
    """
    try:
        signaturep = next(signature.iterancestors())
    except StopIteration:
        raise ValueError("Can't remove the root signature node")
    if signature.tail is not None:
        try:
            signatures = next(signature.itersiblings(preceding=True))
        except StopIteration:
            if signaturep.text is not None:
                signaturep.text = signaturep.text + signature.tail
            else:
                signaturep.text = signature.tail
        else:
            if signatures.tail is not None:
                signatures.tail = signatures.tail + signature.tail
            else:
                signatures.tail = signature.tail
    signaturep.remove(signature)

class VerifyResult(namedtuple("VerifyResult", "signed_data signed_xml signature_xml")):
    """
    The results of a verification return the signed data, the signed xml and the signature xml

    :param signed_data: The binary data as it was signed (literally)
    :type data: bytes
    :param signed_xml: The signed data parsed as XML (or None if parsing failed)
    :type signed_xml: ElementTree or None
    :param signature_xml: The signature element parsed as XML
    :type signed_xml: ElementTree

    This class is a namedtuple representing structured data returned by ``signxml.XMLVerifier.verify()``. As with any
    namedtuple, elements of the return value can be accessed as attributes. For example::
        verified_data = signxml.XMLVerifier().verify(input_data).signed_xml
    """

class XMLSignatureProcessor(XMLProcessor):
    schema_file = "xmldsig1-schema.xsd"

    known_digest_methods = {
        namespaces.ds + "sha1": SHA1,
        namespaces.xenc + "sha256": SHA256,
        namespaces.dsig_more + "sha224": SHA224,
        namespaces.dsig_more + "sha384": SHA384,
        namespaces.xenc + "sha512": SHA512,
    }

    known_hmac_digest_methods = {
        namespaces.ds + "hmac-sha1": SHA1,
        namespaces.dsig_more + "hmac-sha256": SHA256,
        namespaces.dsig_more + "hmac-sha384": SHA384,
        namespaces.dsig_more + "hmac-sha512": SHA512,
        namespaces.dsig_more + "hmac-sha224": SHA224,
    }

    known_signature_digest_methods = {
        namespaces.dsig_more + "rsa-sha256": SHA256,
        namespaces.dsig_more + "ecdsa-sha256": SHA256,
        namespaces.ds + "dsa-sha1": SHA1,
        namespaces.ds + "rsa-sha1": SHA1,
        namespaces.dsig_more + "rsa-sha224": SHA224,
        namespaces.dsig_more + "rsa-sha384": SHA384,
        namespaces.dsig_more + "rsa-sha512": SHA512,
        namespaces.dsig_more + "ecdsa-sha1": SHA1,
        namespaces.dsig_more + "ecdsa-sha224": SHA224,
        namespaces.dsig_more + "ecdsa-sha384": SHA384,
        namespaces.dsig_more + "ecdsa-sha512": SHA512,
        namespaces.dsig11 + "dsa-sha256": SHA256,
    }
    known_digest_tags = {method.split("#")[1]: method for method in known_digest_methods}
    known_hmac_digest_tags = {method.split("#")[1]: method for method in known_hmac_digest_methods}
    known_signature_digest_tags = {method.split("#")[1]: method for method in known_signature_digest_methods}

    # See https://tools.ietf.org/html/rfc5656
    known_ecdsa_curves = {
        "urn:oid:1.2.840.10045.3.1.7": ec.SECP256R1,
        "urn:oid:1.3.132.0.34": ec.SECP384R1,
        "urn:oid:1.3.132.0.35": ec.SECP521R1,
        "urn:oid:1.3.132.0.1": ec.SECT163K1,
        "urn:oid:1.2.840.10045.3.1.1": ec.SECP192R1,
        "urn:oid:1.3.132.0.33": ec.SECP224R1,
        "urn:oid:1.3.132.0.26": ec.SECT233K1,
        "urn:oid:1.3.132.0.27": ec.SECT233R1,
        "urn:oid:1.3.132.0.16": ec.SECT283R1,
        "urn:oid:1.3.132.0.36": ec.SECT409K1,
        "urn:oid:1.3.132.0.37": ec.SECT409R1,
        "urn:oid:1.3.132.0.38": ec.SECT571K1,
    }
    known_ecdsa_curve_oids = {ec().name: oid for oid, ec in known_ecdsa_curves.items()}

    known_c14n_algorithms = {
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        "http://www.w3.org/2006/12/xml-c14n11",
        "http://www.w3.org/2006/12/xml-c14n11#WithComments"
    }
    default_c14n_algorithm = "http://www.w3.org/2006/12/xml-c14n11"

    def _get_digest(self, data, digest_algorithm):
        hasher = Hash(algorithm=digest_algorithm, backend=default_backend())
        hasher.update(data)
        return ensure_str(b64encode(hasher.finalize()))

    def _get_digest_method(self, digest_algorithm_id, methods=None):
        if methods is None:
            methods = self.known_digest_methods
        if digest_algorithm_id not in methods:
            raise InvalidInput('Algorithm "{}" is not recognized'.format(digest_algorithm_id))
        return methods[digest_algorithm_id]()

    def _get_digest_method_by_tag(self, digest_algorithm_tag, methods=None, known_tags=None):
        if known_tags is None:
            known_tags = self.known_digest_tags
        if digest_algorithm_tag not in known_tags:
            raise InvalidInput('Algorithm tag "{}" is not recognized'.format(digest_algorithm_tag))
        return self._get_digest_method(known_tags[digest_algorithm_tag], methods=methods)

    def _get_hmac_digest_method(self, hmac_algorithm_id):
        return self._get_digest_method(hmac_algorithm_id, methods=self.known_hmac_digest_methods)

    def _get_hmac_digest_method_by_tag(self, hmac_algorithm_tag):
        return self._get_digest_method_by_tag(hmac_algorithm_tag, methods=self.known_hmac_digest_methods,
                                              known_tags=self.known_hmac_digest_tags)

    def _get_signature_digest_method(self, signature_algorithm_id):
        return self._get_digest_method(signature_algorithm_id, methods=self.known_signature_digest_methods)

    def _get_signature_digest_method_by_tag(self, signature_algorithm_tag):
        return self._get_digest_method_by_tag(signature_algorithm_tag, methods=self.known_signature_digest_methods,
                                              known_tags=self.known_signature_digest_tags)

    def _find(self, element, query, require=True, namespace="ds", anywhere=False):
        if anywhere:
            result = element.find('.//' + namespace + ":" + query, namespaces=namespaces)
        else:
            result = element.find(namespace + ":" + query, namespaces=namespaces)

        if require and result is None:
            raise InvalidInput("Expected to find XML element {} in {}".format(query, element.tag))
        return result

    def _findall(self, element, query, namespace="ds", anywhere=False):
        if anywhere:
            return element.findall('.//' + namespace + ":" + query, namespaces=namespaces)
        else:
            return element.findall(namespace + ":" + query, namespaces=namespaces)

    def _c14n(self, node, algorithm, inclusive_ns_prefixes=None):
        exclusive, with_comments = False, False

        if algorithm.startswith("http://www.w3.org/2001/10/xml-exc-c14n#"):
            exclusive = True
        if algorithm.endswith("#WithComments"):
            with_comments = True

        c14n = etree.tostring(node, method="c14n", exclusive=exclusive, with_comments=with_comments,
                              inclusive_ns_prefixes=inclusive_ns_prefixes)
        if exclusive is False:
            # TODO: there must be a nicer way to do this. See also:
            # http://www.w3.org/TR/xml-c14n, "namespace axis"
            # http://www.w3.org/TR/xml-c14n2/#sec-Namespace-Processing
            c14n = c14n.replace(b' xmlns=""', b'')
        return c14n

class XMLSigner(XMLSignatureProcessor):
    """
    Create a new XML Signature Signer object, which can be used to hold configuration information and sign multiple
    pieces of data.

    :param method:
        ``signxml.methods.enveloped``, ``signxml.methods.enveloping``, or ``signxml.methods.detached``. See the list
        of signature types under `XML Signature Syntax and Processing Version 2.0, Definitions
        <http://www.w3.org/TR/xmldsig-core2/#sec-Definitions>`_.
    :type method: :py:class:`methods`
    :param signature_algorithm:
        Algorithm that will be used to generate the signature, composed of the signature algorithm and the digest
        algorithm, separated by a hyphen. All algorithm IDs listed under the `Algorithm Identifiers and
        Implementation Requirements <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature
        1.1 standard are supported.
    :type signature_algorithm: string
    :param digest_algorithm: Algorithm that will be used to hash the data during signature generation. All algorithm IDs
        listed under the `Algorithm Identifiers and Implementation Requirements
        <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature 1.1 standard are supported.
    :type digest_algorithm: string
    """
    def __init__(self, method=methods.enveloped, signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                 c14n_algorithm=XMLSignatureProcessor.default_c14n_algorithm):
        if method not in methods:
            raise InvalidInput("Unknown signature method {}".format(method))
        self.method = method
        self.sign_alg = signature_algorithm
        assert self.sign_alg in self.known_signature_digest_tags or self.sign_alg in self.known_hmac_digest_tags
        assert digest_algorithm in self.known_digest_tags
        self.digest_alg = digest_algorithm
        assert c14n_algorithm in self.known_c14n_algorithms
        self.c14n_alg = c14n_algorithm
        self.namespaces = dict(ds=namespaces.ds)
        self._parser = None

    def sign(self, data, key=None, passphrase=None, cert=None, reference_uri=None, key_name=None):
        """
        Sign the data and return the root element of the resulting XML tree.

        :param data: Data to sign
        :type data: String, file-like object, or XML ElementTree Element API compatible object
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
        :param reference_uri:
            Custom reference URI to incorporate into the signature. Only used when ``method`` is set to ``detached``.
        :type reference_uri: string
        :param key_name: Add a KeyName element in the KeyInfo element that may be used by the signer to communicate a
            key identifier to the recipient. Typically, KeyName contains an identifier related to the key pair used to
            sign the message.
        :type key_name: string

        :returns:
            A :py:class:`lxml.etree.Element` object representing the root of the XML tree containing the signature and
            the payload data.

        To specify the location of an enveloped signature within **data**, insert a
        `<Signature Id="placeholder"></Signature>` element in **data**. This element will be replaced by the generated
        signature, and excised when generating the digest.
        """
        if isinstance(cert, (str, bytes)):
            cert_chain = list(iterate_pem(cert))
        else:
            cert_chain = cert

        sig_root, doc_root, c14n_input, reference_uri = self._unpack(data, reference_uri)
        payload_c14n = self._c14n(c14n_input, algorithm=self.c14n_alg)
        digest = self._get_digest(payload_c14n, self._get_digest_method_by_tag(self.digest_alg))
        signed_info_element, signature_value_element = self._build_sig(sig_root, reference_uri, digest)

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
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                key = load_pem_private_key(key, password=passphrase, backend=default_backend())

            hash_alg = self._get_signature_digest_method_by_tag(self.sign_alg)
            if self.sign_alg.startswith("dsa-"):
                signer = key.signer(signature_algorithm=hash_alg)
            elif self.sign_alg.startswith("ecdsa-"):
                signer = key.signer(signature_algorithm=ec.ECDSA(algorithm=hash_alg))
            elif self.sign_alg.startswith("rsa-"):
                signer = key.signer(padding=PKCS1v15(), algorithm=hash_alg)
            else:
                raise NotImplementedError()
            signer.update(signed_info_c14n)
            signature = signer.finalize()
            if self.sign_alg.startswith("dsa-"):
                # Note: The output of the DSA signer is a DER-encoded ASN.1 sequence of two DER integers.
                decoded_signature = der_decoder.decode(signature)[0]
                r = decoded_signature.getComponentByPosition(0)
                s = decoded_signature.getComponentByPosition(1)
                signature = long_to_bytes(r).rjust(32, b"\0") + long_to_bytes(s).rjust(32, b"\0")

            signature_value_element.text = ensure_str(b64encode(signature))

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
                        from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
                        x509_certificate.text = dump_certificate(FILETYPE_PEM, cert)
        else:
            raise NotImplementedError()

        if self.method == methods.enveloping:
            doc_root.append(c14n_input)
        return doc_root

    def _unpack(self, data, reference_uri):
        sig_root = Element(ds_tag("Signature"), nsmap=self.namespaces)
        doc_root = sig_root
        if self.method == methods.enveloped:
            if isinstance(data, (str, bytes)):
                raise InvalidInput("When using enveloped signature, **data** must be an XML element")
            c14n_input = self.get_root(data)
            doc_root = self.get_root(data)
            if reference_uri is not None:
                targets = self._findall(doc_root,'*[@Id="{0}"]'.format(reference_uri), anywhere=True)
                if len(targets)==1:
                    c14n_root = targets[0]
            signature_placeholders = self._findall(doc_root, "Signature[@Id='placeholder']", anywhere=True)
            if len(signature_placeholders) == 0:
                doc_root.append(sig_root)
            elif len(signature_placeholders) == 1:
                sig_root = signature_placeholders[0]
                del sig_root.attrib["Id"]
                _remove_sig(self._findall(c14n_input, "Signature[@Id='placeholder']", anywhere=True)[0])
            else:
                raise InvalidInput("Enveloped signature input contains more than one placeholder")

            if reference_uri is None:
                reference_uri = ""
            # get signed data id attribute value for reference uri
            payload_id = c14n_input.get("Id", c14n_input.get("ID"))
            if payload_id is not None:
                # set default reference uri based on data id attribute value
                reference_uri = "#{}".format(payload_id)
        elif self.method == methods.detached:
            if reference_uri is None:
                reference_uri = "#{}".format(data.get("Id", data.get("ID", "object")))
            c14n_input = self.get_root(data)
        elif self.method == methods.enveloping:
            c14n_input = Element(ds_tag("Object"), nsmap=self.namespaces, Id="object")
            if isinstance(data, (str, bytes)):
                c14n_input.text = data
            else:
                c14n_input.append(self.get_root(data))
            reference_uri = "#object"
        return sig_root, doc_root, c14n_input, reference_uri

    def _build_sig(self, sig_root, reference_uri, digest):
        signed_info = SubElement(sig_root, ds_tag("SignedInfo"), nsmap=self.namespaces)
        c14n_method = SubElement(signed_info, ds_tag("CanonicalizationMethod"), Algorithm=self.c14n_alg)
        if self.sign_alg.startswith("hmac-"):
            algorithm_id = self.known_hmac_digest_tags[self.sign_alg]
        else:
            algorithm_id = self.known_signature_digest_tags[self.sign_alg]
        signature_method = SubElement(signed_info, ds_tag("SignatureMethod"), Algorithm=algorithm_id)
        reference = SubElement(signed_info, ds_tag("Reference"), URI=reference_uri)
        if self.method == methods.enveloped:
            transforms = SubElement(reference, ds_tag("Transforms"))
            SubElement(transforms, ds_tag("Transform"), Algorithm=namespaces.ds + "enveloped-signature")
            SubElement(transforms, ds_tag("Transform"), Algorithm=self.c14n_alg)
        digest_method = SubElement(reference, ds_tag("DigestMethod"), Algorithm=self.known_digest_tags[self.digest_alg])
        digest_value = SubElement(reference, ds_tag("DigestValue"))
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
            named_curve = SubElement(ec_key_value, dsig11_tag("NamedCurve"),
                                     URI=self.known_ecdsa_curve_oids[key.curve.name])
            public_key = SubElement(ec_key_value, dsig11_tag("PublicKey"))
            x = key.public_key().public_numbers().x
            y = key.public_key().public_numbers().y
            public_key.text = ensure_str(b64encode(long_to_bytes(4) + long_to_bytes(x) + long_to_bytes(y)))

class XMLVerifier(XMLSignatureProcessor):
    """
    Create a new XML Signature Verifier object, which can be used to hold configuration information and verify multiple
    pieces of data.
    """
    def _verify_signature_with_pubkey(self, signed_info_c14n, raw_signature, key_value, signature_alg):
        if "ecdsa-" in signature_alg:
            ec_key_value = self._find(key_value, "ECKeyValue", namespace="dsig11")
            named_curve = self._find(ec_key_value, "NamedCurve", namespace="dsig11")
            public_key = self._find(ec_key_value, "PublicKey", namespace="dsig11")
            key_data = b64decode(public_key.text)[1:]
            x = bytes_to_long(key_data[:len(key_data)//2])
            y = bytes_to_long(key_data[len(key_data)//2:])
            curve_class = self.known_ecdsa_curves[named_curve.get("URI")]
            key = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve_class()).public_key(backend=default_backend())
            verifier = key.verifier(raw_signature, ec.ECDSA(self._get_signature_digest_method(signature_alg)))
        elif "dsa-" in signature_alg:
            dsa_key_value = self._find(key_value, "DSAKeyValue")
            p = self._get_long(dsa_key_value, "P")
            q = self._get_long(dsa_key_value, "Q")
            g = self._get_long(dsa_key_value, "G", require=False)
            y = self._get_long(dsa_key_value, "Y")
            pn = dsa.DSAPublicNumbers(y=y, parameter_numbers=dsa.DSAParameterNumbers(p=p, q=q, g=g))
            key = pn.public_key(backend=default_backend())
            der_seq = DERSequenceOfIntegers([bytes_to_long(raw_signature[:len(raw_signature)//2]),
                                             bytes_to_long(raw_signature[len(raw_signature)//2:])])
            sig_as_der_seq = der_encoder.encode(der_seq)
            verifier = key.verifier(sig_as_der_seq, self._get_signature_digest_method(signature_alg))
        elif "rsa-" in signature_alg:
            rsa_key_value = self._find(key_value, "RSAKeyValue")
            modulus = self._get_long(rsa_key_value, "Modulus")
            exponent = self._get_long(rsa_key_value, "Exponent")
            key = rsa.RSAPublicNumbers(e=exponent, n=modulus).public_key(backend=default_backend())
            verifier = key.verifier(raw_signature, padding=PKCS1v15(),
                                    algorithm=self._get_signature_digest_method(signature_alg))
        else:
            raise NotImplementedError()

        verifier.update(signed_info_c14n)
        verifier.verify()

    def _resolve_reference(self, doc_root, reference, uri_resolver=None):
        uri = reference.get("URI")
        if uri == "":
            return doc_root
        elif uri.startswith("#xpointer("):
            raise InvalidInput("XPointer references are not supported")
            # doc_root.xpath(uri.lstrip("#"))[0]
        elif uri.startswith("#"):
            for id_attribute in self.id_attributes:
                # results = doc_root.xpath("..//*[@*[local-name() = '{}']=$uri]".format(id_attribute),
                #                          uri=uri.lstrip("#"))
                results = doc_root.xpath("..//*[@{}=$uri]".format(id_attribute), uri=uri.lstrip("#"))
                if len(results) > 1:
                    raise InvalidInput("Ambiguous reference URI {} resolved to {} nodes".format(uri, len(results)))
                elif len(results) == 1:
                    return results[0]
            raise InvalidInput("Unable to resolve reference URI: {}".format(uri))
        else:
            if uri_resolver is None:
                raise InvalidInput("External URI dereferencing is not configured: {}".format(uri))
            result = uri_resolver(uri)
            if result is None:
                raise InvalidInput("Unable to resolve reference URI: {}".format(uri))
            return result

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
                _remove_sig(signature)

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

    def verify(self, data, require_x509=True, x509_cert=None, cert_subject_name=None, ca_pem_file=None, ca_path=None,
               hmac_key=None, validate_schema=True, parser=None, uri_resolver=None, id_attribute=None):
        """
        Verify the XML signature supplied in the data and return the XML node signed by the signature, or raise an
        exception if the signature is not valid. By default, this requires the signature to be generated using a valid
        X.509 certificate. To enable other means of signature validation, set the **require_x509** argument to `False`.

        .. admonition:: See what is signed

         It is important to understand and follow the best practice rule of "See what is signed" when verifying XML
         signatures. The gist of this rule is: if your application neglects to verify that the information it trusts is
         what was actually signed, the attacker can supply a valid signature but point you to malicious data that wasn't
         signed by that signature.

         In SignXML, you can ensure that the information signed is what you expect to be signed by only trusting the
         data returned by the ``verify()`` method. The return value is the XML node or string that was signed. Also,
         depending on the signature settings used, comments in the XML data may not be subject to signing, so may need
         to be untrusted.

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
        :type require_x509: boolean
        :param x509_cert:
            A trusted external X.509 certificate, given as a PEM-formatted string or OpenSSL.crypto.X509 object, to use
            for verification. Overrides any X.509 certificate information supplied by the signature. If left set to
            ``None``, requires that the signature supply a valid X.509 certificate chain that validates against the
            known certificate authorities. Implies **require_x509=True**.
        :type x509_cert: string or OpenSSL.crypto.X509
        :param ca_pem_file:
            Filename of a PEM file containing certificate authority information to use when verifying certificate-based
            signatures.
        :type ca_pem_file: string or bytes
        :param ca_path:
            Path to a directory containing PEM-formatted certificate authority files to use when verifying
            certificate-based signatures. If neither **ca_pem_file** nor **ca_path** is given, the Mozilla CA bundle
            provided by :py:mod:`certifi` will be loaded.
        :type ca_path: string
        :param cert_subject_name:
            Subject Common Name to check the signing X.509 certificate against. Implies **require_x509=True**.
        :type cert_subject_name: string
        :param hmac_key: If using HMAC, a string containing the shared secret.
        :type hmac_key: string
        :param validate_schema: Whether to validate **data** against the XML Signature schema.
        :type validate_schema: boolean
        :param parser: Custom XML parser instance to use when parsing **data**.
        :type parser: :py:class:`lxml.etree.XMLParser` compatible parser
        :param uri_resolver: Function to use to resolve reference URIs that don't start with "#".
        :type uri_resolver: callable
        :param id_attribute:
            Name of the attribute whose value ``URI`` refers to. By default, SignXML will search for "Id", then "ID".
        :type id_attribute: string

        :raises: :py:class:`cryptography.exceptions.InvalidSignature`

        :returns: VerifyResult object with the signed data, signed xml and signature xml
        :rtype: VerifyResult

        """
        self.hmac_key = hmac_key
        self.require_x509 = require_x509
        self.x509_cert = x509_cert
        self._parser = parser

        if x509_cert:
            self.require_x509 = True

        if id_attribute is None:
            self.id_attributes = ("Id", "ID", "id", "xml:id")
        else:
            self.id_attributes = (id_attribute, )

        root = self.get_root(data)
        if root.tag == ds_tag("Signature"):
            signature_ref = root
        else:
            signature_ref = self._find(root, "Signature", anywhere=True)

        # HACK: deep copy won't keep root's namespaces
        signature = fromstring(etree.tostring(signature_ref), parser=parser)

        if validate_schema:
            self.schema().assertValid(signature)

        signed_info = self._find(signature, "SignedInfo")
        c14n_method = self._find(signed_info, "CanonicalizationMethod")
        c14n_algorithm = c14n_method.get("Algorithm")
        reference = self._find(signed_info, "Reference")
        transforms = self._find(reference, "Transforms", require=False)
        signed_info_c14n = self._c14n(signed_info, algorithm=c14n_algorithm)
        digest_algorithm = self._find(reference, "DigestMethod").get("Algorithm")
        digest_value = self._find(reference, "DigestValue")
        signature_method = self._find(signed_info, "SignatureMethod")
        signature_value = self._find(signature, "SignatureValue")
        signature_alg = signature_method.get("Algorithm")
        raw_signature = b64decode(signature_value.text)
        x509_data = signature.find("ds:KeyInfo/ds:X509Data", namespaces=namespaces)

        if x509_data is not None or self.require_x509:
            from OpenSSL.crypto import load_certificate, X509, FILETYPE_PEM, verify, Error as OpenSSLCryptoError

            if self.x509_cert is None:
                if x509_data is None:
                    raise InvalidInput("Expected a X.509 certificate based signature")
                certs = [cert.text for cert in self._findall(x509_data, "X509Certificate")]
                if not certs:
                    msg = "Expected to find an X509Certificate element in the signature (X509SubjectName, X509SKI are not supported)"  # noqa
                    raise InvalidInput(msg)
                cert_chain = [load_certificate(FILETYPE_PEM, add_pem_header(cert)) for cert in certs]
                signing_cert = verify_x509_cert_chain(cert_chain, ca_pem_file=ca_pem_file, ca_path=ca_path)
            elif isinstance(self.x509_cert, X509):
                signing_cert = self.x509_cert
            else:
                signing_cert = load_certificate(FILETYPE_PEM, add_pem_header(self.x509_cert))

            if cert_subject_name and signing_cert.get_subject().commonName != cert_subject_name:
                raise InvalidSignature("Certificate subject common name mismatch")

            signature_digest_method = self._get_signature_digest_method(signature_alg).name
            try:
                verify(signing_cert, raw_signature, signed_info_c14n, signature_digest_method)
            except OpenSSLCryptoError as e:
                try:
                    lib, func, reason = e.message[0]
                except Exception:
                    reason = e
                raise InvalidSignature("Signature verification failed: {}".format(reason))
            # TODO: CN verification goes here
            # TODO: require one of the following to be set: either x509_cert or (ca_pem_file or ca_path) or common_name
            # Use ssl.match_hostname or code from it to perform match
        elif "hmac-sha" in signature_alg:
            if self.hmac_key is None:
                raise InvalidInput('Parameter "hmac_key" is required when verifying a HMAC signature')

            from cryptography.hazmat.primitives.hmac import HMAC
            signer = HMAC(key=ensure_bytes(self.hmac_key),
                          algorithm=self._get_hmac_digest_method(signature_alg),
                          backend=default_backend())
            signer.update(signed_info_c14n)
            if raw_signature != signer.finalize():
                raise InvalidSignature("Signature mismatch (HMAC)")
        else:
            key_value = signature.find("ds:KeyInfo/ds:KeyValue", namespaces=namespaces)
            if key_value is None:
                raise InvalidInput("Expected to find either KeyValue or X509Data XML element in KeyInfo")

            self._verify_signature_with_pubkey(signed_info_c14n, raw_signature, key_value, signature_alg)

        payload = self._resolve_reference(root, reference, uri_resolver=uri_resolver)
        payload_c14n = self._apply_transforms(payload, transforms, signature_ref, c14n_algorithm)

        if digest_value.text != self._get_digest(payload_c14n, self._get_digest_method(digest_algorithm)):
            raise InvalidDigest("Digest mismatch")

        # We return the signed XML (and only that) to ensure no access to unsigned data happens
        try:
            payload_c14n_xml = fromstring(payload_c14n)
        except etree.XMLSyntaxError:
            payload_c14n_xml = None
        return VerifyResult(payload_c14n, payload_c14n_xml, signature)

    def _get_long(self, element, query, require=True):
        result = self._find(element, query, require=require)
        if result is not None:
            result = bytes_to_long(b64decode(result.text))
        return result

def _add_cert_to_store(store, cert):
    from OpenSSL.crypto import X509StoreContext, X509StoreContextError, Error as OpenSSLCryptoError
    try:
        X509StoreContext(store, cert).verify_certificate()
    except X509StoreContextError as e:
        raise InvalidCertificate(e)
    try:
        store.add_cert(cert)
        return cert
    except OpenSSLCryptoError as e:
        if e.args == ([('x509 certificate routines', 'X509_STORE_add_cert', 'cert already in hash table')],):
            raise RedundantCert(e)
        raise

def verify_x509_cert_chain(cert_chain, ca_pem_file=None, ca_path=None):
    """
    Look at certs in the cert chain and add them to the store one by one.
    Return the cert at the end of the chain. That is the cert to be used by the caller for verifying.
    From https://www.w3.org/TR/xmldsig-core2/#sec-X509Data:
    "All certificates appearing in an X509Data element must relate to the validation key by either containing it
    or being part of a certification chain that terminates in a certificate containing the validation key.
    No ordering is implied by the above constraints"
    """
    from OpenSSL import SSL
    context = SSL.Context(SSL.TLSv1_METHOD)
    if ca_pem_file is None and ca_path is None:
        import certifi
        ca_pem_file = certifi.where()
    context.load_verify_locations(ensure_bytes(ca_pem_file, none_ok=True), capath=ca_path)
    store = context.get_cert_store()
    certs = list(reversed(cert_chain))
    end_of_chain, last_error = None, None
    while len(certs) > 0:
        for cert in certs:
            try:
                end_of_chain = _add_cert_to_store(store, cert)
                certs.remove(cert)
                break
            except RedundantCert:
                certs.remove(cert)
                if end_of_chain is None:
                    end_of_chain = cert
                break
            except Exception as e:
                last_error = e
        else:
            raise last_error
    return end_of_chain
