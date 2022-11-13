from enum import Enum
from typing import Callable

from cryptography.hazmat.primitives import hashes

from .exceptions import InvalidInput


class SignatureConstructionMethod(Enum):
    """
    An enumeration of signature construction methods supported by SignXML, used to specify the method when signing.
    See the list of signature types under `XML Signature Syntax and Processing Version 2.0, Definitions
    <http://www.w3.org/TR/xmldsig-core2/#sec-Definitions>`_.
    """

    enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    """
    The signature is over the XML content that contains the signature as an element. The content provides the root
    XML document element. This is the most common XML signature type in modern applications.
    """

    enveloping = "enveloping-signature"
    """
    The signature is over content found within an Object element of the signature itself. The Object (or its
    content) is identified via a Reference (via a URI fragment identifier or transform).
    """

    detached = "detached-signature"
    """
    The signature is over content external to the Signature element, and can be identified via a URI or
    transform. Consequently, the signature is "detached" from the content it signs. This definition typically applies to
    separate data objects, but it also includes the instance where the Signature and data object reside within the same
    XML document but are sibling elements.
    """


class FragmentLookupMixin:
    @classmethod
    def from_fragment(cls, fragment):
        for i in cls:  # type: ignore
            if i.value.endswith("#" + fragment):
                return i
        else:
            raise InvalidInput(f"Unrecognized {cls.__name__} identifier fragment: {fragment}")


class InvalidInputErrorMixin:
    @classmethod
    def _missing_(cls, value):
        raise InvalidInput(f"Unrecognized {cls.__name__}: {value}")


class DigestAlgorithm(FragmentLookupMixin, InvalidInputErrorMixin, Enum):
    """
    An enumeration of digest algorithms supported by SignXML. See `RFC 9231
    <https://www.rfc-editor.org/rfc/rfc9231.html>`_ and the `Algorithm Identifiers and Implementation Requirements
    <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature 1.1 standard for details.
    """

    SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
    SHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224"
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
    SHA3_224 = "http://www.w3.org/2007/05/xmldsig-more#sha3-224"
    SHA3_256 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256"
    SHA3_384 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384"
    SHA3_512 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512"

    @property
    def implementation(self) -> Callable:
        """
        The cryptography callable that implements the specified algorithm.
        """
        return digest_algorithm_implementations[self]


# TODO: check if padding errors are fixed by using padding=MGF1
class SignatureMethod(FragmentLookupMixin, InvalidInputErrorMixin, Enum):
    """
    An enumeration of signature methods (also referred to as signature algorithms) supported by SignXML. See `RFC 9231
    <https://www.rfc-editor.org/rfc/rfc9231.html>`_ and the `Algorithm Identifiers and Implementation Requirements
    <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature 1.1 standard for details.
    """

    DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
    HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    ECDSA_SHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
    ECDSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
    ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
    ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
    HMAC_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224"
    HMAC_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
    HMAC_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
    HMAC_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
    RSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    RSA_PSS = "http://www.w3.org/2007/05/xmldsig-more#rsa-pss"
    DSA_SHA256 = "http://www.w3.org/2009/xmldsig11#dsa-sha256"
    ECDSA_SHA3_224 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224"
    ECDSA_SHA3_256 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256"
    ECDSA_SHA3_384 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384"
    ECDSA_SHA3_512 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512"
    EDDSA_ED25519 = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
    EDDSA_ED448 = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448"


class CanonicalizationMethod(InvalidInputErrorMixin, Enum):
    """
    An enumeration of XML canonicalization methods (also referred to as canonicalization algorithms) supported by
    SignXML. See `RFC 9231 <https://www.rfc-editor.org/rfc/rfc9231.html>`_ and the `Algorithm Identifiers and
    Implementation Requirements <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature 1.1
    standard for details.
    """

    CANONICAL_XML_1_0 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    CANONICAL_XML_1_0_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
    CANONICAL_XML_1_1 = "http://www.w3.org/2006/12/xmlc14n11#"
    CANONICAL_XML_1_1_DEPRECATED_URI = "http://www.w3.org/2006/12/xml-c14n11"
    CANONICAL_XML_1_1_WITH_COMMENTS = "http://www.w3.org/2006/12/xmlc14n11#WithComments"
    EXCLUSIVE_XML_CANONICALIZATION_1_0 = "http://www.w3.org/2001/10/xml-exc-c14n#"
    EXCLUSIVE_XML_CANONICALIZATION_1_0_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"


digest_algorithm_implementations = {
    DigestAlgorithm.SHA1: hashes.SHA1,
    DigestAlgorithm.SHA224: hashes.SHA224,
    DigestAlgorithm.SHA384: hashes.SHA384,
    DigestAlgorithm.SHA256: hashes.SHA256,
    DigestAlgorithm.SHA512: hashes.SHA512,
    DigestAlgorithm.SHA3_224: hashes.SHA3_224,
    DigestAlgorithm.SHA3_256: hashes.SHA3_256,
    DigestAlgorithm.SHA3_384: hashes.SHA3_384,
    DigestAlgorithm.SHA3_512: hashes.SHA3_512,
    SignatureMethod.DSA_SHA1: hashes.SHA1,
    SignatureMethod.HMAC_SHA1: hashes.SHA1,
    SignatureMethod.RSA_SHA1: hashes.SHA1,
    SignatureMethod.ECDSA_SHA1: hashes.SHA1,
    SignatureMethod.ECDSA_SHA224: hashes.SHA224,
    SignatureMethod.ECDSA_SHA256: hashes.SHA256,
    SignatureMethod.ECDSA_SHA384: hashes.SHA384,
    SignatureMethod.ECDSA_SHA512: hashes.SHA512,
    SignatureMethod.HMAC_SHA224: hashes.SHA224,
    SignatureMethod.HMAC_SHA256: hashes.SHA256,
    SignatureMethod.HMAC_SHA384: hashes.SHA384,
    SignatureMethod.HMAC_SHA512: hashes.SHA512,
    SignatureMethod.RSA_SHA224: hashes.SHA224,
    SignatureMethod.RSA_SHA256: hashes.SHA256,
    SignatureMethod.RSA_SHA384: hashes.SHA384,
    SignatureMethod.RSA_SHA512: hashes.SHA512,
    SignatureMethod.DSA_SHA256: hashes.SHA256,
    SignatureMethod.ECDSA_SHA3_224: hashes.SHA3_224,
    SignatureMethod.ECDSA_SHA3_256: hashes.SHA3_256,
    SignatureMethod.ECDSA_SHA3_384: hashes.SHA3_384,
    SignatureMethod.ECDSA_SHA3_512: hashes.SHA3_512,
    SignatureMethod.EDDSA_ED25519: hashes.SHA512,
    SignatureMethod.EDDSA_ED448: hashes.SHAKE256,
}
