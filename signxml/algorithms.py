from enum import Enum
from typing import Callable, Dict, Type, Union

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

    def __repr__(self):
        return f"{self.__class__.__name__}.{self.name}"  # type: ignore


class DigestAlgorithm(FragmentLookupMixin, InvalidInputErrorMixin, Enum):
    """
    An enumeration of digest algorithms supported by SignXML.  See the
    `Algorithm Identifiers and Implementation Requirements <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of
    the XML Signature 1.1 standard for details.
    """

    SHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224"
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
    SHA3_224 = "http://www.w3.org/2007/05/xmldsig-more#sha3-224"
    SHA3_256 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256"
    SHA3_384 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384"
    SHA3_512 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512"

    SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
    "See `SHA1 deprecation`_."

    @property
    def implementation(self) -> Callable:
        """
        The cryptography callable that implements the specified algorithm.
        """
        return digest_algorithm_implementations[self]


# TODO: check if padding errors are fixed by using padding=MGF1
class SignatureMethod(FragmentLookupMixin, InvalidInputErrorMixin, Enum):
    """
    An enumeration of signature methods (also referred to as signature algorithms) supported by SignXML. See the
    `Algorithm Identifiers and Implementation Requirements <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of
    the XML Signature 1.1 standard for details.
    """

    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    """
    The RSASSA-PKCS1-v1_5 algorithm described in RFC 3447. This is the default, most widely supported signature method.
    """

    RSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    ECDSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
    ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
    ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
    ECDSA_SHA3_224 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224"
    ECDSA_SHA3_256 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256"
    ECDSA_SHA3_384 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384"
    ECDSA_SHA3_512 = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512"
    DSA_SHA256 = "http://www.w3.org/2009/xmldsig11#dsa-sha256"
    HMAC_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224"
    HMAC_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
    HMAC_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
    HMAC_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
    SHA3_224_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1"
    SHA3_256_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1"
    SHA3_384_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1"
    SHA3_512_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1"
    SHA224_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1"
    SHA256_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
    SHA384_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
    SHA512_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"

    DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
    """
    _`SHA1 deprecation`: SHA1 based algorithms are not secure for use in digital signatures. They are included for
    legacy compatibility only and disabled by default. To verify SHA1 based signatures, use::

        XMLVerifier().verify(
            expect_config=SignatureConfiguration(
                signature_methods=...,
                digest_algorithms=...
            )
        )
    """
    HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
    "See `SHA1 deprecation`_."
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    "See `SHA1 deprecation`_."
    ECDSA_SHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
    "See `SHA1 deprecation`_."
    SHA1_RSA_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1"
    "See `SHA1 deprecation`_."


class CanonicalizationMethod(InvalidInputErrorMixin, Enum):
    """
    An enumeration of XML canonicalization methods (also referred to as canonicalization algorithms) supported by
    SignXML. See the `Algorithm Identifiers and Implementation Requirements
    <http://www.w3.org/TR/xmldsig-core1/#sec-AlgID>`_ section of the XML Signature 1.1 standard for details.
    """

    CANONICAL_XML_1_0 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    CANONICAL_XML_1_0_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
    CANONICAL_XML_1_1 = "http://www.w3.org/2006/12/xml-c14n11"
    CANONICAL_XML_1_1_WITH_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
    EXCLUSIVE_XML_CANONICALIZATION_1_0 = "http://www.w3.org/2001/10/xml-exc-c14n#"
    EXCLUSIVE_XML_CANONICALIZATION_1_0_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

    # The identifier for Canonical XML 2.0 is "http://www.w3.org/2010/xml-c14n2", but it is not a W3C standard.
    # While it is supported by lxml, it's not in general use and not supported by SignXML


digest_algorithm_implementations: Dict[Union[DigestAlgorithm, SignatureMethod], Type[hashes.HashAlgorithm]] = {
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
    SignatureMethod.SHA3_224_RSA_MGF1: hashes.SHA3_224,
    SignatureMethod.SHA3_256_RSA_MGF1: hashes.SHA3_256,
    SignatureMethod.SHA3_384_RSA_MGF1: hashes.SHA3_384,
    SignatureMethod.SHA3_512_RSA_MGF1: hashes.SHA3_512,
    SignatureMethod.SHA224_RSA_MGF1: hashes.SHA224,
    SignatureMethod.SHA256_RSA_MGF1: hashes.SHA256,
    SignatureMethod.SHA384_RSA_MGF1: hashes.SHA384,
    SignatureMethod.SHA512_RSA_MGF1: hashes.SHA512,
    SignatureMethod.SHA1_RSA_MGF1: hashes.SHA1,
}
