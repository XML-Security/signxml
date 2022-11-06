from enum import Enum, auto

from cryptography.hazmat.primitives import hashes

from .exceptions import InvalidInput


class XMLSignatureMethods(Enum):
    enveloped = auto()
    enveloping = auto()
    detached = auto()


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


class XMLSecurityDigestAlgorithm(FragmentLookupMixin, InvalidInputErrorMixin, Enum):
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
    def implementation(self):
        return digest_algorithm_implementations[self]


# TODO: check if padding errors are fixed by using padding=MGF1
class XMLSecuritySignatureMethod(FragmentLookupMixin, InvalidInputErrorMixin, Enum):
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


digest_algorithm_implementations = {
    XMLSecurityDigestAlgorithm.SHA1: hashes.SHA1,
    XMLSecurityDigestAlgorithm.SHA224: hashes.SHA224,
    XMLSecurityDigestAlgorithm.SHA384: hashes.SHA384,
    XMLSecurityDigestAlgorithm.SHA256: hashes.SHA256,
    XMLSecurityDigestAlgorithm.SHA512: hashes.SHA512,
    XMLSecurityDigestAlgorithm.SHA3_224: hashes.SHA3_224,
    XMLSecurityDigestAlgorithm.SHA3_256: hashes.SHA3_256,
    XMLSecurityDigestAlgorithm.SHA3_384: hashes.SHA3_384,
    XMLSecurityDigestAlgorithm.SHA3_512: hashes.SHA3_512,
    XMLSecuritySignatureMethod.DSA_SHA1: hashes.SHA1,
    XMLSecuritySignatureMethod.HMAC_SHA1: hashes.SHA1,
    XMLSecuritySignatureMethod.RSA_SHA1: hashes.SHA1,
    XMLSecuritySignatureMethod.ECDSA_SHA1: hashes.SHA1,
    XMLSecuritySignatureMethod.ECDSA_SHA224: hashes.SHA224,
    XMLSecuritySignatureMethod.ECDSA_SHA256: hashes.SHA256,
    XMLSecuritySignatureMethod.ECDSA_SHA384: hashes.SHA384,
    XMLSecuritySignatureMethod.ECDSA_SHA512: hashes.SHA512,
    XMLSecuritySignatureMethod.HMAC_SHA224: hashes.SHA224,
    XMLSecuritySignatureMethod.HMAC_SHA256: hashes.SHA256,
    XMLSecuritySignatureMethod.HMAC_SHA384: hashes.SHA384,
    XMLSecuritySignatureMethod.HMAC_SHA512: hashes.SHA512,
    XMLSecuritySignatureMethod.RSA_SHA224: hashes.SHA224,
    XMLSecuritySignatureMethod.RSA_SHA256: hashes.SHA256,
    XMLSecuritySignatureMethod.RSA_SHA384: hashes.SHA384,
    XMLSecuritySignatureMethod.RSA_SHA512: hashes.SHA512,
    XMLSecuritySignatureMethod.DSA_SHA256: hashes.SHA256,
    XMLSecuritySignatureMethod.ECDSA_SHA3_224: hashes.SHA1,
    XMLSecuritySignatureMethod.ECDSA_SHA3_256: hashes.SHA1,
    XMLSecuritySignatureMethod.ECDSA_SHA3_384: hashes.SHA1,
    XMLSecuritySignatureMethod.ECDSA_SHA3_512: hashes.SHA1,
    XMLSecuritySignatureMethod.EDDSA_ED25519: hashes.SHA512,
    XMLSecuritySignatureMethod.EDDSA_ED448: hashes.SHAKE256,
}
