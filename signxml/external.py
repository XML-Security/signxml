"""Provider-independent signing with private keys held outside SignXML."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS, PKCS1v15

from .algorithms import SignatureMethod, digest_algorithm_implementations
from .exceptions import InvalidInput, InvalidSignature


@dataclass(frozen=True)
class SigningRequest:
    """The message and algorithm supplied to an external signing callback.

    Use :attr:`data` with a provider that hashes messages, or :attr:`digest`
    with a provider's prehashed/digest mode. Do not hash :attr:`digest` again.
    This message is canonicalized ``SignedInfo``, including all reference
    digests and signature annotations; it is not the original XML payload.
    """

    data: bytes = field(repr=False)
    "The canonicalized SignedInfo bytes, ready for message-mode signing."

    signature_algorithm: SignatureMethod
    "The XMLDSig signature method, including its hash and padding requirements."

    @property
    def hash_algorithm(self) -> hashes.HashAlgorithm:
        "The cryptography hash algorithm selected by the signature method."
        return digest_algorithm_implementations[self.signature_algorithm]()

    @property
    def digest(self) -> bytes:
        "The hash of data, ready for a provider's digest mode (without RSA DigestInfo wrapping)."
        hasher = hashes.Hash(self.hash_algorithm)
        hasher.update(self.data)
        return hasher.finalize()


class ExternalSigningKey:
    """An asymmetric public key paired with an application-supplied signing callback.

    Pass this object as ``key=`` to :meth:`signxml.XMLSigner.sign` or
    :meth:`signxml.xades.XAdESSigner.sign`. The private key stays with the
    provider, which can be a cloud service, HSM, hardware token, or OS keystore.

    :param public_key:
        The corresponding cryptography RSA, EC, or DSA public-key object.
        It is used for KeyValue generation and to verify the callback's result.
    :param signer:
        A synchronous callable taking one :class:`SigningRequest` and returning
        signature bytes. Return raw RSA signature bytes, or an ASN.1 DER
        Dss-Sig-Value for ECDSA/DSA, as cryptography's sign methods do. Do not
        return base64 or XML. SignXML converts DER signatures to XMLDSig's
        fixed-width format and base64-encodes the result.

    RSA_* methods require PKCS#1 v1.5 padding. *_RSA_MGF1 methods require PSS,
    MGF1 with the signature hash, and a salt of the hash's digest size.
    The callback must honor the requested method or raise an exception.

    SignXML calls the callback once per signature, after building SignedInfo.
    It makes no provider calls of its own. Authentication, key identifiers,
    timeouts, retries, response decoding, and provider errors belong to the
    callback. Callback exceptions propagate unchanged; there are no automatic
    retries or local-key fallbacks.
    """

    def __init__(
        self,
        *,
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey | dsa.DSAPublicKey,
        signer: Callable[[SigningRequest], bytes],
    ):
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, dsa.DSAPublicKey)):
            raise InvalidInput("ExternalSigningKey requires an RSA, EC, or DSA public key")
        if not callable(signer):
            raise InvalidInput("ExternalSigningKey requires a callable signer")
        self._public_key = public_key
        self._signer = signer

    def public_key(self) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey | dsa.DSAPublicKey:
        "Return the public key used to check the provider's signatures."
        return self._public_key

    @property
    def key_size(self) -> int:
        "The size in bits of the public key."
        return self._public_key.key_size

    def _check_signature_algorithm(self, algorithm: SignatureMethod) -> None:
        if isinstance(self._public_key, rsa.RSAPublicKey):
            supported = algorithm.name.startswith("RSA_") or algorithm.name.endswith("_RSA_MGF1")
        elif isinstance(self._public_key, ec.EllipticCurvePublicKey):
            supported = algorithm.name.startswith("ECDSA_")
        else:
            supported = algorithm.name.startswith("DSA_")
        if not supported:
            raise InvalidInput(f"Signature method {algorithm.name} is incompatible with the external public key")

    def sign(self, request: SigningRequest) -> bytes:
        """Call the provider and verify its result before returning signature bytes.

        This only checks the signature against the configured public key; it
        does not establish certificate trust, validity, or provider identity.
        """
        self._check_signature_algorithm(request.signature_algorithm)
        signature = self._signer(request)
        if not isinstance(signature, bytes):
            raise InvalidInput("External signer must return signature bytes")
        hash_algorithm = request.hash_algorithm
        try:
            if isinstance(self._public_key, rsa.RSAPublicKey):
                if request.signature_algorithm.name.startswith("RSA_"):
                    self._public_key.verify(signature, request.data, PKCS1v15(), hash_algorithm)
                else:
                    padding = PSS(mgf=MGF1(hash_algorithm), salt_length=hash_algorithm.digest_size)
                    self._public_key.verify(signature, request.data, padding, hash_algorithm)
            elif isinstance(self._public_key, ec.EllipticCurvePublicKey):
                self._public_key.verify(signature, request.data, ec.ECDSA(hash_algorithm))
            else:
                self._public_key.verify(signature, request.data, hash_algorithm)
        except (exceptions.InvalidSignature, ValueError) as exc:
            raise InvalidSignature(
                "External signer returned a signature that does not match the request and public key"
            ) from exc
        return signature
