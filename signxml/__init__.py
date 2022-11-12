"""
Use :class:`signxml.XMLSigner` and :class:`signxml.XMLVerifier` to sign and verify XML Signatures, respectively.
See `SignXML documentation <#synopsis>`_ for examples.
"""

from .signer import XMLSigner, XMLSignatureReference
from .verifier import XMLVerifier, VerifyResult
from .algorithms import DigestAlgorithm, SignatureMethod, CanonicalizationMethod, SignatureConstructionMethod
from .exceptions import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature
from .processor import XMLSignatureProcessor
from .util import namespaces

methods = SignatureConstructionMethod
