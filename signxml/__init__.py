"""
Use :class:`signxml.XMLSigner` and :class:`signxml.XMLVerifier` to sign and verify XML Signatures, respectively.
See `SignXML documentation <#synopsis>`_ for examples.
"""

from .algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureConstructionMethod, SignatureMethod
from .exceptions import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature
from .processor import XMLSignatureProcessor
from .signer import SignatureReference, XMLSigner
from .util import namespaces
from .verifier import SignatureConfiguration, VerifyResult, XMLVerifier

methods = SignatureConstructionMethod
