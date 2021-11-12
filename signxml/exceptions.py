"""
SignXML exception types.
"""

import cryptography.exceptions

class InvalidSignature(cryptography.exceptions.InvalidSignature):
    """
    Raised when signature validation fails.
    """

class InvalidDigest(InvalidSignature):
    """
    Raised when digest validation fails (causing the signature to be untrusted).
    """

class InvalidCertificate(InvalidSignature):
    """
    Raised when certificate validation fails.
    """

class InvalidInput(ValueError):
    pass

class RedundantCert(Exception):
    pass
