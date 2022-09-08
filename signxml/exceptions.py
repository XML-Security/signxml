"""
SignXML exception types.
"""

import cryptography.exceptions


class SignXMLException(Exception):
    pass


class InvalidSignature(cryptography.exceptions.InvalidSignature, SignXMLException):
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


class InvalidInput(ValueError, SignXMLException):
    pass


class RedundantCert(SignXMLException):
    pass
