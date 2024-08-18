"""
SignXML utility functions

bytes_to_long, long_to_bytes copied from https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py
"""

import math
import re
import struct
import textwrap
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Any, List, Optional

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from lxml.etree import QName

from ..exceptions import InvalidCertificate

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


class Namespace(dict):
    def __getattr__(self, a):
        return dict.__getitem__(self, a)


namespaces = Namespace(
    ds="http://www.w3.org/2000/09/xmldsig#",
    dsig11="http://www.w3.org/2009/xmldsig11#",
    dsig2="http://www.w3.org/2010/xmldsig2#",
    ec="http://www.w3.org/2001/10/xml-exc-c14n#",
    dsig_more="http://www.w3.org/2001/04/xmldsig-more#",
    xenc="http://www.w3.org/2001/04/xmlenc#",
    xenc11="http://www.w3.org/2009/xmlenc11#",
    xades="http://uri.etsi.org/01903/v1.3.2#",
    xades141="http://uri.etsi.org/01903/v1.4.1#",
)


def ds_tag(tag):
    return QName(namespaces.ds, tag)


def dsig11_tag(tag):
    return QName(namespaces.dsig11, tag)


def ec_tag(tag):
    return QName(namespaces.ec, tag)


def xades_tag(tag):
    return QName(namespaces.xades, tag)


def xades141_tag(tag):
    return QName(namespaces.xades141, tag)


@dataclass
class SigningSettings:
    key: Any
    key_name: Optional[str]
    key_info: Any
    always_add_key_value: bool
    cert_chain: Optional[List]


def ensure_bytes(x, encoding="utf-8", none_ok=False):
    if none_ok is True and x is None:
        return x
    if not isinstance(x, bytes):
        x = x.encode(encoding)
    return x


def ensure_str(x, encoding="utf-8", none_ok=False):
    if none_ok is True and x is None:
        return x
    if not isinstance(x, str):
        x = x.decode(encoding)
    return x


def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    if isinstance(s, int):
        # On Python 2, indexing into a bytearray returns a byte string; on Python 3, an int.
        return s
    acc = 0
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = 4 - length % 4
        s = b"\000" * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack(b">I", s[i : i + 4])[0]
    return acc


def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b""
    pack = struct.pack
    while n > 0:
        s = pack(b">I", n & 0xFFFFFFFF) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b"\000"[0]:
            break
    else:
        # only happens when n == 0
        s = b"\000"
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b"\000" + s
    return s


def bits_to_bytes_unit(num_of_bits):
    """bits_to_bytes_unit(num_of_bits:int) : int
    Convert the unit of measurement for the argument from bits to bytes.

    Rounds up to the nearest whole byte.
    """
    return int(math.ceil(num_of_bits / 8))


pem_regexp = re.compile(
    "{header}{nl}(.+?){footer}".format(header=PEM_HEADER, nl="\r{0,1}\n", footer=PEM_FOOTER), flags=re.S
)


def strip_pem_header(cert):
    search_res = re.search(pem_regexp, ensure_str(cert))
    if search_res:
        return search_res.group(1).replace("\r", "")
    return ensure_str(cert).replace("\r", "")


def add_pem_header(bare_base64_cert):
    bare_base64_cert = ensure_str(bare_base64_cert)
    if bare_base64_cert.startswith(PEM_HEADER):
        return bare_base64_cert.encode()
    cert_with_header = PEM_HEADER + "\n" + textwrap.fill(bare_base64_cert, 64) + "\n" + PEM_FOOTER
    return cert_with_header.encode()


def iterate_pem(certs):
    for match in re.findall(pem_regexp, ensure_str(certs)):
        yield match


def hmac_sha1(key, message):
    hasher = hmac.HMAC(key, hashes.SHA1())
    hasher.update(message)
    return hasher.finalize()


def raw_p_sha1(secret, seed, sizes=()):
    """
    Derive one or more keys from secret and seed.
    (See specs part 6, 6.7.5 and RFC 2246 - TLS v1.0)
    Lengths of keys will match sizes argument

    Source: https://github.com/FreeOpcUa/python-opcua
    key_sizes = (signature_key_size, symmetric_key_size, 16)
    (sigkey, key, init_vec) = p_sha1(nonce2, nonce1, key_sizes)
    """
    full_size = 0
    for size in sizes:
        full_size += size

    result = b""
    accum = seed
    while len(result) < full_size:
        accum = hmac_sha1(secret, accum)
        result += hmac_sha1(secret, accum + seed)

    parts = []
    for size in sizes:
        parts.append(result[:size])
        result = result[size:]
    return tuple(parts)


def p_sha1(client_b64_bytes, server_b64_bytes):
    client_bytes, server_bytes = b64decode(client_b64_bytes), b64decode(server_b64_bytes)
    return b64encode(raw_p_sha1(client_bytes, server_bytes, (len(client_bytes), len(server_bytes)))[0]).decode()


class X509CertChainVerifier:
    """
    Look at certs in the cert chain and add them to the store one by one.
    Return the cert at the end of the chain. That is the cert to be used by the caller for verifying.
    From https://www.w3.org/TR/xmldsig-core2/#sec-X509Data:
    "All certificates appearing in an X509Data element must relate to the validation key by either containing it
    or being part of a certification chain that terminates in a certificate containing the validation key.
    No ordering is implied by the above constraints"

    Note: SignXML no longer uses OpenSSL for certificate chain verificaiton. The CApath parameter supported by OpenSSL
    is not supported by cryptography. The CApath parameter is used to specify a directory containing CA certificates in
    PEM format. The files each contain one CA certificate. The files are looked up by the CA subject name hash value.
    See https://docs.openssl.org/master/man3/SSL_CTX_load_verify_locations/#notes. If you need CApath support, please
    contact SignXML maintainers.
    """

    def __init__(self, ca_pem_file=None, ca_path=None, verification_time=None):
        if ca_pem_file is None:
            ca_pem_file = certifi.where()
        self.ca_pem_file = ca_pem_file
        if ca_path is not None:
            msg = "CApath is not supported. If you need this feature, please contact SignXML maintainers."
            raise NotImplementedError(msg)

        self.verification_time = verification_time

    @property
    def store(self):
        with open(self.ca_pem_file, "rb") as pems:
            certs = x509.load_pem_x509_certificates(pems.read())
        return x509.verification.Store(certs)

    @property
    def builder(self):
        builder = x509.verification.PolicyBuilder()
        builder = builder.store(self.store)
        if self.verification_time is not None:
            builder = builder.time(self.verification_time)
        return builder

    @property
    def verifier(self):
        return self.builder.build_client_verifier()

    def _do_verify(self, cert_chain):
        leaf, intermediates = cert_chain[0], cert_chain[1:]
        result = self.verifier.verify(leaf=leaf, intermediates=intermediates)
        return result.chain[0]

    def verify(self, cert_chain):
        try:
            return self._do_verify(cert_chain)
        except x509.verification.VerificationError:
            try:
                return self._do_verify(list(reversed(cert_chain)))
            except x509.verification.VerificationError as e:
                raise InvalidCertificate(e)


def _remove_sig(signature, idempotent=False):
    """
    Remove the signature node from its parent, keeping any tail element.
    This is needed for eneveloped signatures.

    :param signature: Signature to remove from payload
    :type signature: XML ElementTree Element
    :param idempotent:
        If True, don't raise an error if signature is already detached from parent.
    :type idempotent: boolean
    """
    try:
        signaturep = next(signature.iterancestors())
    except StopIteration:
        if idempotent:
            return
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
