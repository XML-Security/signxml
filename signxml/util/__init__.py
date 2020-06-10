"""
SignXML utility functions

bytes_to_long, long_to_bytes copied from https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import math
import os, sys, re, struct, textwrap
from xml.etree import ElementTree as stdlibElementTree
from base64 import b64encode, b64decode

from eight import str, bytes
from lxml import etree

from ..exceptions import RedundantCert, InvalidCertificate, InvalidInput

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


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
    if USING_PYTHON2:
        acc = long(acc)  # noqa
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack(b'>I', s[i:i + 4])[0]
    return acc


def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b''
    if USING_PYTHON2:
        n = long(n)  # noqa
    pack = struct.pack
    while n > 0:
        s = pack(b'>I', n & 0xffffffff) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b'\000'[0]:
            break
    else:
        # only happens when n == 0
        s = b'\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b'\000' + s
    return s


def bits_to_bytes_unit(num_of_bits):
    """bits_to_bytes_unit(num_of_bits:int) : int
    Convert the unit of measurement for the argument from bits to bytes.

    Rounds up to the nearest whole byte.
    """
    return int(math.ceil(num_of_bits / 8))


pem_regexp = re.compile("{header}{nl}(.+?){footer}".format(header=PEM_HEADER, nl="\r{0,1}\n", footer=PEM_FOOTER),
                        flags=re.S)


def strip_pem_header(cert):
    try:
        return re.search(pem_regexp, ensure_str(cert)).group(1).replace("\r", "")
    except Exception:
        return ensure_str(cert).replace("\r", "")


def add_pem_header(bare_base64_cert):
    bare_base64_cert = ensure_str(bare_base64_cert)
    if bare_base64_cert.startswith(PEM_HEADER):
        return bare_base64_cert
    return PEM_HEADER + "\n" + textwrap.fill(bare_base64_cert, 64) + "\n" + PEM_FOOTER


def iterate_pem(certs):
    for match in re.findall(pem_regexp, ensure_str(certs)):
        yield match


class Namespace(dict):
    def __getattr__(self, a):
        return dict.__getitem__(self, a)


class XMLProcessor:
    _schema, _default_parser = None, None

    @classmethod
    def schema(cls):
        if cls._schema is None:
            schema_path = os.path.join(os.path.dirname(__file__), "..", "schemas", cls.schema_file)
            cls._schema = etree.XMLSchema(etree.parse(schema_path))
        return cls._schema

    @property
    def parser(self):
        if self._parser is None:
            if self._default_parser is None:
                self._default_parser = etree.XMLParser(resolve_entities=False)
            return self._default_parser
        return self._parser

    def fromstring(self, xml_string, **kwargs):
        xml_node = etree.fromstring(xml_string, parser=self.parser, **kwargs)
        for entity in xml_node.iter(etree.Entity):
            raise InvalidInput("Entities are not supported in XML input")
        return xml_node

    def tostring(self, xml_node, **kwargs):
        return etree.tostring(xml_node, **kwargs)

    def get_root(self, data):
        if isinstance(data, (str, bytes)):
            return self.fromstring(data)
        elif isinstance(data, stdlibElementTree.Element):
            # TODO: add debug level logging statement re: performance impact here
            return self.fromstring(stdlibElementTree.tostring(data, encoding="utf-8"))
        else:
            # HACK: deep copy won't keep root's namespaces resulting in an invalid digest
            # We use a copy so we can modify the tree
            # TODO: turn this off for xmlenc
            return self.fromstring(etree.tostring(data))


def hmac_sha1(key, message):
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.backends import default_backend
    hasher = hmac.HMAC(key, hashes.SHA1(), backend=default_backend())
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

    result = b''
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
    # TODO: migrate to Cryptography (pending cert validation support) or https://github.com/wbond/certvalidator
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
