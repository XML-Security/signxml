"""
SignXML utility functions

bytes_to_long, long_to_bytes copied from https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py
"""

from __future__ import print_function, unicode_literals

import struct, textwrap

from eight import *

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"

def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack(b'>I', s[i:i+4])[0]
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
    n = long(n)
    pack = struct.pack
    while n > 0:
        s = pack(b'>I', n & 0xffffffffL) + s
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

def strip_pem_header(cert):
    bare_base64_cert = ""
    for line in cert.splitlines():
        if line != PEM_HEADER and line != PEM_FOOTER:
            bare_base64_cert += line
    return bare_base64_cert

def add_pem_header(bare_base64_cert):
    return PEM_HEADER + "\n" + textwrap.fill(bare_base64_cert, 64) + "\n" + PEM_FOOTER
