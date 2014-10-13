# Copied from https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/asn1.py
#
#  Util/asn1.py : Minimal support for ASN.1 DER binary encoding.
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================
""" ASN.1 DER encoding and decoding

This module provides minimal support for encoding and decoding `ASN.1`_ DER
objects.

.. _`ASN.1`: ftp://ftp.rsasecurity.com/pub/pkcs/ascii/layman.asc

"""

from __future__ import nested_scopes

import sys

from . import long_to_bytes, bytes_to_long

if sys.version_info[0] == 2:
    def bchr(s):
        return chr(s)
    def bord(s):
        return ord(s)
    from StringIO import StringIO as BytesIO
else:
    import BytesIO
    def bchr(s):
        return bytes([s])
    def bord(s):
        return s

def _isInt(x, onlyNonNegative=False):
    test = 0
    try:
        test += x
    except TypeError:
        return False
    return not onlyNonNegative or x>=0

class BytesIO_EOF(BytesIO):
    """This class differs from BytesIO in that an EOFError exception is
    raised whenever EOF is reached."""

    def __init__(self, *params):
        BytesIO.__init__(self, *params)
        self.setRecord(False)

    def setRecord(self, record):
        self._record = record
        self._recording = b""

    def read(self, length):
        s = BytesIO.read(self, length)
        if len(s)<length:
            raise EOFError
        if self._record:
            self._recording += s
        return s

    def read_byte(self):
        return self.read(1)[0]

class _NoDerElementError(EOFError):
    pass

class DerObject(object):
        """Base class for defining a single DER object.

        This class should never be directly instantiated.
        """

        def __init__(self, asn1Id=None, payload=b'', implicit=None, constructed=False):
                """Initialize the DER object according to a specific ASN.1 type.

                :Parameters:
                  asn1Id : integer
                    The universal DER tag identifier for this object
                    (e.g. 0x10 for a SEQUENCE). If None, the tag is not known
                    yet.

                  payload : byte string
                    The initial payload of the object.
                    If not specified, the payload is empty.

                  implicit : integer
                    The IMPLICIT tag to use for the encoded object.
                    It overrides the universal tag *asn1Id*.

                  constructed : bool
                    True when the ASN.1 type is *constructed*.
                    False when it is *primitive*.
                """

                if asn1Id==None:
                    self._idOctet = None
                    return
                asn1Id = self._convertTag(asn1Id)
                self._implicit = implicit
                if implicit:
                    # In a BER/DER identifier octet:
                    # * bits 4-0 contain the tag value
                    # * bit 5 is set if the type is 'construted'
                    #   and unset if 'primitive'
                    # * bits 7-6 depend on the encoding class
                    #
                    # Class        | Bit 7, Bit 6
                    # universal    |   0      0
                    # application  |   0      1
                    # context-spec |   1      0 (default for IMPLICIT)
                    # private      |   1      1
                    #
                    self._idOctet = 0x80 | self._convertTag(implicit)
                else:
                    self._idOctet = asn1Id
                if constructed:
                    self._idOctet |= 0x20
                self.payload = payload

        def _convertTag(self, tag):
                """Check if *tag* is a real DER tag.
                Convert it from a character to number if necessary.
                """
                if not _isInt(tag):
                    if len(tag)==1:
                        tag = bord(tag[0])
                # Ensure that tag is a low tag
                if not (_isInt(tag) and 0 <= tag < 0x1F):
                    raise ValueError("Wrong DER tag")
                return tag

        def _lengthOctets(self):
                """Build length octets according to the current object's payload.

                Return a byte string that encodes the payload length (in
                bytes) in a format suitable for DER length octets (L).
                """
                payloadLen = len(self.payload)
                if payloadLen>127:
                        encoding = long_to_bytes(payloadLen)
                        return bchr(len(encoding)+128) + encoding
                return bchr(payloadLen)

        def encode(self):
                """Return this DER element, fully encoded as a binary byte string."""
                # Concatenate identifier octets, length octets,
                # and contents octets
                return bchr(self._idOctet) + self._lengthOctets() + self.payload

        def _decodeLen(self, s):
                """Decode DER length octets from a file."""

                length = bord(s.read_byte())
                if length<=127:
                        return length
                payloadLength = bytes_to_long(s.read(length & 0x7F))
                # According to DER (but not BER) the long form is used
                # only when the length doesn't fit into 7 bits.
                if payloadLength<=127:
                        raise ValueError("Not a DER length tag (but still valid BER).")
                return payloadLength

        def decode(self, derEle):
                """Decode a complete DER element, and re-initializes this
                object with it.

                :Parameters:
                  derEle : byte string
                    A complete DER element.

                :Raise ValueError:
                  In case of parsing errors.
                :Raise EOFError:
                  If the DER element is too short.
                """

                s = BytesIO_EOF(derEle)
                self._decodeFromStream(s)
                # There shouldn't be other bytes left
                try:
                    b = s.read_byte()
                    raise ValueError("Unexpected extra data after the DER structure")
                except EOFError:
                    pass

        def _decodeFromStream(self, s):
                """Decode a complete DER element from a file."""

                try:
                    idOctet = bord(s.read_byte())
                except EOFError:
                    raise _NoDerElementError
                if self._idOctet != None:
                    if idOctet != self._idOctet:
                        raise ValueError("Unexpected DER tag")
                else:
                    self._idOctet = idOctet
                length = self._decodeLen(s)
                self.payload = s.read(length)

class DerInteger(DerObject):
        """Class to model a DER INTEGER.

        An example of encoding is:

          >>> from Crypto.Util.asn1 import DerInteger
          >>> from binascii import hexlify, unhexlify
          >>> int_der = DerInteger(9)
          >>> print hexlify(int_der.encode())

        which will show ``020109``, the DER encoding of 9.

        And for decoding:

          >>> s = unhexlify(b'020109')
          >>> try:
          >>>   int_der = DerInteger()
          >>>   int_der.decode(s)
          >>>   print int_der.value
          >>> except (ValueError, EOFError):
          >>>   print "Not a valid DER INTEGER"

        the output will be ``9``.
        """

        def __init__(self, value=0, implicit=None):
                """Initialize the DER object as an INTEGER.

                :Parameters:
                  value : integer
                    The value of the integer.

                  implicit : integer
                    The IMPLICIT tag to use for the encoded object.
                    It overrides the universal tag for INTEGER (2).
                """

                DerObject.__init__(self, 0x02, b'', implicit, False)
                self.value = value #: The integer value

        def encode(self):
                """Return the DER INTEGER, fully encoded as a
                binary string."""

                number = self.value
                self.payload = b''
                while True:
                    self.payload = bchr(number&255) + self.payload
                    if 128 <= number <= 255:
                        self.payload = bchr(0x00) + self.payload
                    if -128 <= number <= 255:
                        break
                    number >>= 8
                return DerObject.encode(self)

        def decode(self, derEle):
                """Decode a complete DER INTEGER DER, and re-initializes this
                object with it.

                :Parameters:
                  derEle : byte string
                    A complete INTEGER DER element.

                :Raise ValueError:
                  In case of parsing errors.
                :Raise EOFError:
                  If the DER element is too short.
                """
                DerObject.decode(self, derEle)

        def _decodeFromStream(self, s):
                """Decode a complete DER INTEGER from a file."""

                # Fill up self.payload
                DerObject._decodeFromStream(self, s)

                # Derive self.value from self.payload
                self.value = 0L
                bits = 1
                for i in self.payload:
                    self.value *= 256
                    self.value += bord(i)
                    bits <<= 8
                if self.payload and bord(self.payload[0]) & 0x80:
                    self.value -= bits

class DerSequence(DerObject):
        """Class to model a DER SEQUENCE.

        This object behaves like a dynamic Python sequence.

        Sub-elements that are INTEGERs behave like Python integers.

        Any other sub-element is a binary string encoded as a complete DER
        sub-element (TLV).

        An example of encoding is:

          >>> from Crypto.Util.asn1 import DerSequence, DerInteger
          >>> from binascii import hexlify, unhexlify
          >>> obj_der = unhexlify('070102')
          >>> seq_der = DerSequence([4])
          >>> seq_der.append(9)
          >>> seq_der.append(obj_der.encode())
          >>> print hexlify(seq_der.encode())

        which will show ``3009020104020109070102``, the DER encoding of the
        sequence containing ``4``, ``9``, and the object with payload ``02``.

        For decoding:

          >>> s = unhexlify(b'3009020104020109070102')
          >>> try:
          >>>   seq_der = DerSequence()
          >>>   seq_der.decode(s)
          >>>   print len(seq_der)
          >>>   print seq_der[0]
          >>>   print seq_der[:]
          >>> except (ValueError, EOFError):
          >>>   print "Not a valid DER SEQUENCE"

        the output will be::

          3
          4
          [4L, 9L, b'\x07\x01\x02']

        """

        def __init__(self, startSeq=None, implicit=None):
                """Initialize the DER object as a SEQUENCE.

                :Parameters:
                  startSeq : Python sequence
                    A sequence whose element are either integers or
                    other DER objects.

                  implicit : integer
                    The IMPLICIT tag to use for the encoded object.
                    It overrides the universal tag for SEQUENCE (16).
                """

                DerObject.__init__(self, 0x10, b'', implicit, True)
                if startSeq==None:
                    self._seq = []
                else:
                    self._seq = startSeq

        ## A few methods to make it behave like a python sequence

        def __delitem__(self, n):
                del self._seq[n]
        def __getitem__(self, n):
                return self._seq[n]
        def __setitem__(self, key, value):
                self._seq[key] = value
        def __setslice__(self,i,j,sequence):
                self._seq[i:j] = sequence
        def __delslice__(self,i,j):
                del self._seq[i:j]
        def __getslice__(self, i, j):
                return self._seq[max(0, i):max(0, j)]
        def __len__(self):
                return len(self._seq)
        def __iadd__(self, item):
                self._seq.append(item)
                return self
        def append(self, item):
                self._seq.append(item)
                return self

        def hasInts(self, onlyNonNegative=True):
                """Return the number of items in this sequence that are
                integers.

                :Parameters:
                  onlyNonNegative : boolean
                    If True, negative integers are not counted in.
                """
                def _isInt2(x):
                    return _isInt(x, onlyNonNegative)
                return len(filter(_isInt2, self._seq))

        def hasOnlyInts(self, onlyNonNegative=True):
                """Return True if all items in this sequence are integers
                or non-negative integers.

                This function returns False is the sequence is empty,
                or at least one member is not an integer.

                :Parameters:
                  onlyNonNegative : boolean
                    If True, the presence of negative integers
                    causes the method to return False."""
                return self._seq and self.hasInts(onlyNonNegative)==len(self._seq)

        def encode(self):
                """Return this DER SEQUENCE, fully encoded as a
                binary string.

                :Raises ValueError:
                  If some elements in the sequence are neither integers
                  nor byte strings.
                """
                self.payload = b''
                for item in self._seq:
                    try:
                        self.payload += item
                    except TypeError:
                        try:
                            self.payload += DerInteger(item).encode()
                        except TypeError:
                            raise ValueError("Trying to DER encode an unknown object")
                return DerObject.encode(self)

        def decode(self, derEle):
                """Decode a complete DER SEQUENCE, and re-initializes this
                object with it.

                :Parameters:
                  derEle : byte string
                    A complete SEQUENCE DER element.

                :Raise ValueError:
                  In case of parsing errors.
                :Raise EOFError:
                  If the DER element is too short.

                DER INTEGERs are decoded into Python integers. Any other DER
                element is not decoded. Its validity is not checked.
                """
                DerObject.decode(self, derEle)

        def _decodeFromStream(self, s):
                """Decode a complete DER SEQUENCE from a file."""

                self._seq = []

                # Fill up self.payload
                DerObject._decodeFromStream(self, s)

                # Add one item at a time to self.seq, by scanning self.payload
                p = BytesIO_EOF(self.payload)
                while True:
                    try:
                        p.setRecord(True)
                        der = DerObject()
                        der._decodeFromStream(p)

                        # Parse INTEGERs differently
                        if der._idOctet != 0x02:
                            self._seq.append(p._recording)
                        else:
                            derInt = DerInteger()
                            derInt.decode(p._recording)
                            self._seq.append(derInt.value)

                    except _NoDerElementError:
                        break
                # end
