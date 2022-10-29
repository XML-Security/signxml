"""
XAdES ("XML Advanced Electronic Signatures") is a standard for attaching metadata to XML Signature objects. The
standard is endorsed by the European Union. While a W3C publication from 2003 (https://www.w3.org/TR/XAdES/) exists on
the standard, that page is out of date and further development was undertaken by ETSI. ETSI's approach to standard
document publication and versioning is best described as idiosyncratic, with many documents produced over time with
confusing terminology and naming. The most recent and straighforward description of the standard appears to be in the
following two documents:

* ETSI EN 319 132-1 V1.1.1 (2016-04)
  (https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.01.01_60/en_31913201v010101p.pdf),
  "Part 1: Building blocks and XAdES baseline signatures"
* ETSI EN 319 132-2 V1.1.1 (2016-04)
  (https://www.etsi.org/deliver/etsi_en/319100_319199/31913202/01.01.01_60/en_31913202v010101p.pdf),
  "Part 2: Extended XAdES signatures"

XAdES metadata is attached to the XML Signature object as sub-elements under the ds:Signature/ds:Object path. The
elements required by each XAdES "level" (profile) are summarized in section 6.3 of the first document above, on
pages 50-56.

"""

import os

from lxml import etree

from .. import XMLSignatureProcessor, XMLSigner, XMLVerifier
from ..exceptions import InvalidSignature


class XAdESProcessor(XMLSignatureProcessor):
    schema_files = ["XAdESv141.xsd", "XAdES01903v141-201601.xsd", "XAdES01903v141-201506.xsd"]
    _schema_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "schemas"))


class XAdESSigner(XAdESProcessor, XMLSigner):
    pass


class XAdESVerifier(XAdESProcessor, XMLVerifier):
    def verify(self, data, **kwargs):
        verify_result = super().verify(data, **kwargs)
        return verify_result
