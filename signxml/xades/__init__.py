"""
`XAdES ("XML Advanced Electronic Signatures") <https://en.wikipedia.org/wiki/XAdES>`_ is a standard for attaching
metadata to XML Signature objects. This standard is endorsed by the European Union as the implementation for its
`eSignature <https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eSignature+Overview>`_ regulations.
While a `W3C publication from 2003 <https://www.w3.org/TR/XAdES/>`_ exists on the standard, that page is out of date
and further development was undertaken by `ETSI <https://www.etsi.org>`_. ETSI's approach to standards document
publication and versioning is best described as idiosyncratic, with many documents produced over time with confusing
terminology and naming. Documents are only available as PDFs, and there is no apparent way to track all publications on
a given standard. The most recent and straighforward description of the standard appears to be in the following two
documents:

* `ETSI EN 319 132-1 V1.1.1 (2016-04)
  <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.01.01_60/en_31913201v010101p.pdf>`_,
  "Part 1: Building blocks and XAdES baseline signatures"
* `ETSI EN 319 132-2 V1.1.1 (2016-04)
  <https://www.etsi.org/deliver/etsi_en/319100_319199/31913202/01.01.01_60/en_31913202v010101p.pdf>`_,
  "Part 2: Extended XAdES signatures"

XAdES metadata is attached to the XML Signature object as sub-elements under the ``ds:Signature/ds:Object`` path. The
elements required by each XAdES "level" (profile) are summarized in section 6.3 of the first document above, on
pages 50-56.

In SignXML, use :class:`signxml.xades.XAdESSigner` and :class:`signxml.xades.XAdESVerifier` to sign and verify XAdES
signatures, respectively. See `XAdES Signatures <#xades-signatures>`_ for examples.
"""

from .xades import (
    XAdESSigner,
    XAdESDataObjectFormat,
    XAdESSignaturePolicy,
    XAdESVerifier,
    XAdESVerifyResult,
    XAdESSignatureConfiguration,
)
