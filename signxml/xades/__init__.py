from __future__ import absolute_import, division, print_function, unicode_literals

from base64 import b64encode, b64decode
from enum import Enum
from uuid import uuid4
from datetime import datetime
import pytz

from eight import str, bytes
from lxml import etree
from lxml.etree import Element, SubElement
from lxml.builder import ElementMaker
from defusedxml.lxml import fromstring

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import Hash, SHA1, SHA224, SHA256, SHA384, SHA512
from cryptography.hazmat.backends import default_backend

from .. import XMLSignatureProcessor, XMLSigner, XMLVerifier, VerifyResult, namespaces

from ..exceptions import InvalidSignature, InvalidDigest, InvalidInput, InvalidCertificate  # noqa
from ..util import (bytes_to_long, long_to_bytes, strip_pem_header, add_pem_header, ensure_bytes, ensure_str, Namespace,
                   XMLProcessor, iterate_pem, verify_x509_cert_chain)
from collections import namedtuple

levels = Enum("Levels", "B T LT LTA")


# Retrieved on 17. Oct. 2019: https://portal.etsi.org/pnns/uri-list
namespaces.update(Namespace(
    # xades111="https://uri.etsi.org/01903/v1.1.1#",  # superseeded
    # xades122="https://uri.etsi.org/01903/v1.2.2#",  # superseeded
    xades132="https://uri.etsi.org/01903/v1.3.2#",
    xades141="https://uri.etsi.org/01903/v1.4.1#",
))

XADES132 = ElementMaker(namespace=namespaces.xades132)
XADES141 = ElementMaker(namespace=namespaces.xades141)
DS = ElementMaker(namespace=namespaces.ds)

def _gen_id(suffix):
    return "{}-{suffix}".format(uuid4(), suffix=suffix)



class XAdESProcessor(XMLSignatureProcessor):
    schema_file = "v1.4.1/XAdES01903v141-201601.xsd"

    def _resolve_target(self, doc_root, qualifying_properties):
        uri = qualifying_properties.get("Target")
        if not uri:
            return doc_root
        elif uri.startswith("#xpointer("):
            raise InvalidInput("XPointer references are not supported")
            # doc_root.xpath(uri.lstrip("#"))[0]
        elif uri.startswith("#"):
            for id_attribute in self.id_attributes:
                xpath_query = "//*[@*[local-name() = '{}']=$uri]".format(id_attribute)
                results = doc_root.xpath(xpath_query, uri=uri.lstrip("#"))
                if len(results) > 1:
                    raise InvalidInput("Ambiguous reference URI {} resolved to {} nodes".format(uri, len(results)))
                elif len(results) == 1:
                    return results[0]
        raise InvalidInput("Unable to resolve reference URI: {}".format(uri))


class XAdESSignerOptions(namedtuple("XAdESSignerOptions", "cert_chain signed_xml signature_xml")):
    """
    A containter to hold the XAdES Signer runtime options. It can be provided by
    directly calling ``signxml.XAdESSigner._sign()``.

    :param cert_chain:
        OpenSSL.crypto.X509 objects containing the certificate and a chain of
        intermediate certificates.
    :type cert_chain: array of OpenSSL.crypto.X509 objects
    """


class XAdESSigner(XAdESProcessor, XMLSigner):
    """
    ...
    """

    def __init__(self, level=levels.LTA, legacy=False, tz=pytz.utc):
        self.xades_legacy = legacy
        self.xades_level = level
        self.xades_tz = tz

    def sign(self, *args, **kwargs):
        options_struct = XAdESSignerOptions('foo', 'bar', 'baz')
        self._sign(options_struct)
        return super().sign(*args, **kwargs)

    def _sign(self, options_struct):
        ...

    def _add_xades_reference(self, id):
        """
        This ds:Reference element shall include the Type attribute with its
        value set to:
        """
        DS.Reference(
            Type="http://uri.etsi.org/01903#SignedProperties"
        )
        pass

    def _generate_xades_ssp_elements(self):
        """
        Deprecation as listed in ETSI EN 319 132-1 V1.1.1 (2016-04), Annex D
        """
        elements = []

        elements.append(XADES132.SigningTime(datetime.now(self.xades_tz).isoformat()))

        if self.xades_legacy:
            elements.append(XADES132.SigningCertificate())  # deprecated (legacy)
        else:
            elements.append(XADES132.SigningCertificateV2())

        if self.xades_legacy:
            elements.append(XADES132.SignatureProductionPlace())  # deprecated (legacy)
        else:
            elements.append(XADES132.SignatureProductionPlaceV2())

        elements.append(XADES132.SignaturePolicyIdentifier())

        if self.xades_legacy:
            elements.append(XADES132.SignerRole())  # deprecated (legacy)
        else:
            elements.append(XADES132.SignerRoleV2())

        # any ##other

        return elements

    def _generate_xades_sdop_elements(self):
        elements = []

        elements.append(XADES132.DataObjectFormat())

        elements.append(XADES132.CommitmentTypeIndication())

        elements.append(XADES132.AllDataObjectsTimeStamp())

        elements.append(XADES132.IndividualDataObjectsTimeStamp())

        # any ##other

        return elements

    def _generate_xades_usp_elements(self):
        elements = []

        elements.append(XADES132.CounterSignature())

        elements.append(XADES132.SignatureTimeStamp())

        if self.xades_legacy:
            elements.append(XADES132.CompleteCertificateRefs())  # deprecated (legacy)
        else:
            elements.append(XADES141.CompleteCertificateRefsV2())

        elements.append(XADES132.CompleteRevocationRefs())

        if self.xades_legacy:
            elements.append(XADES132.AttributeCertificateRefs())  # deprecated (legacy)
        else:
            elements.append(XADES141.AttributeCertificateRefsV2())

        elements.append(XADES132.AttributeRevocationRefs())

        if self.xades_legacy:
            elements.append(XADES132.SigAndRefsTimeStamp())  # deprecated (legacy)
        else:
            elements.append(XADES141.SigAndRefsTimeStampV2())

        if self.xades_legacy:
            elements.append(XADES132.RefsOnlyTimeStamp())  # deprecated (legacy)
        else:
            elements.append(XADES141.RefsOnlyTimeStampV2())

        elements.append(XADES132.CertificateValues())

        elements.append(XADES132.RevocationValues())

        elements.append(XADES132.AttrAuthoritiesCertValues())

        elements.append(XADES132.AttributeRevocationValues())

        elements.append(XADES132.ArchiveTimeStamp())

        # any ##other

        return elements

    def _generate_xades_udop_elements(self):
        elements = []

        elements.append(XADES132.UnsignedDataObjectProperty())

        return elements

    def _generate_xades(self):

        """
        Acronyms used in this method
        ----------------------------
        Defined by ETSI EN 319 132-1 V1.1.1 (2016-04)
        qp       := QualifyingProperties,           c. 4.3.1
          sp     := SignedProperties,               c. 4.3.2
            ssp  := SignedSignatureProperties,      c. 4.3.4
            sdop := SignedDataObjectProperties,     c. 4.3.5
          up     := UnsignedProperties,             c. 4.3.3
            usp  := UnignedSignatureProperties,     c. 4.3.6
            udop := UnignedDataObjectProperties,    c. 4.3.7
        """

        ssp_elements = self._generate_xades_ssp_elements()
        sdop_elements = self._generate_xades_sdop_elements()

        usp_elements = self._generate_xades_usp_elements()
        udop_elements = self._generate_xades_udop_elements()

        # Step -3: Construction of SignedProperties
        sp_elements = []
        """
        A XAdES signature shall not incorporate empty SignedSignatureProperties element.
        """
        if ssp_elements:
            """
            The Id attribute shall be used to reference the SignedSignatureProperties element.
            """
            sp_elements.append(*ssp_elements,
                Id=_gen_id("signedsigprops")  # optional
            )
        """
        A XAdES signature shall not incorporate empty SignedDataObjectProperties element.
        """
        if sdop_elements:
            """
            The Id attribute shall be used to reference the SignedDataObjectProperties element.
            """
            sp_elements.append(*sdop_elements,
                Id=_gen_id("signeddataobjprops")  # optional
            )

        # Step -2: Construction of UnsignedProperties
        up_elements = []
        """
        A XAdES signature shall not incorporate empty UnignedSignatureProperties element.
        """
        if usp_elements:
            """
            The Id attribute shall be used to reference the UnignedSignatureProperties element.
            """
            sp_elements.append(*usp_elements,
                Id=_gen_id("unsignedsigprops")  # optional
            )
        """
        A XAdES signature shall not incorporate empty UnignedDataObjectProperties element.
        """
        if udop_elements:
            """
            The Id attribute shall be used to reference the UnignedDataObjectProperties element.
            """
            sp_elements.append(*udop_elements,
                Id=_gen_id("unsigneddataobjprops")  # optional
            )

        # Step -1: Construction of QualifyingProperties
        qp_elements = []

        """
        A XAdES signature shall not incorporate empty SignedProperties element.
        """
        if sp_elements:
            """
            The Id attribute shall be used to reference the SignedProperties element.
            """
            qp_elements.append(
                XADES132.SignedProperties(*sp_elements,
                    Id=_gen_id("signedprops")  # optional
                )
            )
            """
            In order to protect the qualifying properties with the signature,
            a ds:Reference element shall be added to the XML signature.
            """
            self._add_xades_reference(sp_attributes.get('Id'))

        """
        A XAdES signature shall not incorporate empty UnsignedProperties elements.
        """
        if up_elements:
            """
            The Id attribute shall be used to reference the UnsignedProperties element.
            """
            qp_elements.append(
                XADES132.UnsignedProperties(*up_elements,
                    Id=_gen_id("unsignedprops")  # optional
                )
            )

        """
        The Target attribute shall refer to the Id attribute of the
        corresponding ds:Signature. The Id attribute shall be used to reference
        the QualifyingProperties container.
        """
        qp_attributes = {
            "Target": '',  # required
            "Id": _gen_id("qualifyingprops"),  # optional
        }

        """
        A XAdES signature shall not incorporate empty QualifyingProperties elements.
        """
        if not qp_elements:
            return None
        return XADES132.QualifyingProperties(*qp_elements, **qp_attributes)
