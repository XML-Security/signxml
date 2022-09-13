import pytz
import requests
from base64 import b64encode
from collections import namedtuple as python_namedtuple
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from uuid import uuid4

from lxml import etree
from lxml.builder import ElementMaker

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding

from .. import XMLSignatureProcessor, XMLSigner, XMLVerifier, namespaces

from ..exceptions import InvalidInput
from ..util import add_pem_header, ensure_str, Namespace


def namedtuple_with_defaults(typename, field_names, default_values=()):
    T = python_namedtuple(typename, field_names)
    T.__new__.__defaults__ = (None,) * len(T._fields)
    if isinstance(default_values, Mapping):
        prototype = T(**default_values)
    else:
        prototype = T(*default_values)
    T.__new__.__defaults__ = tuple(prototype)
    return T

namedtuple = namedtuple_with_defaults

levels = Enum("Levels", "B T LT LTA")


# Retrieved on 17. Oct. 2019: https://portal.etsi.org/pnns/uri-list
namespaces.update(Namespace(
    # xades111="https://uri.etsi.org/01903/v1.1.1#",  # superseded
    # xades122="https://uri.etsi.org/01903/v1.2.2#",  # superseded
    xades="http://uri.etsi.org/01903/v1.3.2#",
    xades141="http://uri.etsi.org/01903/v1.4.1#",
))

XADES = ElementMaker(namespace=namespaces.xades, nsmap=namespaces)
XADES141 = ElementMaker(namespace=namespaces.xades141, nsmap=namespaces)
DS = ElementMaker(namespace=namespaces.ds, nsmap=namespaces)

# helper functions

def _gen_id(prefix, suffix=None):
    """
    Generates the id
    """
    suffix = "-{}".format(suffix) if suffix else ""

    return "{prefix}-{uid}{suffix}".format(prefix=prefix, uid=uuid4(), suffix=suffix)


def resolve_uri(uri):
    """
    Returns the content of given uri
    """
    try:
        return requests.get(uri).content
    except Exception:
        raise InvalidInput(f"Unable to resolve reference URI: {uri}")


class XAdESProcessor(XMLSignatureProcessor):
    schema_file = "v1.4.1/XAdES01903v141-201601.xsd"

    def _get_cert_encoded(self, cert):
        return ensure_str(b64encode(cert.public_bytes(Encoding.DER)))

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

class ProductionPlace(namedtuple(
    "ProductionPlace",
    "City StreetAddress StateOrProvince PostalCode CountryName"
)):
    """
    A containter to hold the XAdES ProductionPlace values.

    :param City: the city
    :type City: str
    :param StreetAddress: the street adress field
    :type StreetAddress: str
    :param StateOrProvince: the state or province
    :type StateOrProvince: str
    :param PostalCode: the postal code
    :type PostalCode: str
    :param CountryName: the country name
    :type CountryName: str
    """

class CertifiedRoleV2(namedtuple(
    "CertifiedRole",
    "X509AttributeCertificate OtherAttributeCertificate"
)):
    """
    A containter to hold a XAdES CertifiedRoleV2 object.

    :param X509AttributeCertificate:
        attribute certificate conformant to Recommendation ITU-T X.509
        issued to the signer
    :type X509AttributeCertificate:
        :py:class:`cryptography.x509.Certificate` object
    :param OtherAttributeCertificate:
        attribute certificate (issued, in consequence, by Attribute Authorities)
        in different syntax than the one specified in Recommendation ITU-T X.509
    :type OtherAttributeCertificate:
        :py:class:`cryptography.x509.Certificate` object

    .. note::
        Either specify X509AttributeCertificate OR OtherAttributeCertificate.
    """

class SignaturePolicy(namedtuple(
    "SignaturePolicy", "Identifier Description URI"
)):
    """
    A container to hold the XADES SignaturePolicy values

    :param Identifier: the identifier of the policy
    :param Description: the description of the policy
    i.e: for colombia
    'Política de firma para facturas electrónicas de la República de Colombia'
    :param URI: the URI of the policy (if empty the identifier will be used)
    """

class SignerOptions(namedtuple(
    "SignerOptions",
    "CertChain ProductionPlace SignaturePolicy ClaimedRoles CertifiedRoles SignedAssertions",
    {
        "CertChain": [],
        "ProductionPlace": None,
        "SignaturePolicy": None,
        "ClaimedRoles": [],
        "CertifiedRoles": [],
        "SignedAssertions": [],
    }
)):
    """
    A containter to hold the XAdES Signer runtime options. It can be provided by
    directly calling ``signxml.XAdESSigner._sign()``.

    :param CertChain:
        the certificate and a chain of intermediate certificates.
    :type CertChain: array of :py:class:`cryptography.x509.Certificate` objects
    :param ProductionPlace:
        A named tuple containing the values to generate the production place
        signed property.
    :type ProductionPlace: ProductionPlace namedtuple
    :param SignaturePolicy:
        A named tuple containing the values to generate the Signature Policy
    :type SignaturePolicy: SignaturePolicy namedtuple
    :param ClaimedRoles:
        The claimed signer roles, this imlementation limits to string values.
        Submit a placerholder string of your choice for domain application
        definitions for representation of claimed roles and post-process the
        final element tree.
    :type ClaimedRoles:
        :py:class:`list` of :py:class:`str` clamined roles
    :param CertifiedRoles:
        The certified roles as issued by an attribute certification authority
        to the signer
    :type CertifiedRoles:
        array of :py:class:`sgnxml.xades.CertifiedRoleV2` objects
    :param CertifiedRoles:
        The certified roles as issued by an attribute certification authority
        to the signer
    :type CertifiedRoles:
        array of :py:class:`sgnxml.xades.CertifiedRoleV2` objects
    :param SignedAssertions:
        Signed assertions are stronger than a claimed attribute but less
        restrictive than an attribute certificate. As they are not typed in the
        spec, transparently submit an array of :py:class:`lxml.etree.Element`
    :type SignedAssertions:
        array of :py:class:`lxml.etree.Element` objects according to domain
        application definition for representation of signed assertions
    """

class XAdESSigner(XAdESProcessor, XMLSigner):
    """
    ...
    """

    def __init__(self, level=levels.B, legacy=True, tz=pytz.utc, black_list=list(), options=None):
        self.xades_legacy = legacy
        self.xades_level = level
        self.xades_tz = tz
        self.dsig_prefix = "xmldsig"
        self.black_list = black_list
        self.options_struct = options
        self.refs = []
        super().__init__()

    def _unpack(self, data, reference_uris):
        sig_root, doc_root, c14n_inputs, reference_uris = super()._unpack(
            data, reference_uris)
        self._set_default_options()
        reference_uris.append(DS.Object(self._generate_xades()))
        # reference_uris.extend(self.refs)
        return sig_root, doc_root, c14n_inputs, reference_uris

    def _set_default_options(self):
        "Creates empty values for option struct to ensure the sign process works"
        if not self.options_struct:
            self.options_struct = SignerOptions()

        if self.cert_chain and not self.options_struct.CertChain:
            for cert_value in self.cert_chain:
                cert_value = add_pem_header(cert_value)
                if isinstance(cert_value, str):
                    cert_value = cert_value.encode('utf-8')
                cert = load_pem_x509_certificate(cert_value)
                self.options_struct.CertChain.append(cert)

    def _clean_elements_from_black_list(self, elements):
        """
        :param black_list:
            the list of tag elements that will be removed
        :type black_list:
            :py:class:`list`
        :param elemnts:
            the list of elements to be checked in the black list
        :type elements:
            :py:class:`list` of etree.Element
        :return clean elements
        """
        if not isinstance(elements, list):
            elements = list(elements)

        return list(filter(
            lambda x: isinstance(x, etree._Element) and x.tag not in self.black_list, elements
        ))

    def _add_xades_reference(self, el, attrs={}):
        """
        The refs depends the xmldsig scheme,(https://www.w3.org/TR/xmldsig-core2/#sec-Overview)
        not the XADES scheme, therefore, those refs have to wait for the general element to be append to
        the element ds:SignedInfo within the signature element ds:Signature

        This ds:Reference element shall include the Type attribute with its
        value set to:
        (https://www.w3.org/TR/xmldsig-core2/#sec-o-Reference)
        This reference is made for compatibility mode v1 anv v2
        (https://www.w3.org/TR/xmldsig-core2/#sec-Compatibility-Mode-Examples)
        :param el: element
        :type el: etree.Element
        :param attrs: attributes to set in the element 'DigestValue'
        :type attrs: py:class:dict

        Note: PLEASE!! take into account that the digest may differ in the
            validation process caused by the transforms and the namespaces applied
        """
        if attrs:
            attrs["URI"] = "#" + el.get("Id")
            self.refs.append(attrs)
        else:
            self.refs.append("#" + el.get("Id"))

    def _generate_xades_ssp_elements(self):
        """
        Generates the sequence of SignedSignatureProperty elements for
        inclusion into the SignedProperty element.

        Deprecations as listed in ETSI EN 319 132-1 V1.1.1 (2016-04), Annex D


        :returns:
            A :py:class:`list` of effectively generated SignedSignatureProperty
            elements.`
        """
        elements = []

        # Item 1: SigningTime
        elements.append(XADES.SigningTime(datetime.now(self.xades_tz).isoformat()))

        # Item 2: SigningCertificate or SigningCertificateV2
        """
        The SigningCertificateV2 qualifying property shall be a signed
            qualifying property that qualifies the signature.
        The SigningCertificateV2 qualifying property shall contain one reference
            to the signing certificate.
        The SigningCertificateV2 qualifying property may contain references to
            some of or all the certificates within
        the signing certificate path, including one reference to the trust
            anchor when this is a certificate.
        """
        cert_elements = []
        for cert in self.options_struct.CertChain:
            if self.xades_legacy:
                serial_element = XADES.IssuerSerial(
                    DS.X509IssuerName(cert.issuer.rfc4514_string()),
                    DS.X509SerialNumber(str(cert.serial_number)),
                )
            else:
                """
                The content of IssuerSerialV2 element shall be the the base-64
                encoding of one DER-encoded instance of type IssuerSerial type
                defined in IETF RFC 5035 [17].
                """
                raise NotImplementedError(
                    "Please make a PR if you know how to obtain in python a "
                    "'DER-encoded instance of type IssuerSerial type defined in "
                    "IETF RFC 5035'")
                serial_element = XADES.IssuerSerialV2(
                    # TODO implement, wtf?
                )
            """
            The element CertDigest shall contain the digest of the referenced
            certificate.
            CertDigest‘s children elements satisfy the following requirements:
            1) ds:DigestMethod element shall identify the digest algorithm. And
            2) ds:DigestValue element shall contain the base-64 encoded value
               of the digest computed on the DERencoded certificate.
            """
            digest = self._get_digest(
                cert.public_bytes(Encoding.PEM),
                self._get_digest_method_by_tag(self.digest_alg))
            cert_digest = XADES.CertDigest(
                DS.DigestMethod(
                    Algorithm=self.known_digest_tags[self.digest_alg]
                ),
                DS.DigestValue(ensure_str(b64encode(digest)))
            )
            cert_elements.append(XADES.Cert(cert_digest, serial_element))

        if self.xades_legacy:
            elements.append(XADES.SigningCertificate(*cert_elements))  # deprecated (legacy)
        else:
            elements.append(XADES.SigningCertificateV2(*cert_elements))

        # Item 3: SignatureProductionPlace or SignatureProductionPlaceV2
        """
        The SignatureProductionPlaceV2 qualifying property shall be a signed
            qualifying property that qualifies the signer.
        The SignatureProductionPlaceV2 qualifying property shall specify an
            address associated with the signer at a particular geographical
            (e.g. city) location.
        """
        pp_elements = []
        PP = self.options_struct.ProductionPlace
        if PP:
            pa = pp_elements.append
            pa(XADES.City(PP.City)) if PP.City else None
            if not self.xades_legacy:
                pa(XADES.StreetAddress(PP.StreetAddress)) if PP.StreetAddress else None
            pa(XADES.StateOrProvince(PP.StateOrProvince)) if PP.StateOrProvince else None
            pa(XADES.PostalCode(PP.PostalCode)) if PP.PostalCode else None
            pa(XADES.CountryName(PP.CountryName)) if PP.CountryName else None

            """
            Empty SignatureProductionPlaceV2 qualifying properties shall not be generated.
            """
            pp_elements = self._clean_elements_from_black_list(pp_elements)
            if self.xades_legacy and pp_elements:
                elements.append(XADES.SignatureProductionPlace(*pp_elements))  # deprecated (legacy)
            elif pp_elements:
                elements.append(XADES.SignatureProductionPlaceV2(*pp_elements))

        # Item 4: SignaturePolicyIdentifier
        """
        The SignaturePolicyIdentifier qualifying property shall be a signed
            qualifying property qualifying the signature.
        The SignaturePolicyIdentifier qualifying property shall contain either
            an explicit identifier of a signature policy or an indication that
            there is an implied signature policy that the relying party should
            be aware of.

        ETSI TS 119 172-1 specifies a framework for signature policies.
        """
        spid_elements = []
        sp = self.options_struct.SignaturePolicy
        if sp:
            # digest value
            pv = resolve_uri(sp.URI or sp.Identifier)

            spid_elements.append(
                XADES.SigPolicyId(
                    XADES.Identifier(sp.Identifier),
                    XADES.Description(sp.Description)
                )
            )
            digest = self._get_digest(
                pv,
                self._get_digest_method_by_tag(self.digest_alg))
            spid_elements.append(
                XADES.SigPolicyHash(
                    DS.DigestMethod(
                        Algorithm=self.known_digest_tags[self.digest_alg]
                    ),
                    DS.DigestValue(ensure_str(b64encode(digest)))
                )
            )
            if sp.URI:
                spid_elements.append(
                    XADES.SigPolicyQualifiers(
                        XADES.SigPolicyQualifier(XADES.SPURI(sp.URI))
                    )
                )
            spid = XADES.SignaturePolicyId(*spid_elements)
            spi_elements = []
            spi_elements.append(spid)
            elements.append(XADES.SignaturePolicyIdentifier(*spi_elements))

        # Item 5: SignerRole or SignerRoleV2
        """
        The SignerRoleV2 qualifying property shall be a signed qualifying
            property that qualifies the signer.
        The SignerRoleV2 qualifying property shall encapsulate signer attributes
            (e.g. role). This qualifying property may encapsulate the following
            types of attributes:
                • attributes claimed by the signer;
                • attributes certified in attribute certificates issued by an
                  Attribute Authority; or/and
                • assertions signed by a third party.
        """
        clr_elements = []
        """
        The ClaimedRoles element shall contain a non-empty sequence of roles
        claimed by the signer but which are not certified.
        """
        for role in self.options_struct.ClaimedRoles:
            if not isinstance(role, str):
                """
                Additional content types *may* be defined on a domain application
                basis and be part of this element.
                """
                NotImplementedError(
                    "Role types different than strings, although permitted by "
                    "the schema, are not implemented. Use a placeholder and "
                    "post process the resulting element tree, instead!")
            clr_elements.append(XADES.ClaimedRole(role))

        ctr_elements = []
        """
        The CertifiedRolesV2 element shall contain a non-empty sequence of
        certified attributes, which shall be one of the following:
            • the base-64 encoding of DER-encoded X509 attribute certificates
              conformant to Recommendation ITU-T X.509 [4] issued to the signer,
              within the X509AttributeCertificate element; or
            • attribute certificates (issued, in consequence, by Attribute
              Authorities) in different syntax than the one specified in
              Recommendation ITU-T X.509 [4], within the
              OtherAttributeCertificate element. The definition of specific
              OtherAttributeCertificate is outside of the scope of the present
              document
        """
        if self.options_struct.CertifiedRoles and self.xades_legacy:
            NotImplementedError(
                "Legay certified roles wired as objects encoded in "
                "EncapsulatedPKIDataType are not implemented.")

        for role in self.options_struct.CertifiedRoles:
            ctr_elements.append(XADES.CertifiedRolesV2(
                XADES.X509AttributeCertificate(
                    self._get_cert_encoded(role.X509AttributeCertificate)
                ) if role.X509AttributeCertificate else
                XADES.OtherAttributeCertificate(
                    self._get_cert_encoded(role.OtherAttributeCertificate)
                )
            ))

        """
        The SignedAssertions element shall contain a non-empty sequence of
            assertions signed by a third party.
        The definition of specific content types for SignedAssertions is outside
            of the scope of the present document.
        """
        sas_elements = self.options_struct.SignedAssertions
        if not all(['SignedAssertions' in e.tag for e in sas_elements]):
            raise InvalidInput(
                "Input for signed assertions shall be all elements of type "
                "'{https://uri.etsi.org/01903/v1.3.2#}SignedAssertions'")

        sr_elements = []
        if clr_elements:
            sr_elements.append(XADES.ClaimedRoles(*clr_elements))

        if ctr_elements and self.xades_legacy:
            raise  # already cached above, never hit
        elif ctr_elements:
            sr_elements.append(XADES.CertifiedRolesV2(*ctr_elements))

        if sas_elements and not self.xades_legacy:
            sr_elements.append(XADES.SignedAssertions(*sas_elements))

        """
        Empty SignerRoleV2 qualifying properties shall not be generated.
        """
        if not sr_elements:
            pass
        else:
            sr_elements = self._clean_elements_from_black_list(sr_elements)
            if self.xades_legacy:
                elements.append(XADES.SignerRole(*sr_elements))  # deprecated (legacy)
            else:
                elements.append(XADES.SignerRoleV2(*sr_elements))

        # any ##other

        return self._clean_elements_from_black_list(elements)

    def _generate_xades_sdop_elements(self):
        elements = []
        return elements

        # TODO: Find a way to complete such values
        elements.append(XADES.DataObjectFormat())
        elements.append(XADES.CommitmentTypeIndication())
        elements.append(XADES.AllDataObjectsTimeStamp())
        elements.append(XADES.IndividualDataObjectsTimeStamp())

        # any ##other

        return self._clean_elements_from_black_list(elements)

    def _generate_xades_usp_elements(self):
        """
        Deprecation as listed in ETSI EN 319 132-1 V1.1.1 (2016-04), Annex D
        """
        elements = []
        return elements
        # TODO: Find a way to complete such values

        elements.append(XADES.CounterSignature())
        elements.append(XADES.SignatureTimeStamp())

        if self.xades_legacy:
            elements.append(XADES.CompleteCertificateRefs())  # deprecated (legacy)
        else:
            elements.append(XADES141.CompleteCertificateRefsV2())

        elements.append(XADES.CompleteRevocationRefs())

        if self.xades_legacy:
            elements.append(XADES.AttributeCertificateRefs())  # deprecated (legacy)
        else:
            elements.append(XADES141.AttributeCertificateRefsV2())

        elements.append(XADES.AttributeRevocationRefs())

        if self.xades_legacy:
            elements.append(XADES.SigAndRefsTimeStamp())  # deprecated (legacy)
        else:
            elements.append(XADES141.SigAndRefsTimeStampV2())

        if self.xades_legacy:
            elements.append(XADES.RefsOnlyTimeStamp())  # deprecated (legacy)
        else:
            elements.append(XADES141.RefsOnlyTimeStampV2())

        elements.append(XADES.CertificateValues())
        elements.append(XADES.RevocationValues())
        elements.append(XADES.AttrAuthoritiesCertValues())
        elements.append(XADES.AttributeRevocationValues())
        elements.append(XADES.ArchiveTimeStamp())

        # any ##other

        return self._clean_elements_from_black_list(elements)

    def _generate_xades_udop_elements(self):
        elements = []
        elements.append(XADES.UnsignedDataObjectProperty())
        return self._clean_elements_from_black_list(elements)

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
            sp_elements.append(
                XADES.SignedSignatureProperties(
                    *ssp_elements, Id=_gen_id(self.dsig_prefix, "signedsigprops")  # optional
                )
            )
        """
        A XAdES signature shall not incorporate empty SignedDataObjectProperties element.
        """
        if sdop_elements:
            """
            The Id attribute shall be used to reference the SignedDataObjectProperties element.
            """
            sp_elements.append(
                XADES.SignedDataObjectProperties(
                    *sdop_elements, Id=_gen_id(self.dsig_prefix, "signeddataobjprops")  # optional
                )
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
            up_elements.append(
                XADES.UnsignedSignatureProperties(
                    *usp_elements, Id=_gen_id(self.dsig_prefix, "unsignedsigprops")  # optional
                )
            )
        """
        A XAdES signature shall not incorporate empty UnignedDataObjectProperties element.
        """
        if udop_elements:
            """
            The Id attribute shall be used to reference the UnignedDataObjectProperties element.
            """
            usp_elements.append(
                XADES.UnsignedDataObjectProperties(
                    *udop_elements, Id=_gen_id(self.dsig_prefix, "unsigneddataobjprops")  # optional
                )
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
            sp_elements = self._clean_elements_from_black_list(sp_elements)
            sp = XADES.SignedProperties(
                *sp_elements,
                Id=_gen_id(self.dsig_prefix, "signedprops")  # optional
            )
            qp_elements.append(sp)
            """
            In order to protect the qualifying properties with the signature,
            a ds:Reference element shall be added to the XML signature.
            At this point, the qp_elements only should contains the SignedProperties element,
            therefore, it can be referenced by the index 0.
            The refs depend the xmldsig scheme,(https://www.w3.org/TR/xmldsig-core2/#sec-Overview)
            not the XADES scheme, therefore, those refs have to wait for the general element to be appended to
            the element ds:SignedInfo within the signature element ds:Signature

            This ds:Reference element shall include the Type attribute with its
            value set to:
            """
            self._add_xades_reference(sp, {"Type": "http://uri.etsi.org/01903#SignedProperties"})

        """
        A XAdES signature shall not incorporate empty UnsignedProperties elements.
        """
        if up_elements:
            """
            The Id attribute shall be used to reference the UnsignedProperties element.
            """
            up_elements = self._clean_elements_from_black_list(up_elements)
            qp_elements.append(
                XADES.UnsignedProperties(
                    *up_elements,
                    Id=_gen_id(self.dsig_prefix, "unsignedprops")  # optional
                )
            )

        """
        The Target attribute shall refer to the Id attribute of the
        corresponding ds:Signature. The Id attribute shall be used to reference
        the QualifyingProperties container.
        """
        qp_attributes = {
            "Target": "#"+_gen_id(self.dsig_prefix, "signature"),  # required
            "Id": _gen_id(self.dsig_prefix, "qualifyingprops"),  # optional
        }

        """
        A XAdES signature shall not incorporate empty QualifyingProperties elements.
        """
        if not qp_elements:
            return None
        qp_elements = self._clean_elements_from_black_list(qp_elements)
        qp = XADES.QualifyingProperties(*qp_elements, **qp_attributes)
        self._add_xades_reference(qp)
        return qp
