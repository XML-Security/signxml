import logging
import os
from typing import Any, List, Tuple
from xml.etree import ElementTree as stdlibElementTree

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import Hash
from lxml import etree

from .algorithms import CanonicalizationMethod, DigestAlgorithm, digest_algorithm_implementations
from .exceptions import InvalidInput
from .util import namespaces

logger = logging.getLogger(__name__)


class XMLProcessor:
    _schemas: List[Any] = []
    schema_files: List[Any] = []
    _default_parser, _parser = None, None
    _schema_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "schemas"))

    @classmethod
    def schemas(cls):
        if len(cls._schemas) == 0:
            for schema_file in cls.schema_files:
                schema_path = os.path.join(cls._schema_dir, schema_file)
                cls._schemas.append(etree.XMLSchema(etree.parse(schema_path)))
        return cls._schemas

    @property
    def parser(self):
        if self._parser is None:
            if self._default_parser is None:
                self._default_parser = etree.XMLParser(resolve_entities=False)
            return self._default_parser
        return self._parser

    def _fromstring(self, xml_string, **kwargs):
        xml_node = etree.fromstring(xml_string, parser=self.parser, **kwargs)
        for entity in xml_node.iter(etree.Entity):
            raise InvalidInput("Entities are not supported in XML input")
        return xml_node

    def _tostring(self, xml_node, **kwargs):
        return etree.tostring(xml_node, **kwargs)

    def get_root(self, data):
        if isinstance(data, (str, bytes)):
            return self._fromstring(data)
        elif isinstance(data, stdlibElementTree.Element):
            # TODO: add debug level logging statement re: performance impact here
            return self._fromstring(stdlibElementTree.tostring(data, encoding="utf-8"))
        else:
            # Create a separate copy of the node so we can modify the tree and avoid any c14n inconsistencies from
            # namespaces propagating from parent nodes. The lxml docs recommend using copy.deepcopy for this, but it
            # doesn't seem to preserve namespaces. It would be nice to find a less heavy-handed way of doing this.
            return self._fromstring(self._tostring(data))


class XMLSignatureProcessor(XMLProcessor):
    schema_files = ["xmldsig1-schema.xsd"]

    # See https://tools.ietf.org/html/rfc5656
    known_ecdsa_curves = {
        "urn:oid:1.2.840.10045.3.1.7": ec.SECP256R1,
        "urn:oid:1.3.132.0.34": ec.SECP384R1,
        "urn:oid:1.3.132.0.35": ec.SECP521R1,
        "urn:oid:1.3.132.0.1": ec.SECT163K1,
        "urn:oid:1.2.840.10045.3.1.1": ec.SECP192R1,
        "urn:oid:1.3.132.0.33": ec.SECP224R1,
        "urn:oid:1.3.132.0.26": ec.SECT233K1,
        "urn:oid:1.3.132.0.27": ec.SECT233R1,
        "urn:oid:1.3.132.0.16": ec.SECT283R1,
        "urn:oid:1.3.132.0.36": ec.SECT409K1,
        "urn:oid:1.3.132.0.37": ec.SECT409R1,
        "urn:oid:1.3.132.0.38": ec.SECT571K1,
    }
    known_ecdsa_curve_oids = {ec().name: oid for oid, ec in known_ecdsa_curves.items()}  # type: ignore

    excise_empty_xmlns_declarations = False

    id_attributes: Tuple[str, ...] = ("Id", "ID", "id", "xml:id")

    def _get_digest(self, data, algorithm: DigestAlgorithm):
        algorithm_implementation = digest_algorithm_implementations[algorithm]()
        hasher = Hash(algorithm=algorithm_implementation)
        hasher.update(data)
        return hasher.finalize()

    def _find(self, element, query, require=True, xpath=""):
        namespace = "ds"
        if ":" in query:
            namespace, _, query = query.partition(":")
        result = element.find(f"{xpath}{namespace}:{query}", namespaces=namespaces)

        if require and result is None:
            raise InvalidInput(f"Expected to find XML element {query} in {element.tag}")
        return result

    def _findall(self, element, query, xpath=""):
        namespace = "ds"
        if ":" in query:
            namespace, _, query = query.partition(":")
        return element.findall(f"{xpath}{namespace}:{query}", namespaces=namespaces)

    def _c14n(self, nodes, algorithm: CanonicalizationMethod, inclusive_ns_prefixes=None):
        exclusive, with_comments = False, False

        if algorithm.value.startswith("http://www.w3.org/2001/10/xml-exc-c14n#"):
            exclusive = True
        if algorithm.value.endswith("#WithComments"):
            with_comments = True

        if not isinstance(nodes, list):
            nodes = [nodes]

        c14n = b""
        for node in nodes:
            c14n += etree.tostring(
                node,
                method="c14n",
                exclusive=exclusive,
                with_comments=with_comments,
                inclusive_ns_prefixes=inclusive_ns_prefixes,
            )
        if exclusive is False and self.excise_empty_xmlns_declarations is True:
            # Incorrect legacy behavior. See also:
            # - https://github.com/XML-Security/signxml/issues/193
            # - http://www.w3.org/TR/xml-c14n, "namespace axis"
            # - http://www.w3.org/TR/xml-c14n2/#sec-Namespace-Processing
            c14n = c14n.replace(b' xmlns=""', b"")
        logger.debug("Canonicalized string (exclusive=%s, with_comments=%s): %s", exclusive, with_comments, c14n)
        return c14n

    def _resolve_reference(self, doc_root, reference, uri_resolver=None):
        uri = reference.get("URI")
        if uri is None:
            raise InvalidInput("References without URIs are not supported")
        elif uri == "":
            return doc_root
        elif uri.startswith("#xpointer("):
            raise InvalidInput("XPointer references are not supported")
            # doc_root.xpath(uri.lstrip("#"))[0]
        elif uri.startswith("#"):
            for id_attribute in self.id_attributes:
                xpath_query = f"//*[@*[local-name() = '{id_attribute}']=$uri]"
                results = doc_root.xpath(xpath_query, uri=uri.lstrip("#"))
                if len(results) > 1:
                    raise InvalidInput(f"Ambiguous reference URI {uri} resolved to {len(results)} nodes")
                elif len(results) == 1:
                    return results[0]
            raise InvalidInput(f"Unable to resolve reference URI: {uri}")
        else:
            if uri_resolver is None:
                raise InvalidInput(f"External URI dereferencing is not configured: {uri}")
            result = uri_resolver(uri)
            if result is None:
                raise InvalidInput(f"Unable to resolve reference URI: {uri}")
            return result
