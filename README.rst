SignXML: XML Signature in Python
================================

*SignXML* is an implementation of the W3C `XML Signature <http://en.wikipedia.org/wiki/XML_Signature>`_ standard
in Python (both `"Second Edition" <http://www.w3.org/TR/xmldsig-core/>`_ and `Version 1.1
<http://www.w3.org/TR/xmldsig-core1/>`_). This standard (also known as XMLDSig and
`RFC 3275 <http://www.ietf.org/rfc/rfc3275.txt>`_) is used to provide payload security in
`SAML 2.0 <http://en.wikipedia.org/wiki/SAML_2.0>`_, among other uses. *SignXML* implements all of the required
components of the standard, and most recommended ones. Its features are:

* Use of `defusedxml.lxml <https://bitbucket.org/tiran/defusedxml>`_ to defend against common XML-based attacks when verifying signatures
* Extensions to allow signing with and verifying X.509 certificate chains, including hostname/CN validation
* Modern Python compatibility (2.7-3.4+ and PyPy)
* Well-supported and reliable dependencies: `lxml <https://github.com/lxml/lxml>`_, `defusedxml <https://bitbucket.org/tiran/defusedxml>`_, `cryptography <https://github.com/pyca/cryptography>`_, `eight <https://github.com/kislyuk/eight>`_, `pyOpenSSL <https://github.com/pyca/pyopenssl>`_
* Comprehensive testing (including the XMLDSig interoperability suite) and `continuous integration <https://travis-ci.org/kislyuk/signxml>`_
* Simple interface with useful defaults
* Compactness, readability, and extensibility

Installation
------------
::

    pip install signxml

Synopsis
--------

.. code-block:: python

    from signxml import xmldsig

    cert = open("example.pem").read()
    key = open("example.key").read()
    root = ElementTree.fromstring(signature_data)
    xmldsig(root).sign(key=key, cert=cert)
    xmldsig(root).verify()

Using a SAML metadata file:

.. code-block:: python

    from signxml import xmldsig

    with open("metadata.xml", "rb") as fh:
        cert = etree.parse(fh).find("//ds:X509Certificate").text

    root = ElementTree.fromstring(signature_data)
    xmldsig(root).verify(x509_cert=cert)

.. admonition:: Signing SAML assertions

 The SAML assertion schema specifies a location for the enveloped XML signature (between ``<Issuer>`` and
 ``<Subject>``). To sign a SAML assertion in a schema-compliant way, insert a signature placeholder tag at that location
 before calling xmldsig: ``<Signature Id="placeholder"></Signature>``.

See the `API documentation <https://signxml.readthedocs.org/en/latest/#id1>`_ for more.

Authors
-------
* Andrey Kislyuk

Links
-----
* `Project home page (GitHub) <https://github.com/kislyuk/signxml>`_
* `Documentation (Read the Docs) <https://signxml.readthedocs.org/en/latest/>`_
* `Package distribution <https://warehouse.python.org/project/signxml/>`_ `(PyPI) <https://pypi.python.org/pypi/signxml>`_
* `W3C Recommendation: XML Signature Syntax and Processing (Second Edition) <http://www.w3.org/TR/xmldsig-core/>`_
* `W3C Recommendation: XML Signature Syntax and Processing Version 1.1 <http://www.w3.org/TR/xmldsig-core1>`_
* `W3C Working Group Note: XML Signature Syntax and Processing Version 2.0 <http://www.w3.org/TR/xmldsig-core2>`_
* `XML-Signature Interoperability <http://www.w3.org/Signature/2001/04/05-xmldsig-interop.html>`_
* `Test Cases for C14N 1.1 and XMLDSig Interoperability <http://www.w3.org/TR/xmldsig2ed-tests/>`_



Bugs
~~~~
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/kislyuk/signxml/issues>`_.

License
-------
Licensed under the terms of the `Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_.

.. image:: https://travis-ci.org/kislyuk/signxml.png
        :target: https://travis-ci.org/kislyuk/signxml
.. image:: https://coveralls.io/repos/kislyuk/signxml/badge.png?branch=master
        :target: https://coveralls.io/r/kislyuk/signxml?branch=master
.. image:: https://pypip.in/v/signxml/badge.png
        :target: https://warehouse.python.org/project/signxml/
.. image:: https://pypip.in/d/signxml/badge.png
        :target: https://pypi.python.org/pypi/signxml
.. image:: https://readthedocs.org/projects/signxml/badge/?version=latest
        :target: https://signxml.readthedocs.org/
