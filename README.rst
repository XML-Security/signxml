UNDER DEVELOPMENT

SignXML: XML Signature in Python
================================

*SignXML* is an implementation of the W3C `XML Signature <http://en.wikipedia.org/wiki/XML_Signature>`_ standard in
Python. This standard (also known as XMLDSig) is used to provide payload security in `SAML 2.0
<http://en.wikipedia.org/wiki/SAML_2.0>`_, among other uses. *SignXML* implements all of the required components of the
standard. Its features are:

* Extensions to allow the use of stronger hash functions (e.g. SHA256 instead of SHA1)
* Extensions to allow signing and verifying with all common certificate formats
* Modern Python compatibility (2.7-3.4+ and PyPy)
* Minimal and reliable dependency footprint: `lxml <https://github.com/lxml/lxml>`_, `pycrypto <https://github.com/dlitz/pycrypto>`_, `eight <https://github.com/kislyuk/eight>`_
* Comprehensive testing and `continuous integration <https://travis-ci.org/kislyuk/signxml>`_
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

    xmldsig(d).sign()
    xmldsig(d).verify()

Authors
-------
* Andrey Kislyuk

Links
-----
* `Project home page (GitHub) <https://github.com/kislyuk/signxml>`_
* `Documentation (Read the Docs) <https://signxml.readthedocs.org/en/latest/>`_
* `Package distribution (PyPI) <https://warehouse.python.org/project/signxml/>`_
* `W3C Recommendation: XML Signature Syntax and Processing (Second Edition) <http://www.w3.org/TR/xmldsig-core/>`_

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
        :target: https://warehouse.python.org/project/signxml/
