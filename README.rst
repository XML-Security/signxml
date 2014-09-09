UNDER DEVELOPMENT

SignXML: XML Signature in Python
================================

*SignXML* is an implementation of the W3C `XML Signature <http://en.wikipedia.org/wiki/XML_Signature>`_ standard in
Python. This standard is used to provide payload security in `SAML 2.0 <http://en.wikipedia.org/wiki/SAML_2.0>`_, among
other uses. *SignXML* implements all of the required components of the standard.

 The following development goals are
emphasized:

* Modern Python compatibility (2.7-3.4+ and PyPy)
* Minimal dependency footprint: ``lxml``, ``pycrypto``, ``eight``
* Safe cryptographic and XML processing choices
* A comprehensive test matrix
* Simplicity, compactness, readability, and extensibility

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
