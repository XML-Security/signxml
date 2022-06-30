Changes for v2.9.1 (2022-06-30)
===============================

-  Added hooks for pyinstaller and fixed relative file import. Fixes #16

Changes for v2.9.0 (2021-10-08)
===============================

-  Unlimit cryptography version constraint. Fixes #177

-  Bump pyOpenSSL compat range; add dep version strategy note

Changes for v2.8.2 (2021-05-14)
===============================

-  Allow the combination of X509Data and KeyValue when they represent
   the same public key (#169)

-  Use self.namespaces signature properties “Object” element (#167)

Changes for v2.8.1 (2020-10-29)
===============================

-  Allow cryptography versions >3 (but <4) (#164)

-  Add support for adding Signature Properties to a detached signature
   (#160)

Changes for v2.8.0 (2020-06-20)
===============================

-  Compare raw digest bytes instead of base64 encoded digests. Fixes
   #155

-  Initial X509IssuerSerial/X509Digest support

-  Support custom inclusive_ns_prefixes when signing

Changes for v2.7.3 (2020-06-10)
===============================

-  Fix ECDSA signature encoding/decoding (#150)

-  Add InclusiveNamespaces PrefixList support for SignedInfo

-  Test and documentation improvements

Changes for v2.7.2 (2019-12-01)
===============================

-  Relax dependency version range on eight

-  Update dependency installation documentation

-  XMLSigner.sign(): add always_add_key_value kwarg to include both
   X509Data and KeyValue for ill-defined signing applications

-  XMLVerifier.verify(): reject signatures that contain both X509Data
   and KeyValue by default; add ignore_ambiguous_key_info kwarg to
   bypass

Changes for v2.7.1 (2019-11-30)
===============================

-  Accept PEM keys as either str or bytes

Changes for v2.7.0 (2019-11-30)
===============================

-  Drop defusedxml dependency; add security notes

-  Add missing c14n transform for enveloping and detached methods (#107)

-  Relax pyOpenSSL dependency version range to include version 19

-  Apply transforms and digest calculations to copies of root. Closes
   #125. (#126)

-  Documentation and test improvements

Changes for v2.6.0 (2019-01-10)
===============================

-  Update dependencies to baseline on Ubuntu 18.04

-  Clarify documentation of Ubuntu installation dependencies

-  List ipaddress as a dependency

-  Strip PEM header from OpenSSL.crypto.X509 cert

-  Doc updates: dependency versions, standard links

-  Fix cryptography deprecation warnings. Closes #108

-  Allow URI attribute of Reference to be absent (#102)

Changes for v2.5.2 (2017-12-07)
===============================

-  Fix release

Changes for v2.5.1 (2017-12-07)
===============================

Fix release

Changes for v2.5.0 (2017-12-07)
===============================

-  Relax dependency version constraints.

-  Drop Python 3.3 support.

-  Support for PEM files with CR+LF line endings (#93).

Changes for v2.4.0 (2017-07-10)
===============================

-  Import asn1crypto on demand

-  Allow newer versions of cryptography library (#89)

Changes for v2.3.0 (2017-04-24)
===============================

-  Add explicit dependency on asn1crypto to setup.py (#87)

-  Remove use of Exception.message for py3 compatibility. Closes #36
   (#86)

-  Use asn1crypto instead of pyasn1 to match cryptography lib (#85)

-  Pin to major version of lxml instead of minor

-  Allow newer versions of several requirements (#84)

-  Allow newer version of eight library (#83)

Changes for v2.2.4 (2017-03-19)
===============================

-  Documentation and test fixes

Changes for v2.2.3 (2016-12-20)
===============================

-  Release automation: parse repo name correctly

Changes for v2.2.2 (2016-12-20)
===============================

-  Expand supported cryptography version range. Fixes #74

-  Documentation and release automation improvements

Changes for v2.2.1 (2016-09-26)
===============================

-  Fix handling of reference URIs in detached signing

-  Test infra fixes

Changes for v2.2.0 (2016-09-25)
===============================

-  Support custom key info when signing
-  Initial elements of ws-security support
-  Support signing and verifying multiple references

Changes for v2.1.4 (2016-09-18)
===============================

-  Only sign the referenced element when passed reference\_uri (thanks
   to @soby).

-  Add CN validation - instead of a full X.509 certificate, it is now
   possible to pass a common name that will be matched against the CN of
   a cert trusted by the CA store.

-  Order-agnostic cert chain validation and friendlier ingestion of cert
   chains.

-  Minor/internal changes; packaging fix for 2.1.0

Changes for v2.1.0 (2016-09-18)
===============================

-  Pre-release; see notes for v2.1.4

Version 2.0.0 (2016-08-05)
--------------------------
- Major API change: signxml.xmldsig(data).sign() -> signxml.XMLSigner().sign(data)
- Major API change: signxml.xmldsig(data).verify() -> signxml.XMLVerifier().verify(data)
- Signer and verifier objects now carry no data-specific state; instead carry system configuration state that is
  expected to be reused
- Signer and verifier objects should now be safe to reuse in reentrant environments
- Internal architecture changes to improve modularity and eliminate data-specific latent state and side effects

Version 1.0.2 (2016-08-01)
--------------------------
- Update xmlenc namespaces for downstream encryptxml support

Version 1.0.1 (2016-07-14)
--------------------------
- Packaging fix: remove stray .pyc file

Version 1.0.0 (2016-04-08)
--------------------------
- Major API change: Return signature information in verify() return value (#41, #50). Thanks to @klondi.
- Major API change: Excise signature node from verify() return value to avoid possibly returning untrusted data (#47). Thanks to @klondi.

Version 0.6.0 (2016-03-24)
--------------------------
- Remove signature nodes appropriately (#46). Thanks to @klondi.
- Expand Travis CI test to include flake8 linter.

Version 0.5.0 (2016-03-02)
--------------------------
- Add support for using a KeyName element within the KeyInfo block (#38). Thanks to @Pelleplutt.
- Update cryptography dependency
- Expand Travis CI test matrix to include OS X

Version 0.4.6 (2015-11-28)
--------------------------
- Python 3.5 compatibility fix: move enum34 into conditional dependencies (#37). Thanks to @agronholm.

Version 0.4.5 (2015-11-08)
--------------------------
- Support enveloped signatures nested at arbitrary levels beneath root element (#32, #33). Thanks to @jmindek.
- Update certifi, cryptography dependencies

Version 0.4.4 (2015-08-07)
--------------------------
- Handle xml.etree.ElementTree nodes as input (previously these would cause a crash, despite the documentation suggesting otherwise). Closes #19, thanks to @nickcash.

Version 0.4.3 (2015-07-26)
--------------------------
- Do not open schema file in text mode when parsing XML (closes #18, thanks to @nick210)
- Update cryptography dependency

Version 0.4.2 (2015-04-24)
--------------------------
- Add support for parameterizable signature namespace (PR #12, thanks to @ldnunes)
- Update cryptography dependency

Version 0.4.1 (2015-04-21)
--------------------------
- Add support for detached signatures (closes #3)
- Update pyOpenSSL dependency; use X509StoreContext.verify_certificate()

Version 0.4.0 (2015-03-08)
--------------------------
- Use pyasn1 for DER encoding and decoding, eliminating some DSA signature verification failures

Version 0.3.9 (2015-02-04)
--------------------------
- Do not distribute tests in source archive

Version 0.3.7 (2015-02-04)
--------------------------
- Configurable id attribute name for verifying non-standard internal object references, e.g. ADFS (closes #6)

Version 0.3.6 (2015-01-10)
--------------------------
- Python 3 compatibility fixes
- Fix test matrix (Python version configuration) in Travis

Version 0.3.5 (2014-12-22)
--------------------------
- Refactor application of enveloped signature transforms
- Support base64 transform
- Support application of different canonicalization algorithms to signature and payload (closes #1)

Version 0.3.4 (2014-12-14)
--------------------------
- Add support for exclusive canonicalization with InclusiveNamespaces PrefixList attribute

Version 0.3.3 (2014-12-13)
--------------------------
- Overhaul support of canonicalization algorithms

Version 0.3.2 (2014-12-11)
--------------------------
- Fix bug in enveloped signature canonicalization of namespace prefixes

Version 0.3.1 (2014-10-17)
--------------------------
- Fix bug in enveloped signature excision

Version 0.3.0 (2014-10-16)
--------------------------
- Allow location of enveloped signature to be specified

Version 0.2.9 (2014-10-14)
--------------------------
- Use exclusive c14n when signing

Version 0.2.8 (2014-10-13)
--------------------------
- Namespace all tags when generating signature

Version 0.2.7 (2014-10-13)
--------------------------
- Switch default signing method to enveloped signature

Version 0.2.6 (2014-10-13)
--------------------------
- Fix typo in ns prefixing code

Version 0.2.5 (2014-10-13)
--------------------------
- Fix handling of DER sequences in DSA key serialization
- Parameterize excision with ns prefix

Version 0.2.4 (2014-10-12)
--------------------------
- Fix excision with ns prefix

Version 0.2.3 (2014-10-12)
--------------------------
- Fixes to c14n of enveloped signatures
- Expand tests to use the XML Signature interoperability test suite

Version 0.2.2 (2014-10-04)
--------------------------
- Load bare X509 certificates from SAML metadata correctly

Version 0.2.1 (2014-10-04)
--------------------------
- Always use X509 information even if key value is present
- Internal refactor to modularize key value handling logic

Version 0.2.0 (2014-10-02)
--------------------------
- Use defusedxml when verifying signatures.
- Eliminate dependency on PyCrypto.
- Introduce support for ECDSA asymmetric key encryption.
- Introduce ability to validate xmldsig11 schema.
- Expand test suite coverage.

Version 0.1.9 (2014-09-27)
--------------------------
- Allow use of external X509 certificates for validation; add an example of supplying a cert from SAML metadata.

Version 0.1.8 (2014-09-25)
--------------------------
- Packaging fix.

Version 0.1.7 (2014-09-25)
--------------------------
- Packaging fix.

Version 0.1.6 (2014-09-25)
--------------------------
- Accept etree elements in verify.

Version 0.1.5 (2014-09-25)
--------------------------
- Packaging fix.

Version 0.1.4 (2014-09-25)
--------------------------
- Begin work toward conformance with version 1.1 of the spec.

Version 0.1.3 (2014-09-23)
--------------------------
- Require x509 for verification by default.

Version 0.1.2 (2014-09-22)
--------------------------
- Documentation fixes.

Version 0.1.1 (2014-09-22)
--------------------------
- Documentation fixes.

Version 0.1.0 (2014-09-22)
--------------------------
- Initial release.
