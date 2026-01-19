Changes for v4.2.1 (2026-01-18)
===============================

- Add legacy SigningCertificate with IssuerSerial for XAdES
  interoperability (#282)

Changes for v4.2.0 (2025-08-19)
===============================

- Align behaviour of expect_references with docs (#279). Passing
  ``expect_references=True`` to ``verify(...)`` now results in a list of
  ``verify_results``, irrespective of the number of references in the
  signature.

- Accept lxml 6.x

Changes for v4.1.0 (2025-06-28)
===============================

-  Add options to exclude the C14N Transform element in signatures
   (#274)

Changes for v4.0.5 (2025-06-02)
===============================

-  Use Python 3.9 compatible typing expression

Changes for v4.0.4 (2025-06-01)
===============================

This release contains security fixes for two security advisories:

-  Signature verification with HMAC is vulnerable to an algorithm
   confusion attack
   (https://github.com/XML-Security/signxml/security/advisories/GHSA-6vx8-pcwv-xhf4)

-  Signature verification with HMAC is vulnerable to a timing attack
   (https://github.com/XML-Security/signxml/security/advisories/GHSA-gmhf-gg8w-jw42)

Changes for v4.0.3 (2024-11-23)
===============================

-  Fix issue with support for deprecated PyOpenSSL certificates

-  Fully remove the ca_path parameter; add docs for signature location
   pinning

Changes for v4.0.2 (2024-09-10)
===============================

-  XAdES signing: remove duplicate timezone information from
   ``SigningTime`` (#266)

Changes for v4.0.1 (2024-08-30)
===============================

-  Verifier: Accept PyOpenSSL cert input, add deprecation warning

Changes for v4.0.0 (2024-08-21)
===============================

-  Replace PyOpenSSL with Cryptography (#260)

   -  This is a major infrastructure change that replaces core
      certificate parsing, key processing, signature validation, and
      certificate chain validation functions previously provided by
      PyOpenSSL with those provided by Cryptography. Care was taken to
      preserve the exisitng API, including exception types, but many
      error messages raised in various error conditions have changed. If
      you see unexpected behavior and you have reason to believe it is
      incorrect, please file an issue.

   -  Breaking change: the ca_path parameter, previously used to specify
      CA certificate stores, is no longer supported. Use the ca_pem_file
      parameter instead.

-  Raise error when invalid certificate string is passed as input to
   signer

-  Fix public key matching for ECDSA (#245)

Changes for v3.2.2 (2024-01-28)
===============================

-  Update upper bound on lxml dependency to allow lxml 5

-  Bump minimum dependency versions to align with Ubuntu 20.04

-  Test and release infrastructure improvements

Changes for v3.2.1 (2023-08-06)
===============================

-  Use dataclass.replace in SignatureReference construction. Fixes #231

Changes for v3.2.0 (2023-04-12)
===============================

-  Roundtrip referenced XML nodes before c14n to detach them from parent
   document when verifying (#225)

Changes for v3.1.1 (2023-04-08)
===============================

-  Add type attribute to XAdES signed properties reference (#224)

Changes for v3.1.0 (2023-01-04)
===============================

-  Use distinct default for payload c14n. Fixes #217

-  Deprecate SHA1

-  Test and documentation improvements

Changes for v3.0.2 (2022-11-28)
===============================

-  Remove incorrect deprecation of xml-c14n11 URI

Changes for v3.0.1 (2022-11-27)
===============================

-  Mark SHA1 as deprecated

-  Aggregate verification settings in SignatureConfiguration dataclass

-  Mark all dataclasses in API as frozen

-  Add ability to assert expected signature location

-  Add ability to assert expected signature algorithms

-  Add ability to assert expected digest algorithms

-  Add MGF1 (“RSASSA-PSS without parameters”) algorithm identifiers

-  Remove PSS (“RSASSA-PSS with parameters”) and EdDSA algorithm
   identifiers (given low usage and no interop examples, we will not be
   implementing PSS parameters for now; EdDSA key info additionally has
   no standardized way to serialize it)

-  Add debug logging of canonicalization outputs

-  Documentation and formatting improvements

Changes for v3.0.0 (2022-11-13)
===============================

-  Add XAdES support

-  Migrate all configuration inputs to enums (string identifiers are
   still supported, but will be deprecated in a future version)

-  Migrate structured data inputs to dataclasses

-  Deprecate excise_empty_xmlns_declarations

-  Documentation and test infrastructure improvements

-  Clean up top level signxml and signxml.xades namespaces

-  Stop using default_backend for cryptography, it is no longer required

-  Drop Python 3.6 support (#200)

-  Drop Python 3.6 support.

Changes for v2.10.1 (2022-09-09)
================================

-  Do not excise any empty ``xmlns=""`` declarations by default. This
   behavior is now configurable as follows

   ::

      signer = XMLSigner()
      signer.excise_empty_xmlns_declarations = True
      signer.sign(...)

   ::

      verifier = XMLVerifier()
      verifier.excise_empty_xmlns_declarations = True
      verifier.verify(...)

-  Documentation and autoformatting improvements

Changes for v2.10.0 (2022-08-20)
================================

-  Excise empty xmlns declarations only in signature, not in payload

-  Add pyinstaller support to signxml (#188)

-  Documentation, test infrastructure, and code organization
   improvements

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
