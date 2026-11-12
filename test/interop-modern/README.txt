Modernized xmlsec interoperability vectors
=========================================

Copied unchanged from https://github.com/lsh123/xmlsec/tree/ca209d82429783d5120f71b90bdd1dac14cf0c7e/tests
(11 November 2026): xmldsig11-interop-2012.modern,
merlin-xmldsig-twenty-three.modern, and phaos-xmldsig-three.modern.
Their README.txt files describe the upstream provenance and modernization.
The upstream Copyright notice is included in this directory.
These are xmlsec re-signings of historical suites, not new W3C recommendations.
The unsigned templates are retained alongside the signed vectors.

Support files from the same revision:
- external-data/xml-stylesheet-2005 and xml-stylesheet-2005.b64
- external-data/rfc3161.txt
- keys/rsa/rsa-4096-cert.pem (public certificate for X509Digest resolution)
No private keys are required. HMAC fixtures use the public test secret "secret".

Run: python test/test_modern_interop.py -v

The suite pins embedded leaf certificates and uses a time within their validity
period; it tests signature interoperability, not certificate-chain policy.
The X509Digest case additionally exercises the certificate resolver.
Unsupported Manifest, XPath/XSLT and key lookup cases are explicit skips.
Truncated HMAC and corrupted signatures must be rejected.
