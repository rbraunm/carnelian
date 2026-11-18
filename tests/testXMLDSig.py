# SPDX-License-Identifier: MIT
"""Enveloped XML Signatures made by signxml (an independent implementation), verified, and attacked."""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from lxml import etree
from signxml import XMLSigner

from carnelian.signatures import ECPublicKey, RSAPublicKey
from carnelian.xmldsig import SignatureRefused, verifyEnveloped
from carnelian.xmlTree import parse

samlAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
template = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"><saml:Assertion xmlns:saml="{samlAssertion}" ID="a1"><saml:Issuer>https://idp.example.org</saml:Issuer><saml:Subject><saml:NameID>ana@example.org</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"""
rsaKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ecKey = ec.generate_private_key(ec.SECP256R1())
rsaPublic = RSAPublicKey(rsaKey.public_key().public_numbers().n, rsaKey.public_key().public_numbers().e)
ecPublic = ECPublicKey("P-256", ecKey.public_key().public_numbers().x, ecKey.public_key().public_numbers().y)


def signedResponse(algorithm="rsa-sha256", digest="sha256", key=rsaKey):
  root = etree.fromstring(template)
  assertion = root[0]
  signer = XMLSigner(signature_algorithm=algorithm, digest_algorithm=digest, c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
  signed = signer.sign(assertion, key=key, reference_uri="#a1", always_add_key_value=False)
  root.replace(assertion, signed)
  return root


def assertionOf(data):
  root = parse(etree.tostring(data) if not isinstance(data, bytes) else data)
  return root, next(element for element in root.descendants() if element.localName == "Assertion")


@pytest.mark.parametrize("algorithm, digest, key, public", [
  ("rsa-sha256", "sha256", rsaKey, rsaPublic), ("rsa-sha512", "sha384", rsaKey, rsaPublic),
  ("ecdsa-sha256", "sha256", ecKey, ecPublic), ("ecdsa-sha384", "sha512", ecKey, ecPublic),
])
def testSignaturesMadeBySignxmlVerify(algorithm, digest, key, public):
  _, assertion = assertionOf(signedResponse(algorithm, digest, key))
  assert verifyEnveloped(assertion, [ecPublic, public]) is assertion


def testAChangedAssertionIsRefused():
  root = signedResponse()
  root.find(f".//{{{samlAssertion}}}NameID").text = "admin@example.org"
  _, assertion = assertionOf(root)
  with pytest.raises(SignatureRefused, match="digest does not match: it was changed after signing"):
    verifyEnveloped(assertion, [rsaPublic])


def testAnotherKeyDoesNotVerify():
  other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
  _, assertion = assertionOf(signedResponse())
  with pytest.raises(SignatureRefused, match="does not verify with any trusted key"):
    verifyEnveloped(assertion, [RSAPublicKey(other.n, other.e)])


def testSHA1IsRefusedByName():
  root = signedResponse()
  method = root.find(".//{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
  method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
  with pytest.raises(SignatureRefused, match="SHA-1 digests are refused"):
    verifyEnveloped(assertionOf(root)[1], [rsaPublic])


def testAnUnsignedElementIsRefused():
  _, assertion = assertionOf(template.encode())
  with pytest.raises(SignatureRefused, match="has 0 <Signature> children"):
    verifyEnveloped(assertion, [rsaPublic])


def testADuplicateIDIsRefused():
  root = signedResponse()
  evil = copy.deepcopy(root[0])
  evil.remove(evil.find("{http://www.w3.org/2000/09/xmldsig#}Signature"))
  evil.find(f".//{{{samlAssertion}}}NameID").text = "admin@example.org"
  root.append(evil)
  with pytest.raises(SignatureRefused, match="2 elements carry ID 'a1'"):
    verifyEnveloped(assertionOf(root)[1], [rsaPublic])


def testASignatureForAnotherElementIsRefused():
  root = signedResponse()
  root[0].set("ID", "a2")
  with pytest.raises(SignatureRefused, match="the reference '#a1' is not to the signed element's ID 'a2'"):
    verifyEnveloped(assertionOf(root)[1], [rsaPublic])


def testExtraTransformsAreRefused():
  root = signedResponse()
  transforms = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Transforms")
  extra = etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform")
  extra.set("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116")
  with pytest.raises(SignatureRefused, match="exactly enveloped-signature, then exclusive c14n"):
    verifyEnveloped(assertionOf(root)[1], [rsaPublic])
