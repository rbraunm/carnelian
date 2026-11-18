# SPDX-License-Identifier: MIT
"""SAML with the service provider's own keys: encrypted assertions built here with cryptography as the oracle, signed
requests and single logout checked with it, the core loaded without cryptography, then a real Keycloak."""

import base64
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
import http.cookiejar
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from lxml import etree

from carnelian.fetching import Fetcher, secureContext
from carnelian.keys import DecryptionFailed, LocalDecryptionKey, LocalSigningKey, ecdsaSHA256, rsaSHA256
from carnelian.saml import (EncryptionPolicy, IdentityProvider, ReplayCache, SAMLRefused, ServiceProvider, SignOutRequest,
                            aes128CBC, aes128GCM, aes256CBC, aes256GCM, claimedIssuer, identityProviderFromMetadata, rsaOAEP,
                            rsaOAEPMGF1P, serviceProviderMetadata)
from carnelian.xmlTree import parse

from testOIDC import _Form, _Stop, account
from testSAML import (acs, certificateFor, dsigNS, idp, instant, key, now, pending, posted, public, response, saml, samlp,
                      signAssertion, signed, sp, _Posted)

xenc = "http://www.w3.org/2001/04/xmlenc#"
xenc11 = "http://www.w3.org/2009/xmlenc11#"
sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256"
slo = "https://sp.example.org/slo"
idpLogout = f"{idp}/protocol/saml"


def pemPair(privateKey):
  der = base64.b64decode(certificateFor(privateKey))
  certificate = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
  return privateKey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()), certificate


signingPrivate = rsa.generate_private_key(public_exponent=65537, key_size=2048)
decryptionPrivate = rsa.generate_private_key(public_exponent=65537, key_size=2048)
signingKey = LocalSigningKey(*pemPair(signingPrivate))
decryptionKey = LocalDecryptionKey(*pemPair(decryptionPrivate))
otherDecryptionKey = LocalDecryptionKey(*pemPair(rsa.generate_private_key(public_exponent=65537, key_size=2048)))
cbcPolicy = EncryptionPolicy(contentAlgorithms=frozenset({aes128GCM, aes256GCM, aes128CBC, aes256CBC}))
hashFor = {None: hashes.SHA1, sha256Digest: hashes.SHA256, f"{xenc11}mgf1sha256": hashes.SHA256}


def encrypt(root, content=aes256GCM, transport=rsaOAEPMGF1P, digest=None, mask=None, recipient=decryptionPrivate,
            placement="inside", keyCount=1, label=None, tamper=False, rewrite=None):
  """Replace the response's assertion by an EncryptedAssertion, the way an identity provider encrypts it."""
  assertion = root.find(f"{{{saml}}}Assertion")
  plaintext = etree.tostring(assertion) if rewrite is None else rewrite(etree.tostring(assertion))
  contentKey = os.urandom(16 if "128" in content else 32)
  if content.endswith("gcm"):
    iv = os.urandom(12)
    cipherData = iv + AESGCM(contentKey).encrypt(iv, plaintext, None)
  else:
    count = 16 - len(plaintext) % 16
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(contentKey), modes.CBC(iv)).encryptor()
    cipherData = iv + encryptor.update(plaintext + os.urandom(count - 1) + bytes([count])) + encryptor.finalize()
  if tamper:
    cipherData = cipherData[:-1] + bytes([cipherData[-1] ^ 1])
  if transport == f"{xenc}rsa-1_5":
    wrapped = recipient.public_key().encrypt(contentKey, padding.PKCS1v15())
  else:
    wrapped = recipient.public_key().encrypt(contentKey, padding.OAEP(
      mgf=padding.MGF1(hashFor[mask]()), algorithm=hashFor[digest](), label=None))
  parameters = (f'<ds:DigestMethod Algorithm="{digest}"/>' if digest else "") + (
    f'<xenc11:MGF Algorithm="{mask}"/>' if mask else "")
  encryptedKey = (f'<xenc:EncryptedKey Id="k1"><xenc:EncryptionMethod Algorithm="{transport}">{parameters}'
                  f"</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>{base64.b64encode(wrapped).decode()}"
                  "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>")
  keyInfo = (encryptedKey * keyCount if placement == "inside"
             else f'<ds:RetrievalMethod Type="{xenc}EncryptedKey" URI="#k1"/>')
  data = (f'<xenc:EncryptedData Type="{xenc}Element"><xenc:EncryptionMethod Algorithm="{label or content}"/>'
          f"<ds:KeyInfo>{keyInfo}</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{base64.b64encode(cipherData).decode()}"
          "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>")
  root.replace(assertion, etree.fromstring(
    f'<saml:EncryptedAssertion xmlns:saml="{saml}" xmlns:xenc="{xenc}" xmlns:xenc11="{xenc11}" xmlns:ds="{dsigNS}">'
    f'{data}{encryptedKey if placement == "beside" else ""}</saml:EncryptedAssertion>'))
  return root


def provider(decryptionKeys=(decryptionKey,), encryptionPolicy=EncryptionPolicy(), withSigningKey=True, cache=None):
  identityProvider = IdentityProvider(idp, f"{idp}/sso", (public,), singleLogoutURL=idpLogout)
  return ServiceProvider(sp, acs, identityProvider, clock=lambda: now, replayCache=cache,
                         signingKey=signingKey if withSigningKey else None, decryptionKeys=decryptionKeys,
                         encryptionPolicy=encryptionPolicy, singleLogoutURL=slo)


# ---- encrypted assertions --------------------------------------------------

@pytest.mark.parametrize("content, transport, digest, mask", [
  (aes256GCM, rsaOAEPMGF1P, None, None),
  (aes128GCM, rsaOAEPMGF1P, sha256Digest, None),
  (aes256GCM, rsaOAEP, None, None),
  (aes128GCM, rsaOAEP, sha256Digest, f"{xenc11}mgf1sha256"),
])
def testAnEncryptedSignedAssertionGivesTheIdentity(content, transport, digest, mask):
  root = encrypt(signAssertion(response()), content, transport, digest, mask)
  identity = provider().finishSignIn(pending, posted(root))
  assert (identity.nameID, identity.sessionIndex) == ("ana", "s-1")
  assert identity.attributes == {"groups": ("/field/team-a", "/analysts")}


def testAnEncryptedKeyBesideTheDataIsFoundThroughItsRetrievalMethod():
  root = encrypt(signAssertion(response()), placement="beside")
  assert provider().finishSignIn(pending, posted(root)).nameID == "ana"


def testEveryConfiguredDecryptionKeyIsTried():
  root = encrypt(signAssertion(response()))
  assert provider(decryptionKeys=(otherDecryptionKey, decryptionKey)).finishSignIn(pending, posted(root)).nameID == "ana"


@pytest.mark.parametrize("content", [aes128CBC, aes256CBC])
def testCBCIsDecryptedWhenAllowedAndTheResponseSignatureVerifiedFirst(content):
  root = signed(encrypt(response(), content))
  assert provider(encryptionPolicy=cbcPolicy).finishSignIn(pending, posted(root)).nameID == "ana"


def testACiphertextChangedUnderASignedResponseIsRefusedByTheSignatureBeforeDecrypting():
  root = signed(encrypt(response(), aes128CBC))
  value = root.find(f"{{{saml}}}EncryptedAssertion/{{{xenc}}}EncryptedData/{{{xenc}}}CipherData/{{{xenc}}}CipherValue")
  cipherData = bytearray(base64.b64decode(value.text))
  cipherData[20] ^= 1
  value.text = base64.b64encode(bytes(cipherData)).decode()
  with pytest.raises(SAMLRefused, match="digest does not match"):
    provider(encryptionPolicy=cbcPolicy).finishSignIn(pending, posted(root))


@pytest.mark.parametrize("build, policy, message", [
  (lambda: encrypt(signAssertion(response()), transport=f"{xenc}rsa-1_5"), EncryptionPolicy(),
   r"RSA PKCS #1 v1.5 key transport \(xmlenc#rsa-1_5\) is always refused"),
  (lambda: signed(encrypt(response(), aes128CBC)), EncryptionPolicy(),
   "content encryption http://www.w3.org/2001/04/xmlenc#aes128-cbc is not allowed by this provider's encryption policy"),
  (lambda: encrypt(signAssertion(response()), aes256CBC), cbcPolicy,
   "AES-CBC content is decrypted only under a verified signature on the Response itself"),
  (lambda: encrypt(signAssertion(response()), label=f"{xenc}tripledes-cbc"), EncryptionPolicy(),
   "content encryption http://www.w3.org/2001/04/xmlenc#tripledes-cbc is not supported"),
  (lambda: encrypt(signAssertion(response()), keyCount=2), EncryptionPolicy(),
   "2 EncryptedKeys go with the EncryptedData; exactly one is accepted"),
  (lambda: encrypt(signAssertion(response()), transport=rsaOAEP), EncryptionPolicy(keyTransports=frozenset({rsaOAEPMGF1P})),
   "key transport http://www.w3.org/2009/xmlenc11#rsa-oaep is not allowed"),
  (lambda: encrypt(signAssertion(response())), EncryptionPolicy(oaepDigests=frozenset({sha256Digest})),
   "OAEP digest http://www.w3.org/2000/09/xmldsig#sha1 is not allowed"),
  (lambda: encrypt(signAssertion(response()), transport=rsaOAEPMGF1P, mask=f"{xenc11}mgf1sha256"), EncryptionPolicy(),
   "rsa-oaep-mgf1p fixes MGF1 with SHA-1; an MGF element is refused"),
])
def testEncryptionOutsideThePolicyIsRefusedByName(build, policy, message):
  with pytest.raises(SAMLRefused, match=message):
    provider(encryptionPolicy=policy).finishSignIn(pending, posted(build()))


def testATamperedCiphertextAndAWrongKeyGetTheSameRefusal():
  refusals = []
  for root, keys in ((encrypt(signAssertion(response()), tamper=True), (decryptionKey,)),
                     (encrypt(signAssertion(response())), (otherDecryptionKey,)),
                     (signed(encrypt(response(), aes128CBC, tamper=True)), (decryptionKey,))):
    with pytest.raises(SAMLRefused) as refused:
      provider(decryptionKeys=keys, encryptionPolicy=cbcPolicy).finishSignIn(pending, posted(root))
    refusals.append(str(refused.value))
  assert refusals == ["the encrypted assertion does not decrypt with this service provider's keys"] * 3


extension = "urn:example:extension"
roleStatement = (b'<x:AttributeStatement><x:Attribute Name="role"><x:AttributeValue>admin</x:AttributeValue></x:Attribute>'
                 b"</x:AttributeStatement></saml:Assertion>")


def responseDeclaringX():
  """A response whose root declares the prefix x, which nothing outside the encrypted assertion uses."""
  return etree.fromstring(etree.tostring(response()).replace(b"<samlp:Response ", f'<samlp:Response xmlns:x="{extension}" '.encode(), 1))


def testADecryptedAssertionUsingAPrefixFromOutsideItIsRefusedUnderTheResponseSignature():
  # Exclusive canonicalization leaves out xmlns:x, so it can be rebound without breaking the Response's signature.
  def withRoles(plaintext):
    return plaintext.replace(f' xmlns:x="{extension}"'.encode(), b"").replace(b"</saml:Assertion>", roleStatement)
  root = signed(encrypt(responseDeclaringX(), rewrite=withRoles))
  document = etree.tostring(root)
  rebound = document.replace(f'xmlns:x="{extension}"'.encode(), f'xmlns:x="{saml}"'.encode())
  assert rebound != document
  for sent in (document, rebound):
    with pytest.raises(SAMLRefused, match=r"the decrypted assertion uses namespace prefixes \['x'\] declared outside it"):
      provider().finishSignIn(pending, base64.b64encode(sent).decode())


def testADecryptedAssertionWithItsOwnSignatureMayUsePrefixesFromOutsideIt():
  root = encrypt(signAssertion(response()), rewrite=lambda plaintext: plaintext.replace(f' xmlns:saml="{saml}"'.encode(), b"", 1))
  assert provider().finishSignIn(pending, posted(root)).nameID == "ana"


class RecordingKey:
  """A decryption key that notes each operation it is asked for, with the content algorithm and key length."""

  def __init__(self, key):
    self.key, self.calls = key, []

  @property
  def certificate(self):
    return self.key.certificate

  def unwrapKey(self, wrappedKey, oaepDigest, maskDigest):
    self.calls.append("unwrapKey")
    return self.key.unwrapKey(wrappedKey, oaepDigest, maskDigest)

  def decryptContent(self, algorithm, contentKey, cipherData):
    self.calls.append(("decryptContent", algorithm, len(contentKey)))
    return self.key.decryptContent(algorithm, contentKey, cipherData)


def testEveryKeyUnwrapsAndDecryptsContentWhetherOrNotItsUnwrapFails():
  right, wrong = RecordingKey(decryptionKey), RecordingKey(otherDecryptionKey)
  assert provider(decryptionKeys=(right, wrong)).finishSignIn(pending, posted(encrypt(signAssertion(response())))).nameID == "ana"
  assert right.calls == wrong.calls == ["unwrapKey", ("decryptContent", "aes256-gcm", 32)]
  alone = RecordingKey(otherDecryptionKey)
  with pytest.raises(SAMLRefused, match="does not decrypt with this service provider's keys"):
    provider(decryptionKeys=(alone,)).finishSignIn(pending, posted(encrypt(signAssertion(response()), aes128GCM)))
  assert alone.calls == ["unwrapKey", ("decryptContent", "aes128-gcm", 16)]


def testEveryDecryptionFailureOfTheBackendIsOneTypeWithOneMessage():
  failures = []
  for attempt in (lambda: decryptionKey.unwrapKey(bytes(256), "sha1", "sha1"),
                  lambda: decryptionKey.decryptContent("aes256-gcm", bytes(32), bytes(40)),
                  lambda: decryptionKey.decryptContent("aes128-gcm", bytes(32), bytes(40)),
                  lambda: decryptionKey.decryptContent("aes128-cbc", bytes(16), bytes(8))):
    with pytest.raises(DecryptionFailed) as failed:
      attempt()
    failures.append(str(failed.value))
  assert failures == ["this does not decrypt with this key"] * 4


def testADecryptedAssertionStillNeedsASignature():
  with pytest.raises(SAMLRefused, match="neither the response nor its assertion is signed"):
    provider().finishSignIn(pending, posted(encrypt(response())))


def testADecryptedAssertionGoesThroughEveryCheck():
  with pytest.raises(SAMLRefused, match="not for 'https://sp.example.org/meta'"):
    provider().finishSignIn(pending, posted(encrypt(signAssertion(response(audience="https://other.example.org")))))
  cache = ReplayCache()
  provider(cache=cache).finishSignIn(pending, posted(encrypt(signAssertion(response()))))
  with pytest.raises(SAMLRefused, match="assertion 'a1' was already used"):
    provider(cache=cache).finishSignIn(pending, posted(encrypt(signAssertion(response()))))


def testWithoutDecryptionKeysAnEncryptedAssertionStaysRefusedByName():
  with pytest.raises(SAMLRefused, match="encrypted assertions are refused: this service provider has no decryption key"):
    provider(decryptionKeys=()).finishSignIn(pending, posted(encrypt(signAssertion(response()))))


def testAnEncryptedAssertionBesideAPlainOneIsRefused():
  root = encrypt(signAssertion(response()))
  root.append(signAssertion(response()).find(f"{{{saml}}}Assertion"))
  with pytest.raises(SAMLRefused, match="exactly one assertion, plain or encrypted"):
    provider().finishSignIn(pending, posted(root))


@pytest.mark.parametrize("arguments, message", [
  ({"keyTransports": frozenset({f"{xenc}rsa-1_5"})}, "always refused"),
  ({"contentAlgorithms": frozenset({f"{xenc}tripledes-cbc"})}, "is not supported"),
  ({"contentAlgorithms": frozenset()}, "allows no content encryption"),
])
def testAnEncryptionPolicyOutsideWhatIsSafeIsRefused(arguments, message):
  with pytest.raises(ValueError, match=message):
    EncryptionPolicy(**arguments)


def testOneKeyCannotBothSignAndDecrypt():
  with pytest.raises(ValueError, match="the signing key is also a decryption key"):
    ServiceProvider(sp, acs, IdentityProvider(idp, f"{idp}/sso", (public,)), signingKey=signingKey,
                    decryptionKeys=(LocalDecryptionKey(*pemPair(signingPrivate)),))


def testTheCoreDoesNotImportCryptography():
  modules = "carnelian.saml, carnelian.federation, carnelian.oidc, carnelian.cas, carnelian.ldap, carnelian.scim, carnelian.workload"
  program = "import sys, {0}; {1}; print(sorted(name for name in sys.modules if name.split('.')[0] == 'cryptography')[:1])"
  root = str(Path(__file__).parent.parent)
  core = subprocess.run([sys.executable, "-c", program.format(modules, "pass")], capture_output=True, text=True, cwd=root, check=True)
  withKeys = subprocess.run([sys.executable, "-c", program.format(modules, "import carnelian.keys")],
                            capture_output=True, text=True, cwd=root, check=True)
  assert (core.stdout.strip(), withKeys.stdout.strip()) == ("[]", "['cryptography']")


# ---- the keys backend ------------------------------------------------------

def testAnECDSASigningKeySignsInXMLDSigForm():
  private = ec.generate_private_key(ec.SECP256R1())
  signer = LocalSigningKey(*pemPair(private), signatureAlgorithm=ecdsaSHA256)
  value = signer.sign(b"SAMLRequest=x&SigAlg=y")
  assert len(value) == 64
  private.public_key().verify(encode_dss_signature(int.from_bytes(value[:32], "big"), int.from_bytes(value[32:], "big")),
                              b"SAMLRequest=x&SigAlg=y", ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("build, message", [
  (lambda: LocalSigningKey(pemPair(signingPrivate)[0], pemPair(decryptionPrivate)[1]), "the certificate is not for this private key"),
  (lambda: LocalSigningKey(*pemPair(ec.generate_private_key(ec.SECP256R1()))), "does not suit"),
  (lambda: LocalSigningKey(*pemPair(signingPrivate), signatureAlgorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
   "is not supported"),
  (lambda: LocalDecryptionKey(*pemPair(ec.generate_private_key(ec.SECP256R1()))), "a decryption key is RSA"),
  (lambda: LocalDecryptionKey(*pemPair(rsa.generate_private_key(public_exponent=65537, key_size=1024))), "1024 bits is refused"),
])
def testKeysThatCannotServeAreRefusedAtConstruction(build, message):
  with pytest.raises(ValueError, match=message):
    build()


# ---- signed requests -------------------------------------------------------

def rawFields(address):
  query = urllib.parse.urlsplit(address).query
  return query, [part.split("=", 1)[0] for part in query.split("&")], dict(urllib.parse.parse_qsl(query))


def testWithASigningKeyTheRedirectQueryIsSigned():
  address, _ = provider().beginSignIn("state-1")
  query, names, fields = rawFields(address)
  assert names == ["SAMLRequest", "RelayState", "SigAlg", "Signature"]
  assert fields["SigAlg"] == rsaSHA256
  signedPart = query[:query.index("&Signature=")]
  signingPrivate.public_key().verify(base64.b64decode(fields["Signature"]), signedPart.encode(), padding.PKCS1v15(), hashes.SHA256())


def testWithoutASigningKeyTheRedirectQueryIsUnsigned():
  _, names, _ = rawFields(provider(withSigningKey=False).beginSignIn("state-1")[0])
  assert names == ["SAMLRequest", "RelayState"]


# ---- metadata --------------------------------------------------------------

def testServiceProviderMetadataListsItsKeysAlgorithmsAndLogout():
  names = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": dsigNS}
  document = etree.fromstring(serviceProviderMetadata(sp, acs, signingCertificate=signingKey.certificate,
                                                      encryptionCertificates=(decryptionKey.certificate, otherDecryptionKey.certificate),
                                                      encryptionPolicy=cbcPolicy, singleLogoutURL=slo))
  descriptor = document.find("md:SPSSODescriptor", names)
  assert descriptor.get("AuthnRequestsSigned") == "true"
  assert [(element.get("use"), base64.b64decode(element.find("ds:KeyInfo/ds:X509Data/ds:X509Certificate", names).text))
          for element in descriptor.findall("md:KeyDescriptor", names)] == [
    ("signing", signingKey.certificate), ("encryption", decryptionKey.certificate), ("encryption", otherDecryptionKey.certificate)]
  assert [[method.get("Algorithm") for method in element.findall("md:EncryptionMethod", names)]
          for element in descriptor.findall("md:KeyDescriptor", names)] == [
    [], *[[aes256GCM, aes128GCM, aes256CBC, aes128CBC, rsaOAEP, rsaOAEPMGF1P]] * 2]
  assert [(service.get("Binding").rsplit(":", 1)[1], service.get("Location"))
          for service in descriptor.findall("md:SingleLogoutService", names)] == [("HTTP-Redirect", slo), ("HTTP-POST", slo)]
  assert [element.tag.rsplit("}", 1)[1] for element in descriptor] == [
    "KeyDescriptor", "KeyDescriptor", "KeyDescriptor", "SingleLogoutService", "SingleLogoutService", "AssertionConsumerService"]


def identityProviderMetadata(logoutServices):
  return f"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="{dsigNS}" entityID="{idp}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificateFor(key)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>{logoutServices}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{idp}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>""".encode()


def logoutService(binding, location, responseLocation=None):
  extra = f' ResponseLocation="{responseLocation}"' if responseLocation else ""
  return f'<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:{binding}" Location="{location}"{extra}/>'


def testTheIdentityProvidersRedirectLogoutServiceIsReadFromItsMetadata():
  found = identityProviderFromMetadata(identityProviderMetadata(
    logoutService("HTTP-POST", f"{idp}/post") + logoutService("HTTP-Redirect", idpLogout, f"{idp}/answers")), idp)
  assert (found.singleLogoutURL, found.singleLogoutResponseURL) == (idpLogout, f"{idp}/answers")
  assert identityProviderFromMetadata(identityProviderMetadata(""), idp).singleLogoutURL is None
  with pytest.raises(SAMLRefused, match="2 SingleLogoutServices for the Redirect binding"):
    identityProviderFromMetadata(identityProviderMetadata(logoutService("HTTP-Redirect", idpLogout) * 2), idp)
  with pytest.raises(SAMLRefused, match="is not an https address"):
    identityProviderFromMetadata(identityProviderMetadata(logoutService("HTTP-Redirect", "http://idp.example.org/slo")), idp)


# ---- single logout ---------------------------------------------------------

def redirectQuery(document, parameter, relayState=None, signWith=key, sigAlg=rsaSHA256):
  """The identity provider's side of the Redirect binding: deflate, then sign the query (bindings 3.4.4.1)."""
  compressor = zlib.compressobj(wbits=-15)
  fields = [(parameter, base64.b64encode(compressor.compress(document.encode()) + compressor.flush()).decode())]
  if relayState is not None:
    fields.append(("RelayState", relayState))
  fields.append(("SigAlg", sigAlg))
  query = urllib.parse.urlencode(fields)
  signature = signWith.sign(query.encode(), padding.PKCS1v15(), hashes.SHA256())
  return query + "&" + urllib.parse.urlencode({"Signature": base64.b64encode(signature).decode()})


def logoutResponse(inResponseTo, destination=slo, issuer=idp, status="urn:oasis:names:tc:SAML:2.0:status:Success",
                   responseID="lr1", issued=0):
  identifier = f' ID="{responseID}"' if responseID is not None else ""
  return (f'<samlp:LogoutResponse xmlns:samlp="{samlp}" xmlns:saml="{saml}"{identifier} Version="2.0" '
          f'IssueInstant="{instant(issued)}" '
          f'Destination="{destination}" InResponseTo="{inResponseTo}"><saml:Issuer>{issuer}</saml:Issuer>'
          f'<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status></samlp:LogoutResponse>')


def logoutRequest(requestID="_idp1", destination=slo, issued=0, sessionIndexes=("s-1",)):
  indexes = "".join(f"<samlp:SessionIndex>{index}</samlp:SessionIndex>" for index in sessionIndexes)
  return (f'<samlp:LogoutRequest xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{requestID}" Version="2.0" '
          f'IssueInstant="{instant(issued)}" Destination="{destination}"><saml:Issuer>{idp}</saml:Issuer>'
          f'<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">ana</saml:NameID>{indexes}</samlp:LogoutRequest>')


def outgoing(address, parameter):
  query, _, fields = rawFields(address)
  signingPrivate.public_key().verify(base64.b64decode(fields["Signature"]), query[:query.index("&Signature=")].encode(),
                                     padding.PKCS1v15(), hashes.SHA256())
  return parse(zlib.decompress(base64.b64decode(fields[parameter]), -15)), fields


def testSignOutSendsASignedLogoutRequestForTheSession():
  address, started = provider().beginSignOut("ana", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "s-1", "back")
  assert address.startswith(idpLogout + "?")
  request, fields = outgoing(address, "SAMLRequest")
  assert (request.localName, request.attribute("ID"), request.attribute("Destination"), fields["RelayState"]) == (
    "LogoutRequest", started.requestID, idpLogout, "back")
  assert [(element.localName, element.simpleText) for element in request.elements()] == [
    ("Issuer", sp), ("NameID", "ana"), ("SessionIndex", "s-1")]


def testTheProvidersLogoutResponseIsAcceptedByEitherBinding():
  started = provider().beginSignOut("ana", None, "s-1")[1]
  assert provider().finishSignOut(started, query=redirectQuery(logoutResponse(started.requestID), "SAMLResponse", "back")) is None
  postedResponse = posted(signed(etree.fromstring(logoutResponse(started.requestID))))
  assert provider().finishSignOut(started, samlResponse=postedResponse) is None


@pytest.mark.parametrize("query, message", [
  (lambda requestID: redirectQuery(logoutResponse("_other"), "SAMLResponse"), "does not answer this logout's request"),
  (lambda requestID: redirectQuery(logoutResponse(requestID, destination="https://evil.example.org/slo"), "SAMLResponse"),
   "the LogoutResponse is for 'https://evil.example.org/slo'"),
  (lambda requestID: redirectQuery(logoutResponse(requestID, issuer="https://evil.example.org"), "SAMLResponse"),
   "issued by 'https://evil.example.org'"),
  (lambda requestID: redirectQuery(logoutResponse(requestID, status="urn:oasis:names:tc:SAML:2.0:status:Requester"),
                                   "SAMLResponse"), "answered urn:oasis:names:tc:SAML:2.0:status:Requester"),
  (lambda requestID: redirectQuery(logoutResponse(requestID), "SAMLResponse").split("&SigAlg=")[0], "is not signed"),
  (lambda requestID: redirectQuery(logoutResponse(requestID), "SAMLResponse", signWith=signingPrivate),
   "does not verify with any trusted key"),
  (lambda requestID: redirectQuery(logoutResponse(requestID), "SAMLResponse", sigAlg="http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
   "RSA with SHA-1 is refused"),
  (lambda requestID: redirectQuery(logoutResponse(requestID), "SAMLResponse").replace("&SigAlg", "&RelayState=x&SigAlg"),
   "does not verify with any trusted key"),
  (lambda requestID: "SAMLResponse=x&" + redirectQuery(logoutResponse(requestID), "SAMLResponse"), "carries SAMLResponse twice"),
  (lambda requestID: redirectQuery(logoutResponse(requestID, responseID=None), "SAMLResponse"),
   "not a SAML 2.0 LogoutResponse with an ID"),
  (lambda requestID: redirectQuery(logoutResponse(requestID, issued=-3600), "SAMLResponse"),
   "was not issued between this logout's request and now"),
  (lambda requestID: redirectQuery(logoutResponse(requestID, issued=3600), "SAMLResponse"),
   "was not issued between this logout's request and now"),
  (lambda requestID: redirectQuery(logoutResponse(requestID), "SAMLResponse", "back").replace("RelayState=", "Relay%53tate="),
   "the query spells RelayState as 'Relay%53tate'; only the literal name is read"),
  (lambda requestID: redirectQuery(logoutResponse(requestID), "SAMLResponse").replace("SigAlg=", "%53igAlg="),
   "the query spells SigAlg as '%53igAlg'"),
])
def testALogoutResponseOutsideTheProfileIsRefused(query, message):
  started = provider().beginSignOut("ana", None, "s-1")[1]
  with pytest.raises(SAMLRefused, match=message):
    provider().finishSignOut(started, query=query(started.requestID))


def testALogoutResponseIsAcceptedOnce():
  cache = ReplayCache()
  started = provider(cache=cache).beginSignOut("ana", None, "s-1")[1]
  assert provider(cache=cache).finishSignOut(started, query=redirectQuery(logoutResponse(started.requestID), "SAMLResponse")) is None
  again = redirectQuery(logoutResponse(started.requestID, responseID="lr2"), "SAMLResponse")
  with pytest.raises(SAMLRefused, match=f"'{started.requestID}' was already used"):
    provider(cache=cache).finishSignOut(started, query=again)


def testAnUnsignedPostedLogoutResponseIsRefused():
  started = provider().beginSignOut("ana", None, "s-1")[1]
  with pytest.raises(SAMLRefused, match="the posted LogoutResponse is not signed"):
    provider().finishSignOut(started, samlResponse=base64.b64encode(logoutResponse(started.requestID).encode()).decode())


def testLogoutNeedsASigningKey():
  with pytest.raises(SAMLRefused, match="single logout needs a signing key"):
    provider(withSigningKey=False).beginSignOut("ana", None, "s-1")


def testAnswerSignOutNeedsASigningKeyWhereverTheAnswerGoes():
  identityProvider = IdentityProvider(idp, f"{idp}/sso", (public,), singleLogoutURL=idpLogout,
                                      singleLogoutResponseURL=f"{idp}/answers")
  request = SignOutRequest(requestID="_idp1", nameID="ana", nameIDFormat=None, sessionIndexes=("s-1",), relayState=None)
  unsigned = ServiceProvider(sp, acs, identityProvider, clock=lambda: now, singleLogoutURL=slo)
  with pytest.raises(SAMLRefused, match="single logout needs a signing key"):
    unsigned.answerSignOut(request)
  keyed = ServiceProvider(sp, acs, identityProvider, clock=lambda: now, signingKey=signingKey, singleLogoutURL=slo)
  address = keyed.answerSignOut(request)
  assert address.startswith(f"{idp}/answers?")
  assert outgoing(address, "SAMLResponse")[0].attribute("Destination") == f"{idp}/answers"


def testTheServiceProvidersOwnXMLCarriesAnyTextXMLCan():
  nameID, sessionIndex = 'a]]>b&<"c\td\r\ne', "s]]>1"
  request, _ = outgoing(provider().beginSignOut(nameID, "urn:example:format]]>", sessionIndex)[0], "SAMLRequest")
  assert [(element.localName, element.simpleText) for element in request.elements()] == [
    ("Issuer", sp), ("NameID", nameID), ("SessionIndex", sessionIndex)]
  assert request.only(saml, "NameID").attribute("Format") == "urn:example:format]]>"
  for unwritable in ("a\x00b", "a\udcffb"):
    with pytest.raises(SAMLRefused, match="holds a character XML cannot carry"):
      provider().beginSignOut(unwritable, None, None)


def testTheProvidersLogoutRequestIsReadAndAnsweredSigned():
  cache = ReplayCache()
  request = provider(cache=cache).readSignOutRequest(query=redirectQuery(logoutRequest(), "SAMLRequest", "relay-9"))
  assert (request.requestID, request.nameID, request.nameIDFormat, request.sessionIndexes, request.relayState) == (
    "_idp1", "ana", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", ("s-1",), "relay-9")
  answer, fields = outgoing(provider().answerSignOut(request), "SAMLResponse")
  assert (answer.localName, answer.attribute("InResponseTo"), answer.attribute("Destination"), fields["RelayState"]) == (
    "LogoutResponse", "_idp1", idpLogout, "relay-9")
  assert answer.only(samlp, "Status").only(samlp, "StatusCode").attribute("Value") == "urn:oasis:names:tc:SAML:2.0:status:Success"
  with pytest.raises(SAMLRefused, match="'_idp1' was already used"):
    provider(cache=cache).readSignOutRequest(query=redirectQuery(logoutRequest(), "SAMLRequest", "relay-9"))


def testAPostedLogoutRequestIsReadWithItsRelayState():
  postedRequest = posted(signed(etree.fromstring(logoutRequest(sessionIndexes=("s-1", "s-2")))))
  request = provider().readSignOutRequest(samlRequest=postedRequest, relayState="relay-3")
  assert (request.sessionIndexes, request.relayState) == (("s-1", "s-2"), "relay-3")


@pytest.mark.parametrize("document, message", [
  (logoutRequest(issued=-3600), "was not issued just now"),
  (logoutRequest(destination="https://evil.example.org/slo"), "the LogoutRequest is for 'https://evil.example.org/slo'"),
  (logoutRequest().replace("<saml:NameID", "<saml:EncryptedID/><saml:NameID"), "EncryptedID and BaseID are refused"),
])
def testALogoutRequestOutsideTheProfileIsRefused(document, message):
  with pytest.raises(SAMLRefused, match=message):
    provider().readSignOutRequest(query=redirectQuery(document, "SAMLRequest"))


def testTheClaimedIssuerChoosesTheProviderAndIsNotTrusted():
  query = redirectQuery(logoutRequest(), "SAMLRequest", "relay-9")
  assert claimedIssuer("SAMLRequest", query=query) == idp
  assert claimedIssuer("SAMLRequest", posted=posted(signed(etree.fromstring(logoutRequest())))) == idp
  forged = logoutRequest().replace(f"<saml:Issuer>{idp}</saml:Issuer>", "<saml:Issuer>https://other.example.org/idp</saml:Issuer>")
  forgedQuery = redirectQuery(forged, "SAMLRequest")
  assert claimedIssuer("SAMLRequest", query=forgedQuery) == "https://other.example.org/idp"
  with pytest.raises(SAMLRefused, match="issued by 'https://other.example.org/idp'"):
    provider().readSignOutRequest(query=forgedQuery)


@pytest.mark.parametrize("call, message", [
  (lambda: claimedIssuer("SAMLRequest", query="SAMLResponse=abc"), "must carry a SAMLRequest"),
  (lambda: claimedIssuer("SAMLRequest", query="SAMLRequest=abc&Relay%53tate=x"), "only the literal name is read"),
  (lambda: claimedIssuer("SAMLRequest", posted=base64.b64encode(b"<a/>").decode()), "Issuer"),
  (lambda: claimedIssuer("SAMLRequest", posted=base64.b64encode(
    logoutRequest().replace(f"<saml:Issuer>{idp}</saml:Issuer>", "<saml:Issuer> </saml:Issuer>").encode()).decode()),
   "names a blank Issuer"),
])
def testAClaimedIssuerIsReadStrictly(call, message):
  with pytest.raises(SAMLRefused, match=message):
    call()


def testAClaimedIssuerNeedsExactlyOneSource():
  with pytest.raises(ValueError, match="one of them"):
    claimedIssuer("SAMLRequest")
  with pytest.raises(ValueError, match="a SAMLRequest or a SAMLResponse"):
    claimedIssuer("RelayState", query="RelayState=x")


def testARedirectMessageThatInflatesTooFarIsRefused():
  compressor = zlib.compressobj(wbits=-15)
  bomb = base64.b64encode(compressor.compress(b" " * 2_000_000) + compressor.flush()).decode()
  query = urllib.parse.urlencode([("SAMLRequest", bomb), ("SigAlg", rsaSHA256)])
  query += "&" + urllib.parse.urlencode({"Signature": base64.b64encode(key.sign(query.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()})
  with pytest.raises(SAMLRefused, match="inflates to more than 1000000 bytes"):
    provider().readSignOutRequest(query=query)


# ---- against the testbed's Keycloak ----------------------------------------

class Browser:
  """A person's browser: cookies kept, redirects reported rather than followed (the service provider is not reachable)."""

  def __init__(self, context):
    self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                              urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _Stop())

  def open(self, address, form=None):
    """(the address redirected to, None) or (None, the page)."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    try:
      with self.opener.open(urllib.request.Request(address, data=data, method="POST" if form else "GET"), timeout=20) as answer:
        return None, answer.read().decode("utf-8")
    except urllib.error.HTTPError as redirect:
      if redirect.code not in (302, 303):
        raise
      return redirect.url, None

  def signIn(self, address, userName, password):
    """The SAMLResponse Keycloak posts back, after its login form unless a session is already open."""
    _, page = self.open(address)
    posting = _Posted()
    posting.feed(page)
    if "SAMLResponse" not in posting.fields:
      login = _Form()
      login.feed(page)
      assert login.action, page[:500]
      _, page = self.open(login.action, {"username": userName, "password": password, "credentialId": ""})
      posting = _Posted()
      posting.feed(page)
    assert "SAMLResponse" in posting.fields, page[:500]
    return posting.fields["SAMLResponse"]


@pytest.fixture(scope="module")
def keyed(testbed):
  settings = testbed["saml"]["keyed"]
  fetcher = Fetcher(secureContext(testbed["certificateAuthority"]))
  metadata = fetcher.getBytes(testbed["saml"]["metadataURL"], "application/samlmetadata+xml, application/xml;q=0.9")
  identityProvider = identityProviderFromMetadata(metadata, testbed["saml"]["identityProviderEntityID"])

  def read(name):
    return Path(settings[name]).read_bytes()

  keys = {"signingKey": LocalSigningKey(read("signingKey"), read("signingCertificate")),
          "decryptionKey": LocalDecryptionKey(read("encryptionKey"), read("encryptionCertificate"))}
  return settings, keys, identityProvider, fetcher


def encryptionMethods(samlResponse):
  root = parse(base64.b64decode(samlResponse))
  assert not root.childrenNamed(saml, "Assertion")
  data = root.only(saml, "EncryptedAssertion").only(xenc, "EncryptedData")
  encryptedKey = data.only(dsigNS, "KeyInfo").only(xenc, "EncryptedKey")
  return data.only(xenc, "EncryptionMethod").attribute("Algorithm"), encryptedKey.only(xenc, "EncryptionMethod").attribute("Algorithm")


@pytest.mark.parametrize("kind, policy, methods", [
  ("encryptsGCM", EncryptionPolicy(), (aes256GCM, rsaOAEP)),
  ("encryptsCBC", cbcPolicy, (aes128CBC, rsaOAEPMGF1P)),
])
@pytest.mark.parametrize("userName", ["ana", "\u0645\u0631\u064a\u0645"])
def testKeycloaksEncryptedAssertionsAreDecrypted(testbed, keyed, kind, policy, methods, userName):
  settings, keys, identityProvider, fetcher = keyed
  serviceProvider = ServiceProvider(settings["entities"][kind], testbed["saml"]["consumerURL"], identityProvider,
                                    decryptionKeys=(otherDecryptionKey, keys["decryptionKey"]), encryptionPolicy=policy)
  address, started = serviceProvider.beginSignIn()
  expected = account(testbed, userName)
  samlResponse = Browser(fetcher.context).signIn(address, userName, expected["password"])
  assert encryptionMethods(samlResponse) == methods
  withoutKeys = ServiceProvider(settings["entities"][kind], testbed["saml"]["consumerURL"], identityProvider)
  with pytest.raises(SAMLRefused, match="encrypted assertions are refused"):
    withoutKeys.finishSignIn(started, samlResponse)
  identity = serviceProvider.finishSignIn(started, samlResponse)
  assert identity.nameID == userName
  assert sorted(identity.attributes["groups"]) == sorted(expected["groups"])


def testKeycloakAcceptsSignedRequests(testbed, keyed):
  settings, keys, identityProvider, fetcher = keyed
  serviceProvider = ServiceProvider(settings["entities"]["signsRequests"], testbed["saml"]["consumerURL"], identityProvider,
                                    signingKey=keys["signingKey"])
  address, started = serviceProvider.beginSignIn("state-7")
  assert "&Signature=" in address
  identity = serviceProvider.finishSignIn(started, Browser(fetcher.context).signIn(address, "ana", account(testbed, "ana")["password"]))
  assert identity.nameID == "ana"


def testSingleLogoutThroughKeycloak(testbed, keyed):
  settings, keys, identityProvider, fetcher = keyed
  assert identityProvider.singleLogoutURL is not None
  first, second = (ServiceProvider(settings["entities"][kind], testbed["saml"]["consumerURL"], identityProvider,
                                   signingKey=keys["signingKey"], singleLogoutURL=settings["singleLogoutURLs"][kind])
                   for kind in ("logsOut", "logsOutToo"))
  browser = Browser(fetcher.context)
  password = account(testbed, "jose")["password"]
  address, started = first.beginSignIn()
  identity = first.finishSignIn(started, browser.signIn(address, "jose", password))
  address, started = second.beginSignIn()
  secondIdentity = second.finishSignIn(started, browser.signIn(address, "jose", password))
  address, leaving = first.beginSignOut(identity.nameID, identity.nameIDFormat, identity.sessionIndex, "after-logout")
  location, page = browser.open(address)
  assert location is not None and location.startswith(settings["singleLogoutURLs"]["logsOutToo"] + "?"), page
  request = second.readSignOutRequest(query=urllib.parse.urlsplit(location).query)
  assert (request.nameID, request.sessionIndexes) == ("jose", (secondIdentity.sessionIndex,))
  location, page = browser.open(second.answerSignOut(request))
  assert location is not None and location.startswith(settings["singleLogoutURLs"]["logsOut"] + "?"), page
  query = urllib.parse.urlsplit(location).query
  first.finishSignOut(leaving, query=query)
  assert dict(urllib.parse.parse_qsl(query))["RelayState"] == "after-logout"
  _, page = browser.open(first.beginSignIn()[0])
  assert page is not None and 'id="kc-form-login"' in page
