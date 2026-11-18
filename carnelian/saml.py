# SPDX-License-Identifier: MIT
"""A SAML 2.0 service provider: the Web Browser SSO profile, Redirect binding out, POST binding back, and single logout.

The identity provider is known from its metadata: its entity ID, its single sign-on
address for the Redirect binding, its single logout address when it has one, and its
signing certificates. Sign-in has two halves, as for OpenID Connect: `beginSignIn` gives the
address to send the person to and a Pending record to keep server-side; `finishSignIn` takes
that record and the SAMLResponse posted back, refused unread when longer than
`maximumResponseLength` characters. The response or its assertion must carry a signature by
a trusted key (decided by `xmldsig.verifyEnveloped`, which returns the element it verified,
and only verified elements are read). Then: destination, InResponseTo, issuer, status, one
assertion, its validity window, conditions holding only audience restrictions (OneTimeUse,
ProxyRestriction and any other condition are refused by name) with this service provider in
every one, a bearer subject confirmation whose Recipient is this assertion consumer address
and whose InResponseTo is this request (its Address is not checked), one AuthnStatement
whose SessionNotOnOrAfter, when given, has not passed, and an assertion ID not seen before
from this issuer. NameID, Issuer, Audience and AttributeValue must be text only (an
AttributeValue may also be one NameID, the form eduPersonTargetedID takes); the NameID must
not be blank.

Replay is kept by a ReplayStore: the default ReplayCache holds one process's memory, so a
deployment with several processes or hosts gives every ServiceProvider the same shared
store, whose `admit` is an atomic claim.

Operations with a private key go through the interface of `carnelian.keys` (the `keys`
extra, or a key service of the application's): this module never imports it. With
decryption keys, an EncryptedAssertion is decrypted under an EncryptionPolicy that the
configuration chooses and the document never does: RSA PKCS #1 v1.5 key transport is always
refused, RSA-OAEP and AES-GCM are the default, and AES-CBC is decrypted only when the policy
allows it and the Response's own signature has been verified first. Every failure to
decrypt is one refusal, whatever went wrong: every key unwraps and decrypts the content, a
failed unwrap with a random content key. The decrypted assertion is parsed with the same
limits and goes through every check above; unless it carries its own signature, it must
declare every namespace prefix it uses, since the Response's exclusive canonical form need
not cover a declaration outside it. Without decryption keys an EncryptedAssertion is
refused by name. With a signing key, requests and logout messages are signed by the
Redirect binding's query signature (SAML bindings 3.4.4.1); without one, requests go
unsigned and logout is refused by name. A LogoutResponse needs an ID and an IssueInstant
between its request and now, and answers its request once: the request's ID is claimed in
the ReplayStore under this service provider's entity ID. The Redirect binding's parameters
are read by their literal names; an encoded spelling of one is refused. An identity
provider's address with a fragment or a parameter of the binding is refused.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import re
import secrets
import threading
import time
import urllib.parse
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from carnelian.der import publicKeyFromCertificate
from carnelian.signatures import ECPublicKey, RSAPublicKey
from carnelian.xmldsig import SignatureRefused, dsig, verifyEnveloped, verifySignatureValue
from carnelian.xmlTree import Element, Text, XMLRefused, parse

if TYPE_CHECKING:
  from carnelian.keys import DecryptionKey, SigningKey

__all__ = ["SAMLRefused", "IdentityProvider", "identityProviderFromMetadata", "Pending", "SAMLIdentity",
           "ReplayStore", "ReplayCache", "EncryptionPolicy", "SignOutRequest", "ServiceProvider",
           "serviceProviderMetadata", "rsaOAEPMGF1P", "rsaOAEP", "aes128GCM", "aes256GCM", "aes128CBC", "aes256CBC"]

assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
protocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"
metadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
uiNamespace = "urn:oasis:names:tc:SAML:metadata:ui"
entityAttributeNamespace = "urn:oasis:names:tc:SAML:metadata:attribute"
entityCategoryName = "http://macedir.org/entity-category"
redirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
postBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
successStatus = "urn:oasis:names:tc:SAML:2.0:status:Success"
bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
maximumResponseLength = 1_400_000
maximumInflatedBytes = 1_000_000

xmlEncryption = "http://www.w3.org/2001/04/xmlenc#"
xmlEncryption11 = "http://www.w3.org/2009/xmlenc11#"
rsaPKCS1v15Transport = xmlEncryption + "rsa-1_5"
rsaOAEPMGF1P = xmlEncryption + "rsa-oaep-mgf1p"
rsaOAEP = xmlEncryption11 + "rsa-oaep"
aes128GCM = xmlEncryption11 + "aes128-gcm"
aes256GCM = xmlEncryption11 + "aes256-gcm"
aes128CBC = xmlEncryption + "aes128-cbc"
aes256CBC = xmlEncryption + "aes256-cbc"
encryptedElementType = xmlEncryption + "Element"
encryptedKeyType = xmlEncryption + "EncryptedKey"
sha1Digest = "http://www.w3.org/2000/09/xmldsig#sha1"
_oaepDigests = {
  sha1Digest: "sha1",
  "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
  "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
  "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}
_maskFunctions = {xmlEncryption11 + f"mgf1{name}": name for name in ("sha1", "sha256", "sha384", "sha512")}
_keyTransports = (rsaOAEP, rsaOAEPMGF1P)
_contentAlgorithms = {aes256GCM: ("aes256-gcm", 32), aes128GCM: ("aes128-gcm", 16), aes256CBC: ("aes256-cbc", 32),
                      aes128CBC: ("aes128-cbc", 16)}
_cbcAlgorithms = (aes128CBC, aes256CBC)
_undecryptable = "the encrypted assertion does not decrypt with this service provider's keys"
_bindingParameters = frozenset({"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"})
_notXMLCharacter = re.compile("[^\t\n\r\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


class SAMLRefused(ValueError):
  """A SAML sign-in or logout that did not complete, with why."""


@dataclass(frozen=True)
class IdentityProvider:
  entityID: str
  singleSignOnURL: str
  signingKeys: tuple[RSAPublicKey | ECPublicKey, ...]
  singleLogoutURL: str | None = None
  singleLogoutResponseURL: str | None = None

  def __post_init__(self) -> None:
    for address in (self.singleSignOnURL, self.singleLogoutURL, self.singleLogoutResponseURL):
      if address is not None:
        _checkEndpoint(address)


def _checkEndpoint(address: str) -> None:
  """An identity provider's address, to which the Redirect binding adds its own query."""
  if "#" in address:
    raise SAMLRefused(f"the identity provider's address {address!r} carries a fragment")
  query = urllib.parse.urlsplit(address).query
  names = {urllib.parse.unquote_plus(part.partition("=")[0]) for part in query.split("&") if part}
  if names & _bindingParameters:
    raise SAMLRefused(f"the identity provider's address {address!r} already carries {sorted(names & _bindingParameters)}")


def identityProviderFromMetadata(metadata: bytes, entityID: str | None = None) -> IdentityProvider:
  """The identity provider an EntityDescriptor describes; its entity ID must be `entityID` when given."""
  try:
    root = parse(metadata)
  except XMLRefused as error:
    raise SAMLRefused(f"the metadata is refused: {error}") from None
  return identityProviderFromDescriptor(root, entityID)


def identityProviderFromDescriptor(root: Element, entityID: str | None = None) -> IdentityProvider:
  if not root.isA(metadataNamespace, "EntityDescriptor"):
    raise SAMLRefused("the metadata is not an EntityDescriptor")
  try:
    found = root.required("entityID")
  except XMLRefused as error:
    raise SAMLRefused(f"the metadata is refused: {error}") from None
  if entityID is not None and found != entityID:
    raise SAMLRefused(f"the metadata is for {found!r}, not {entityID!r}")
  try:
    descriptor = root.only(metadataNamespace, "IDPSSODescriptor")
    if "urn:oasis:names:tc:SAML:2.0:protocol" not in (descriptor.attribute("protocolSupportEnumeration") or "").split():
      raise SAMLRefused("the identity provider does not support SAML 2.0")
    services = [service.required("Location") for service in descriptor.childrenNamed(metadataNamespace, "SingleSignOnService")
                if service.attribute("Binding") == redirectBinding]
    singleSignOnURL = services[0] if len(services) == 1 else None
    if singleSignOnURL is None or not singleSignOnURL.startswith("https://"):
      raise SAMLRefused(f"the metadata needs one https SingleSignOnService for the Redirect binding, got {services}")
    logoutServices = [service for service in descriptor.childrenNamed(metadataNamespace, "SingleLogoutService")
                      if service.attribute("Binding") == redirectBinding]
    if len(logoutServices) > 1:
      raise SAMLRefused(f"the metadata has {len(logoutServices)} SingleLogoutServices for the Redirect binding; it may have one")
    singleLogoutURL = logoutServices[0].required("Location") if logoutServices else None
    singleLogoutResponseURL = logoutServices[0].attribute("ResponseLocation") if logoutServices else None
    for address in (singleLogoutURL, singleLogoutResponseURL):
      if address is not None and not address.startswith("https://"):
        raise SAMLRefused(f"the metadata's SingleLogoutService {address!r} is not an https address")
    keys = []
    for keyDescriptor in descriptor.childrenNamed(metadataNamespace, "KeyDescriptor"):
      if keyDescriptor.attribute("use") not in (None, "signing"):
        continue
      for certificate in keyDescriptor.only(dsig, "KeyInfo").only(dsig, "X509Data").childrenNamed(dsig, "X509Certificate"):
        keys.append(publicKeyFromCertificate(base64.b64decode("".join(certificate.simpleText.split()), validate=True)))
  except SAMLRefused:
    raise
  except ValueError as error:
    # XMLRefused, DERError, SignatureError and the base64 errors are all ValueErrors.
    raise SAMLRefused(f"the metadata is refused: {error}") from None
  if not keys:
    raise SAMLRefused("the metadata names no signing certificate")
  return IdentityProvider(entityID=found, singleSignOnURL=singleSignOnURL, signingKeys=tuple(keys),
                          singleLogoutURL=singleLogoutURL, singleLogoutResponseURL=singleLogoutResponseURL)


@dataclass(frozen=True)
class Pending:
  requestID: str
  startedAt: float


@dataclass(frozen=True)
class SAMLIdentity:
  issuer: str
  nameID: str
  nameIDFormat: str | None
  sessionIndex: str | None
  attributes: dict[str, tuple[str, ...]] = field(repr=False)
  sessionNotOnOrAfter: float | None = None


@dataclass(frozen=True)
class SignOutRequest:
  """A logout the identity provider asks for: end the sessions of this NameID (those with these indexes, when
  given), then answer with `ServiceProvider.answerSignOut`."""
  requestID: str
  nameID: str
  nameIDFormat: str | None
  sessionIndexes: tuple[str, ...]
  relayState: str | None


@dataclass(frozen=True)
class EncryptionPolicy:
  """The XML Encryption algorithms an encrypted assertion may use, chosen by configuration and never by the document.

  The default is RSA-OAEP key transport (either URI, any listed digest) and AES-GCM content. Add aes128CBC or
  aes256CBC to `contentAlgorithms` only for a provider that cannot use GCM; CBC is then decrypted only when the
  Response's own signature has been verified first. RSA PKCS #1 v1.5 key transport cannot be allowed."""
  keyTransports: frozenset[str] = frozenset(_keyTransports)
  oaepDigests: frozenset[str] = frozenset(_oaepDigests)
  maskDigests: frozenset[str] = frozenset(_maskFunctions)
  contentAlgorithms: frozenset[str] = frozenset({aes128GCM, aes256GCM})

  def __post_init__(self) -> None:
    if rsaPKCS1v15Transport in self.keyTransports:
      raise ValueError("RSA PKCS #1 v1.5 key transport (xmlenc#rsa-1_5) is always refused: Bleichenbacher's attack")
    for chosen, known, what in ((self.keyTransports, _keyTransports, "key transport"),
                                (self.oaepDigests, _oaepDigests, "OAEP digest"),
                                (self.maskDigests, _maskFunctions, "mask generation function"),
                                (self.contentAlgorithms, _contentAlgorithms, "content encryption")):
      if not chosen:
        raise ValueError(f"the encryption policy allows no {what}")
      unknown = set(chosen) - set(known)
      if unknown:
        raise ValueError(f"{what} {sorted(unknown)} is not supported; {sorted(known)}")

  def metadataAlgorithms(self) -> list[str]:
    """The allowed algorithms in order of preference, as md:EncryptionMethod lists them."""
    return ([algorithm for algorithm in _contentAlgorithms if algorithm in self.contentAlgorithms]
            + [algorithm for algorithm in _keyTransports if algorithm in self.keyTransports])


class ReplayStore(Protocol):
  """Where assertion and LogoutRequest IDs are remembered, per issuer, and the IDs of this service provider's own
  answered LogoutRequests under its own entity ID. Behind several processes, one shared store (a database
  table with (issuer, assertion ID) as its unique key, say) so an assertion used on one process is refused on all."""

  def admit(self, issuer: str, assertionID: str, until: float, now: float) -> None:
    """Claim (issuer, assertionID) until `until`, atomically: of concurrent claims of one pair all but one
    raise SAMLRefused, as does any claim while an earlier one has not expired."""


class ReplayCache:
  """Assertion IDs seen per issuer in this process, kept until their assertion could no longer be accepted anyway."""

  def __init__(self) -> None:
    self._seen: dict[tuple[str, str], float] = {}
    self._lock = threading.Lock()

  def admit(self, issuer: str, assertionID: str, until: float, now: float) -> None:
    with self._lock:
      self._seen = {key: expiry for key, expiry in self._seen.items() if expiry > now}
      if (issuer, assertionID) in self._seen:
        raise SAMLRefused(f"assertion {assertionID!r} was already used")
      self._seen[(issuer, assertionID)] = until


_instant = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$")


def _time(text: str | None, what: str) -> float:
  match = _instant.match(text or "")
  if not match:
    raise SAMLRefused(f"{what} {text!r} is not a UTC dateTime")
  year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
  try:
    whole = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.UTC).timestamp()
  except ValueError:
    raise SAMLRefused(f"{what} {text!r} is not a valid instant") from None
  return whole + (float(match.group(7)) if match.group(7) else 0.0)


def _base64(text: str, what: str) -> bytes:
  try:
    return base64.b64decode("".join(text.split()), validate=True)
  except ValueError:
    raise SAMLRefused(f"{what} is not base64") from None


def _inflated(data: bytes) -> bytes:
  inflater = zlib.decompressobj(wbits=-15)
  try:
    document = inflater.decompress(data, maximumInflatedBytes)
  except zlib.error:
    raise SAMLRefused("the Redirect binding's message is not DEFLATE data") from None
  if inflater.unconsumed_tail:
    raise SAMLRefused(f"the Redirect binding's message inflates to more than {maximumInflatedBytes} bytes")
  if not inflater.eof or inflater.unused_data:
    raise SAMLRefused("the Redirect binding's message is not one whole DEFLATE stream")
  return document


class ServiceProvider:
  def __init__(self, entityID: str, assertionConsumerURL: str, identityProvider: IdentityProvider,
               leewaySeconds: int = 60, pendingSeconds: int = 600, replayCache: ReplayStore | None = None,
               clock: Callable[[], float] = time.time, signingKey: SigningKey | None = None,
               decryptionKeys: tuple[DecryptionKey, ...] = (), encryptionPolicy: EncryptionPolicy = EncryptionPolicy(),
               singleLogoutURL: str | None = None) -> None:
    if singleLogoutURL is not None and not singleLogoutURL.startswith("https://"):
      raise ValueError(f"{singleLogoutURL} must be an https address")
    if signingKey is not None:
      signingPublic = publicKeyFromCertificate(signingKey.certificate)
      if any(publicKeyFromCertificate(key.certificate) == signingPublic for key in decryptionKeys):
        raise ValueError("the signing key is also a decryption key; XML Encryption needs a key pair of its own")
    self.entityID = entityID
    self.assertionConsumerURL = assertionConsumerURL
    self.identityProvider = identityProvider
    self.leewaySeconds = leewaySeconds
    self.pendingSeconds = pendingSeconds
    self.replayCache: ReplayStore = replayCache if replayCache is not None else ReplayCache()
    self.clock = clock
    self.signingKey = signingKey
    self.decryptionKeys = decryptionKeys
    self.encryptionPolicy = encryptionPolicy
    self.singleLogoutURL = singleLogoutURL

  def _newMessage(self) -> tuple[Pending, str]:
    """A new message's ID and time, as the Pending record of its answer, and its IssueInstant."""
    pending = Pending(requestID="_" + secrets.token_hex(20), startedAt=self.clock())
    return pending, datetime.datetime.fromtimestamp(pending.startedAt, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

  def _redirect(self, location: str, parameter: str, message: str, relayState: str | None) -> str:
    """The Redirect binding's address for a message, its query signed (bindings 3.4.4.1) when there is a signing key."""
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(message.encode("utf-8")) + compressor.flush()
    fields = [(parameter, base64.b64encode(deflated).decode("ascii"))]
    if relayState is not None:
      fields.append(("RelayState", relayState))
    if self.signingKey is not None:
      fields.append(("SigAlg", self.signingKey.signatureAlgorithm))
    query = urllib.parse.urlencode(fields)
    if self.signingKey is not None:
      signature = base64.b64encode(self.signingKey.sign(query.encode("ascii"))).decode("ascii")
      query += "&" + urllib.parse.urlencode({"Signature": signature})
    return f"{location}{'&' if '?' in location else '?'}{query}"

  def beginSignIn(self, relayState: str | None = None) -> tuple[str, Pending]:
    pending, instant = self._newMessage()
    request = (
      f'<samlp:AuthnRequest xmlns:samlp="{protocolNamespace}" xmlns:saml="{assertionNamespace}" ID="{pending.requestID}" '
      f'Version="2.0" IssueInstant="{instant}" Destination="{_attribute(self.identityProvider.singleSignOnURL)}" '
      f'AssertionConsumerServiceURL="{_attribute(self.assertionConsumerURL)}" ProtocolBinding="{postBinding}">'
      f"<saml:Issuer>{_attribute(self.entityID)}</saml:Issuer></samlp:AuthnRequest>"
    )
    return self._redirect(self.identityProvider.singleSignOnURL, "SAMLRequest", request, relayState), pending

  def finishSignIn(self, pending: Pending, samlResponse: str) -> SAMLIdentity:
    now = self.clock()
    if now - pending.startedAt > self.pendingSeconds:
      raise SAMLRefused("the sign-in took too long; start again")
    if len(samlResponse) > maximumResponseLength:
      raise SAMLRefused(f"the SAMLResponse is longer than {maximumResponseLength} characters")
    document = _base64(samlResponse, "the SAMLResponse")
    try:
      return self._read(parse(document), pending, now)
    except (XMLRefused, SignatureRefused) as error:
      raise SAMLRefused(str(error)) from None

  def _issuer(self, element: Element, required: bool) -> None:
    issuer = element.only(assertionNamespace, "Issuer") if required else element.optional(assertionNamespace, "Issuer")
    if issuer is not None and issuer.simpleText != self.identityProvider.entityID:
      raise SAMLRefused(f"issued by {issuer.simpleText!r}, not {self.identityProvider.entityID!r}")

  @staticmethod
  def _status(message: Element) -> None:
    status = message.only(protocolNamespace, "Status").only(protocolNamespace, "StatusCode")
    if status.attribute("Value") != successStatus:
      text = message.only(protocolNamespace, "Status").optional(protocolNamespace, "StatusMessage")
      raise SAMLRefused(f"the identity provider answered {status.attribute('Value')}: {text.text if text else ''}".rstrip(": "))

  def _read(self, response: Element, pending: Pending, now: float) -> SAMLIdentity:
    if not response.isA(protocolNamespace, "Response") or response.attribute("Version") != "2.0":
      raise SAMLRefused("not a SAML 2.0 Response")
    if response.attribute("Destination") != self.assertionConsumerURL:
      raise SAMLRefused(f"the response is for {response.attribute('Destination')!r}, not {self.assertionConsumerURL!r}")
    if response.attribute("InResponseTo") != pending.requestID:
      raise SAMLRefused("the response does not answer this sign-in's request")
    self._issuer(response, required=False)
    self._status(response)
    if response.childrenNamed(assertionNamespace, "EncryptedAssertion") and not self.decryptionKeys:
      raise SAMLRefused("encrypted assertions are refused: this service provider has no decryption key (the keys extra)")
    keys = list(self.identityProvider.signingKeys)
    responseSigned = bool(response.childrenNamed(dsig, "Signature"))
    if responseSigned:
      response = verifyEnveloped(response, keys)
    encrypted = response.childrenNamed(assertionNamespace, "EncryptedAssertion")
    if encrypted:
      if len(encrypted) != 1 or response.childrenNamed(assertionNamespace, "Assertion"):
        raise SAMLRefused("the response must carry exactly one assertion, plain or encrypted")
      assertion = self._decrypted(encrypted[0], responseSigned)
    else:
      assertion = response.only(assertionNamespace, "Assertion")
    if assertion.childrenNamed(dsig, "Signature"):
      assertion = verifyEnveloped(assertion, keys)
    elif not responseSigned:
      raise SAMLRefused("neither the response nor its assertion is signed")
    return self._readAssertion(assertion, pending, now)

  def _decrypted(self, container: Element, responseVerified: bool) -> Element:
    """The Assertion an EncryptedAssertion holds, decrypted under this provider's policy with its keys."""
    policy = self.encryptionPolicy
    found = container.childrenNamed(xmlEncryption, "EncryptedData")
    if len(found) != 1:
      raise SAMLRefused(f"the EncryptedAssertion holds {len(found)} EncryptedData; exactly one is accepted")
    encryptedData = found[0]
    if encryptedData.attribute("Type") != encryptedElementType:
      raise SAMLRefused(f"EncryptedData of Type {encryptedData.attribute('Type')!r} is refused; only {encryptedElementType}")
    content = encryptedData.only(xmlEncryption, "EncryptionMethod").required("Algorithm")
    if content not in _contentAlgorithms:
      raise SAMLRefused(f"content encryption {content} is not supported")
    if content not in policy.contentAlgorithms:
      raise SAMLRefused(f"content encryption {content} is not allowed by this provider's encryption policy")
    if content in _cbcAlgorithms and not responseVerified:
      raise SAMLRefused("AES-CBC content is decrypted only under a verified signature on the Response itself; "
                        "a signature inside the ciphertext comes too late")
    encryptedKey = self._encryptedKey(container, encryptedData)
    method = encryptedKey.only(xmlEncryption, "EncryptionMethod")
    transport = method.required("Algorithm")
    if transport == rsaPKCS1v15Transport:
      raise SAMLRefused("RSA PKCS #1 v1.5 key transport (xmlenc#rsa-1_5) is always refused")
    if transport not in _keyTransports:
      raise SAMLRefused(f"key transport {transport} is not supported")
    if transport not in policy.keyTransports:
      raise SAMLRefused(f"key transport {transport} is not allowed by this provider's encryption policy")
    if method.childrenNamed(xmlEncryption, "OAEPparams"):
      raise SAMLRefused("OAEPparams (an OAEP label) are refused")
    digestMethod = method.optional(dsig, "DigestMethod")
    digest = digestMethod.required("Algorithm") if digestMethod is not None else sha1Digest
    if digest not in _oaepDigests or digest not in policy.oaepDigests:
      raise SAMLRefused(f"OAEP digest {digest} is not allowed by this provider's encryption policy")
    maskFunction = method.optional(xmlEncryption11, "MGF")
    if maskFunction is not None and transport == rsaOAEPMGF1P:
      raise SAMLRefused("rsa-oaep-mgf1p fixes MGF1 with SHA-1; an MGF element is refused")
    mask = maskFunction.required("Algorithm") if maskFunction is not None else xmlEncryption11 + "mgf1sha1"
    if mask not in _maskFunctions or mask not in policy.maskDigests:
      raise SAMLRefused(f"mask generation function {mask} is not allowed by this provider's encryption policy")
    wrappedKey, cipherData = _cipherValue(encryptedKey), _cipherValue(encryptedData)
    algorithm, keyLength = _contentAlgorithms[content]
    plaintexts = []
    for key in self.decryptionKeys:
      try:
        contentKey, unwrapped = key.unwrapKey(wrappedKey, _oaepDigests[digest], _maskFunctions[mask]), True
      except ValueError:
        # A random key of the right length keeps a failed unwrap on the same path as content that fails its tag.
        contentKey, unwrapped = secrets.token_bytes(keyLength), False
      try:
        plaintext = key.decryptContent(algorithm, contentKey, cipherData)
      except ValueError:
        continue
      if unwrapped:
        plaintexts.append(plaintext)
    if not plaintexts:
      raise SAMLRefused(_undecryptable)
    try:
      assertion = _inContext(plaintexts[0], container)
    except ValueError:
      raise SAMLRefused(_undecryptable) from None
    inherited = _inheritedPrefixes(assertion)
    if inherited and not assertion.childrenNamed(dsig, "Signature"):
      raise SAMLRefused(f"the decrypted assertion uses namespace prefixes {sorted(inherited)} declared outside it, where "
                        "the Response's signature need not cover them; without a signature of its own it must declare "
                        "every prefix it uses")
    return assertion

  @staticmethod
  def _encryptedKey(container: Element, encryptedData: Element) -> Element:
    """The one EncryptedKey: in the EncryptedData's KeyInfo, or beside it and named there by a RetrievalMethod."""
    keyInfo = encryptedData.optional(dsig, "KeyInfo")
    inside = keyInfo.childrenNamed(xmlEncryption, "EncryptedKey") if keyInfo is not None else []
    retrievals = keyInfo.childrenNamed(dsig, "RetrievalMethod") if keyInfo is not None else []
    beside = container.childrenNamed(xmlEncryption, "EncryptedKey")
    if len(inside) + len(beside) != 1:
      raise SAMLRefused(f"{len(inside) + len(beside)} EncryptedKeys go with the EncryptedData; exactly one is accepted")
    if inside:
      if retrievals:
        raise SAMLRefused("a RetrievalMethod beside an EncryptedKey in the KeyInfo is refused")
      return inside[0]
    if len(retrievals) != 1:
      raise SAMLRefused("an EncryptedKey beside the EncryptedData must be named by one RetrievalMethod in its KeyInfo")
    retrieval, encryptedKey = retrievals[0], beside[0]
    if retrieval.attribute("Type") != encryptedKeyType or retrieval.elements():
      raise SAMLRefused(f"a RetrievalMethod of Type {encryptedKeyType} and without transforms is the only one accepted")
    identifier = encryptedKey.attribute("Id")
    if not identifier or retrieval.attribute("URI") != f"#{identifier}":
      raise SAMLRefused("the RetrievalMethod does not name the EncryptedKey beside the EncryptedData")
    return encryptedKey

  def _readAssertion(self, assertion: Element, pending: Pending, now: float) -> SAMLIdentity:
    leeway = self.leewaySeconds
    assertionID = assertion.attribute("ID")
    if not assertion.isA(assertionNamespace, "Assertion") or assertion.attribute("Version") != "2.0" or not assertionID:
      raise SAMLRefused("not a SAML 2.0 Assertion with an ID")
    self._issuer(assertion, required=True)
    conditions = assertion.only(assertionNamespace, "Conditions")
    if conditions.attribute("NotBefore") is not None and _time(conditions.attribute("NotBefore"), "NotBefore") > now + leeway:
      raise SAMLRefused("the assertion is not valid yet")
    notOnOrAfter = _time(conditions.attribute("NotOnOrAfter"), "Conditions NotOnOrAfter")
    if notOnOrAfter <= now - leeway:
      raise SAMLRefused("the assertion has expired")
    restrictions = conditions.elements()
    for condition in restrictions:
      if not condition.isA(assertionNamespace, "AudienceRestriction"):
        raise SAMLRefused(f"the condition <{condition.localName}> is not supported, so the assertion is refused")
    if not restrictions:
      raise SAMLRefused("the assertion has no audience restriction")
    for restriction in restrictions:
      if self.entityID not in [audience.simpleText for audience in restriction.childrenNamed(assertionNamespace, "Audience")]:
        raise SAMLRefused(f"the assertion is not for {self.entityID!r}")
    subject = assertion.only(assertionNamespace, "Subject")
    nameID = subject.only(assertionNamespace, "NameID")
    if not nameID.simpleText.strip():
      raise SAMLRefused("the assertion's NameID is blank")
    confirmations = [confirmation for confirmation in subject.childrenNamed(assertionNamespace, "SubjectConfirmation")
                     if confirmation.attribute("Method") == bearer]
    if not confirmations:
      raise SAMLRefused("the assertion has no bearer subject confirmation")
    if not any(self._confirms(confirmation, pending, now) for confirmation in confirmations):
      raise SAMLRefused("no subject confirmation is for this sign-in, this address and now")
    statements = assertion.childrenNamed(assertionNamespace, "AuthnStatement")
    if len(statements) != 1:
      raise SAMLRefused(f"the assertion has {len(statements)} AuthnStatements; this profile needs exactly one")
    statement = statements[0]
    sessionEnd = statement.attribute("SessionNotOnOrAfter")
    sessionNotOnOrAfter = _time(sessionEnd, "SessionNotOnOrAfter") if sessionEnd is not None else None
    if sessionNotOnOrAfter is not None and sessionNotOnOrAfter <= now - leeway:
      raise SAMLRefused("the identity provider's session has already ended")
    attributes: dict[str, tuple[str, ...]] = {}
    for attributeStatement in assertion.childrenNamed(assertionNamespace, "AttributeStatement"):
      for attribute in attributeStatement.childrenNamed(assertionNamespace, "Attribute"):
        name = attribute.required("Name")
        values = tuple(_attributeValue(value) for value in attribute.childrenNamed(assertionNamespace, "AttributeValue"))
        attributes[name] = attributes.get(name, ()) + values
    self.replayCache.admit(self.identityProvider.entityID, assertionID, notOnOrAfter + leeway, now)
    return SAMLIdentity(
      issuer=self.identityProvider.entityID, nameID=nameID.simpleText, nameIDFormat=nameID.attribute("Format"),
      sessionIndex=statement.attribute("SessionIndex"), attributes=attributes, sessionNotOnOrAfter=sessionNotOnOrAfter,
    )

  def _confirms(self, confirmation: Element, pending: Pending, now: float) -> bool:
    data = confirmation.only(assertionNamespace, "SubjectConfirmationData")
    if data.attribute("Recipient") != self.assertionConsumerURL or data.attribute("InResponseTo") != pending.requestID:
      return False
    if data.attribute("NotBefore") is not None:
      return False
    return _time(data.attribute("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter") > now - self.leewaySeconds

  def _logoutAddress(self) -> str:
    if self.signingKey is None:
      raise SAMLRefused("single logout needs a signing key (the keys extra); this service provider has none")
    if self.identityProvider.singleLogoutURL is None:
      raise SAMLRefused("the identity provider's metadata names no SingleLogoutService for the Redirect binding")
    if self.singleLogoutURL is None:
      raise SAMLRefused("this service provider has no singleLogoutURL to receive logout messages")
    return self.identityProvider.singleLogoutURL

  def beginSignOut(self, nameID: str, nameIDFormat: str | None, sessionIndex: str | None,
                   relayState: str | None = None) -> tuple[str, Pending]:
    """The address that asks the identity provider to end this person's session, and the record to keep for the answer."""
    location = self._logoutAddress()
    pending, instant = self._newMessage()
    nameFormat = f' Format="{_attribute(nameIDFormat)}"' if nameIDFormat is not None else ""
    index = f"<samlp:SessionIndex>{_attribute(sessionIndex)}</samlp:SessionIndex>" if sessionIndex is not None else ""
    request = (
      f'<samlp:LogoutRequest xmlns:samlp="{protocolNamespace}" xmlns:saml="{assertionNamespace}" ID="{pending.requestID}" '
      f'Version="2.0" IssueInstant="{instant}" Destination="{_attribute(location)}">'
      f"<saml:Issuer>{_attribute(self.entityID)}</saml:Issuer>"
      f"<saml:NameID{nameFormat}>{_attribute(nameID)}</saml:NameID>{index}</samlp:LogoutRequest>"
    )
    return self._redirect(location, "SAMLRequest", request, relayState), pending

  def finishSignOut(self, pending: Pending, query: str | None = None, samlResponse: str | None = None) -> None:
    """Check the identity provider's LogoutResponse to `beginSignOut`: give the raw query string of the Redirect
    binding exactly as received, or the SAMLResponse posted by the POST binding."""
    self._logoutAddress()
    now = self.clock()
    if now - pending.startedAt > self.pendingSeconds:
      raise SAMLRefused("the logout took too long; start again")
    try:
      response, _ = self._incoming("SAMLResponse", query, samlResponse, None)
      if (not response.isA(protocolNamespace, "LogoutResponse") or response.attribute("Version") != "2.0"
          or not response.attribute("ID")):
        raise SAMLRefused("not a SAML 2.0 LogoutResponse with an ID")
      self._destination(response)
      if response.attribute("InResponseTo") != pending.requestID:
        raise SAMLRefused("the LogoutResponse does not answer this logout's request")
      issued = _time(response.attribute("IssueInstant"), "IssueInstant")
      if not pending.startedAt - self.leewaySeconds <= issued <= now + self.leewaySeconds:
        raise SAMLRefused("the LogoutResponse was not issued between this logout's request and now")
      self._issuer(response, required=True)
      self._status(response)
      self.replayCache.admit(self.entityID, pending.requestID, pending.startedAt + self.pendingSeconds + self.leewaySeconds, now)
    except (XMLRefused, SignatureRefused) as error:
      raise SAMLRefused(str(error)) from None

  def readSignOutRequest(self, query: str | None = None, samlRequest: str | None = None,
                         relayState: str | None = None) -> SignOutRequest:
    """The identity provider's LogoutRequest: give the raw query string of the Redirect binding exactly as received,
    or the SAMLRequest posted by the POST binding with its RelayState."""
    self._logoutAddress()
    now = self.clock()
    try:
      request, relayState = self._incoming("SAMLRequest", query, samlRequest, relayState)
      requestID = request.attribute("ID")
      if not request.isA(protocolNamespace, "LogoutRequest") or request.attribute("Version") != "2.0" or not requestID:
        raise SAMLRefused("not a SAML 2.0 LogoutRequest with an ID")
      self._destination(request)
      self._issuer(request, required=True)
      issued = _time(request.attribute("IssueInstant"), "IssueInstant")
      if not now - self.pendingSeconds - self.leewaySeconds <= issued <= now + self.leewaySeconds:
        raise SAMLRefused("the LogoutRequest was not issued just now")
      notOnOrAfter = request.attribute("NotOnOrAfter")
      if notOnOrAfter is not None and _time(notOnOrAfter, "NotOnOrAfter") <= now - self.leewaySeconds:
        raise SAMLRefused("the LogoutRequest has expired")
      if request.childrenNamed(assertionNamespace, "EncryptedID") or request.childrenNamed(assertionNamespace, "BaseID"):
        raise SAMLRefused("a LogoutRequest names its subject by a plain NameID here; EncryptedID and BaseID are refused")
      nameID = request.only(assertionNamespace, "NameID")
      if not nameID.simpleText.strip():
        raise SAMLRefused("the LogoutRequest's NameID is blank")
      indexes = tuple(index.simpleText for index in request.childrenNamed(protocolNamespace, "SessionIndex"))
      self.replayCache.admit(self.identityProvider.entityID, requestID, issued + self.pendingSeconds + 2 * self.leewaySeconds, now)
    except (XMLRefused, SignatureRefused) as error:
      raise SAMLRefused(str(error)) from None
    return SignOutRequest(requestID=requestID, nameID=nameID.simpleText, nameIDFormat=nameID.attribute("Format"),
                          sessionIndexes=indexes, relayState=relayState)

  def answerSignOut(self, request: SignOutRequest) -> str:
    """The address that tells the identity provider the session has ended: a signed LogoutResponse by the Redirect
    binding. End the application's session first."""
    location = self._logoutAddress()
    if self.identityProvider.singleLogoutResponseURL is not None:
      location = self.identityProvider.singleLogoutResponseURL
    message, instant = self._newMessage()
    response = (
      f'<samlp:LogoutResponse xmlns:samlp="{protocolNamespace}" xmlns:saml="{assertionNamespace}" ID="{message.requestID}" '
      f'Version="2.0" IssueInstant="{instant}" Destination="{_attribute(location)}" '
      f'InResponseTo="{_attribute(request.requestID)}"><saml:Issuer>{_attribute(self.entityID)}</saml:Issuer>'
      f'<samlp:Status><samlp:StatusCode Value="{successStatus}"/></samlp:Status></samlp:LogoutResponse>'
    )
    return self._redirect(location, "SAMLResponse", response, request.relayState)

  def _destination(self, message: Element) -> None:
    if message.attribute("Destination") != self.singleLogoutURL:
      raise SAMLRefused(f"the {message.localName} is for {message.attribute('Destination')!r}, not {self.singleLogoutURL!r}")

  def _incoming(self, parameter: str, query: str | None, posted: str | None,
                relayState: str | None) -> tuple[Element, str | None]:
    """A logout message and its RelayState, its signature verified: the Redirect binding's query signature, or the
    POST binding's enveloped XML signature."""
    keys = list(self.identityProvider.signingKeys)
    if query is not None and posted is None:
      return self._redirected(parameter, query, relayState, keys)
    if posted is None or query is not None:
      raise ValueError("give the Redirect binding's query or the POST binding's posted value, one of them")
    if len(posted) > maximumResponseLength:
      raise SAMLRefused(f"the {parameter} is longer than {maximumResponseLength} characters")
    message = parse(_base64(posted, f"the {parameter}"))
    if not message.childrenNamed(dsig, "Signature"):
      raise SAMLRefused(f"the posted {message.localName} is not signed")
    return verifyEnveloped(message, keys), relayState

  @staticmethod
  def _redirected(parameter: str, query: str, relayState: str | None,
                  keys: list[RSAPublicKey | ECPublicKey]) -> tuple[Element, str | None]:
    if relayState is not None:
      raise ValueError("the Redirect binding's RelayState is read from its query")
    if len(query) > maximumResponseLength or not query.isascii():
      raise SAMLRefused(f"the query is not ASCII of at most {maximumResponseLength} characters")
    fields: dict[str, str] = {}
    for part in query.split("&"):
      name, _, value = part.partition("=")
      if name in _bindingParameters:
        if name in fields:
          raise SAMLRefused(f"the query carries {name} twice")
        fields[name] = value
      elif urllib.parse.unquote_plus(name) in _bindingParameters:
        raise SAMLRefused(f"the query spells {urllib.parse.unquote_plus(name)} as {name!r}; only the literal name is read")
    if parameter not in fields or ({"SAMLRequest", "SAMLResponse"} - {parameter}) & set(fields):
      raise SAMLRefused(f"the query must carry a {parameter} and nothing else to read")
    if "SigAlg" not in fields or "Signature" not in fields:
      raise SAMLRefused(f"the {parameter} is not signed: the query has no SigAlg and Signature")
    signedPart = "&".join(f"{name}={fields[name]}" for name in (parameter, "RelayState", "SigAlg") if name in fields)
    signature = _base64(urllib.parse.unquote_plus(fields["Signature"]), "the Signature")
    verifySignatureValue(signedPart.encode("ascii"), signature, urllib.parse.unquote_plus(fields["SigAlg"]), keys)
    message = parse(_inflated(_base64(urllib.parse.unquote_plus(fields[parameter]), f"the {parameter}")))
    readState = urllib.parse.unquote_plus(fields["RelayState"]) if "RelayState" in fields else None
    return message, readState


def _cipherValue(element: Element) -> bytes:
  cipherData = element.only(xmlEncryption, "CipherData")
  if cipherData.childrenNamed(xmlEncryption, "CipherReference"):
    raise SAMLRefused("a CipherReference is refused; the ciphertext must be in the document")
  try:
    return base64.b64decode("".join(cipherData.only(xmlEncryption, "CipherValue").simpleText.split()), validate=True)
  except binascii.Error:
    raise SAMLRefused(f"the {element.localName}'s CipherValue is not base64") from None


def _inContext(plaintext: bytes, context: Element) -> Element:
  """The one element of decrypted XML, parsed with the namespaces in scope where it was encrypted (XML Encryption 4.5);
  a prefix taken from there is trusted only under the element's own signature (`_inheritedPrefixes`)."""
  namespaces: dict[str, str] = {}
  element: Element | None = context
  while element is not None:
    for prefix, uri in element.declarations.items():
      namespaces.setdefault(prefix, uri)
    element = element.parent
  declarations = "".join(f' xmlns="{_attribute(uri)}"' if prefix == "" else f' xmlns:{prefix}="{_attribute(uri)}"'
                         for prefix, uri in sorted(namespaces.items()) if prefix != "xml")
  wrapper = parse(f"<decrypted{declarations}>".encode("utf-8") + plaintext + b"</decrypted>")
  elements = wrapper.elements()
  if len(elements) != 1 or any(isinstance(child, Text) and child.data.strip() for child in wrapper.children):
    raise ValueError("the decrypted XML is not one element")
  return elements[0]


def _inheritedPrefixes(root: Element) -> set[str]:
  """The prefixes `root` and its descendants use whose namespace is declared outside `root`."""
  inherited = set()
  for element in (root, *root.descendants()):
    used = {element.prefix} | {name.partition(":")[0] for name, _ in element.attributes
                               if ":" in name and not name.startswith("xmlns:")}
    for prefix in used - {"xml"}:
      if not _declaredWithin(element, prefix, root) and root.namespaceFor(prefix):
        inherited.add(prefix)
  return inherited


def _declaredWithin(element: Element, prefix: str, root: Element) -> bool:
  current: Element | None = element
  while current is not None:
    if prefix in current.declarations:
      return True
    if current is root:
      return False
    current = current.parent
  return False


def _attribute(text: str) -> str:
  """Text for an attribute value or element content of this service provider's own XML."""
  if _notXMLCharacter.search(text):
    raise SAMLRefused(f"{text!r} holds a character XML cannot carry")
  return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
          .replace("\t", "&#9;").replace("\n", "&#10;").replace("\r", "&#13;"))


def _attributeValue(value: Element) -> str:
  """An attribute's value as text; one NameID element is read as its text, the form eduPersonTargetedID takes."""
  elements = value.elements()
  if len(elements) == 1 and elements[0].isA(assertionNamespace, "NameID") and not value.text.replace(elements[0].text, "", 1).strip():
    return elements[0].simpleText
  return value.simpleText


def _keyDescriptor(use: str, certificate: bytes, methods: list[str]) -> str:
  publicKeyFromCertificate(certificate)
  encoded = base64.b64encode(certificate).decode("ascii")
  return (f'<md:KeyDescriptor use="{use}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encoded}</ds:X509Certificate>'
          "</ds:X509Data></ds:KeyInfo>" + "".join(f'<md:EncryptionMethod Algorithm="{method}"/>' for method in methods)
          + "</md:KeyDescriptor>")


def serviceProviderMetadata(entityID: str, assertionConsumerURL: str, displayNames: dict[str, str] | None = None,
                            informationURL: str | None = None, privacyStatementURL: str | None = None,
                            organizationName: str | None = None, technicalContact: str | None = None,
                            securityContact: str | None = None, entityCategories: tuple[str, ...] = (),
                            signingCertificate: bytes | None = None, encryptionCertificates: tuple[bytes, ...] = (),
                            encryptionPolicy: EncryptionPolicy = EncryptionPolicy(),
                            singleLogoutURL: str | None = None) -> bytes:
  """This service provider's metadata, for an identity provider (or a federation) to register; unsigned.

  Only the entity ID and the assertion consumer address are needed; names, information and privacy pages, the
  organization, contacts and entity categories are written when given (a federation asks for all of them). The
  signing certificate (DER, a SigningKey's `certificate`) says requests are signed; each encryption certificate
  (DER, a DecryptionKey's) is listed with the algorithms `encryptionPolicy` allows; the single logout address
  takes the Redirect and the POST binding."""
  for address in (assertionConsumerURL, informationURL, privacyStatementURL, singleLogoutURL):
    if address is not None and not address.startswith("https://"):
      raise ValueError(f"{address} must be an https address")
  for contact in (technicalContact, securityContact):
    if contact is not None and not re.match(r"^[^@\s]+@[^@\s]+$", contact):
      raise ValueError(f"{contact} is not an e-mail address")
  if organizationName is not None and informationURL is None:
    raise ValueError("an organization needs its informationURL, written as the OrganizationURL")
  names = "".join(f'<mdui:DisplayName xml:lang="{_attribute(language)}">{_attribute(text)}</mdui:DisplayName>'
                  for language, text in sorted((displayNames or {}).items()))
  pages = "".join(f'<mdui:{element} xml:lang="en">{_attribute(address)}</mdui:{element}>'
                  for element, address in (("InformationURL", informationURL), ("PrivacyStatementURL", privacyStatementURL))
                  if address is not None)
  information = f"<md:Extensions><mdui:UIInfo>{names}{pages}</mdui:UIInfo></md:Extensions>" if names or pages else ""
  categories = "".join(f"<saml:AttributeValue>{_attribute(category)}</saml:AttributeValue>" for category in entityCategories)
  extensions = (f'<md:Extensions><mdattr:EntityAttributes><saml:Attribute Name="{entityCategoryName}" '
                f'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">{categories}</saml:Attribute>'
                f"</mdattr:EntityAttributes></md:Extensions>" if entityCategories else "")
  keyDescriptors = (_keyDescriptor("signing", signingCertificate, []) if signingCertificate is not None else "") + "".join(
    _keyDescriptor("encryption", certificate, encryptionPolicy.metadataAlgorithms()) for certificate in encryptionCertificates)
  logout = "".join(f'<md:SingleLogoutService Binding="{binding}" Location="{_attribute(singleLogoutURL)}"/>'
                   for binding in (redirectBinding, postBinding)) if singleLogoutURL is not None else ""
  organization = ""
  if organizationName is not None and informationURL is not None:
    organization = (f'<md:Organization><md:OrganizationName xml:lang="en">{_attribute(organizationName)}</md:OrganizationName>'
                    f'<md:OrganizationDisplayName xml:lang="en">{_attribute(organizationName)}</md:OrganizationDisplayName>'
                    f'<md:OrganizationURL xml:lang="en">{_attribute(informationURL)}</md:OrganizationURL></md:Organization>')
  contacts = ""
  if technicalContact is not None:
    contacts += (f'<md:ContactPerson contactType="technical"><md:EmailAddress>mailto:{_attribute(technicalContact)}'
                 "</md:EmailAddress></md:ContactPerson>")
  if securityContact is not None:
    contacts += ('<md:ContactPerson contactType="other" xmlns:remd="http://refeds.org/metadata" '
                 'remd:contactType="http://refeds.org/metadata/contactType/security">'
                 f"<md:EmailAddress>mailto:{_attribute(securityContact)}</md:EmailAddress></md:ContactPerson>")
  document = (
    f'<md:EntityDescriptor xmlns:md="{metadataNamespace}" xmlns:saml="{assertionNamespace}" '
    f'xmlns:mdui="{uiNamespace}" xmlns:mdattr="{entityAttributeNamespace}" xmlns:ds="{dsig}" entityID="{_attribute(entityID)}">'
    f"{extensions}"
    '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
    f'AuthnRequestsSigned="{"true" if signingCertificate is not None else "false"}" WantAssertionsSigned="true">'
    f"{information}{keyDescriptors}{logout}"
    '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    f'Location="{_attribute(assertionConsumerURL)}" index="0" isDefault="true"/>'
    f"</md:SPSSODescriptor>{organization}{contacts}</md:EntityDescriptor>"
  )
  return document.encode("utf-8")
