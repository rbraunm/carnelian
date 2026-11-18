# SPDX-License-Identifier: MIT
"""A SAML 2.0 service provider: the Web Browser SSO profile, Redirect binding out, POST binding back.

The identity provider is known from its metadata: its entity ID, its single sign-on
address for the Redirect binding, and its signing certificates. Sign-in has two halves, as
for OpenID Connect: `beginSignIn` gives the address to send the person to and a Pending
record to keep server-side; `finishSignIn` takes that record and the SAMLResponse posted
back. The response or its assertion must carry a signature by a trusted key (decided by
`xmldsig.verifyEnveloped`, which returns the element it verified, and only verified
elements are read). Then: destination, InResponseTo, issuer, status, one plain assertion
(EncryptedAssertion is refused by name: decrypting needs a secret key), conditions and
every audience restriction, a bearer subject confirmation for this request and address,
and an assertion ID not seen before.

Requests are unsigned (signing needs a secret key); configure the identity provider not to
require signed requests.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import re
import secrets
import time
import urllib.parse
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field

from carnelian.der import publicKeyFromCertificate
from carnelian.signatures import ECPublicKey, RSAPublicKey
from carnelian.xmldsig import SignatureRefused, dsig, verifyEnveloped
from carnelian.xmlTree import Element, XMLRefused, parse

__all__ = ["SAMLRefused", "IdentityProvider", "identityProviderFromMetadata", "Pending", "SAMLIdentity",
           "ReplayCache", "ServiceProvider"]

assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
protocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"
metadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
redirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
postBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
successStatus = "urn:oasis:names:tc:SAML:2.0:status:Success"
bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


class SAMLRefused(ValueError):
  """A SAML sign-in that did not complete, with why."""


@dataclass(frozen=True)
class IdentityProvider:
  entityID: str
  singleSignOnURL: str
  signingKeys: tuple[RSAPublicKey | ECPublicKey, ...]


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
    if len(services) != 1 or not services[0].startswith("https://"):
      raise SAMLRefused(f"the metadata needs one https SingleSignOnService for the Redirect binding, got {services}")
    keys = []
    for keyDescriptor in descriptor.childrenNamed(metadataNamespace, "KeyDescriptor"):
      if keyDescriptor.attribute("use") not in (None, "signing"):
        continue
      for certificate in keyDescriptor.only(dsig, "KeyInfo").only(dsig, "X509Data").childrenNamed(dsig, "X509Certificate"):
        keys.append(publicKeyFromCertificate(base64.b64decode("".join(certificate.text.split()), validate=True)))
  except (XMLRefused, binascii.Error) as error:
    raise SAMLRefused(f"the metadata is refused: {error}") from None
  if not keys:
    raise SAMLRefused("the metadata names no signing certificate")
  return IdentityProvider(entityID=found, singleSignOnURL=services[0], signingKeys=tuple(keys))


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


class ReplayCache:
  """Assertion IDs seen, kept until their assertion could no longer be accepted anyway."""

  def __init__(self) -> None:
    self._seen: dict[str, float] = {}

  def admit(self, assertionID: str, until: float, now: float) -> None:
    self._seen = {key: expiry for key, expiry in self._seen.items() if expiry > now}
    if assertionID in self._seen:
      raise SAMLRefused(f"assertion {assertionID!r} was already used")
    self._seen[assertionID] = until


_instant = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$")


def _time(text: str | None, what: str) -> float:
  match = _instant.match(text or "")
  if not match:
    raise SAMLRefused(f"{what} {text!r} is not a UTC dateTime")
  year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
  whole = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.UTC).timestamp()
  return whole + (float(match.group(7)) if match.group(7) else 0.0)


class ServiceProvider:
  def __init__(self, entityID: str, assertionConsumerURL: str, identityProvider: IdentityProvider,
               leewaySeconds: int = 60, pendingSeconds: int = 600, replayCache: ReplayCache | None = None,
               clock: Callable[[], float] = time.time) -> None:
    self.entityID = entityID
    self.assertionConsumerURL = assertionConsumerURL
    self.identityProvider = identityProvider
    self.leewaySeconds = leewaySeconds
    self.pendingSeconds = pendingSeconds
    self.replayCache = replayCache if replayCache is not None else ReplayCache()
    self.clock = clock

  def beginSignIn(self, relayState: str | None = None) -> tuple[str, Pending]:
    pending = Pending(requestID="_" + secrets.token_hex(20), startedAt=self.clock())
    instant = datetime.datetime.fromtimestamp(pending.startedAt, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    request = (
      f'<samlp:AuthnRequest xmlns:samlp="{protocolNamespace}" xmlns:saml="{assertionNamespace}" ID="{pending.requestID}" '
      f'Version="2.0" IssueInstant="{instant}" Destination="{_attribute(self.identityProvider.singleSignOnURL)}" '
      f'AssertionConsumerServiceURL="{_attribute(self.assertionConsumerURL)}" ProtocolBinding="{postBinding}">'
      f"<saml:Issuer>{_attribute(self.entityID)}</saml:Issuer></samlp:AuthnRequest>"
    )
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(request.encode("utf-8")) + compressor.flush()
    fields = {"SAMLRequest": base64.b64encode(deflated).decode("ascii")}
    if relayState is not None:
      fields["RelayState"] = relayState
    separator = "&" if "?" in self.identityProvider.singleSignOnURL else "?"
    return f"{self.identityProvider.singleSignOnURL}{separator}{urllib.parse.urlencode(fields)}", pending

  def finishSignIn(self, pending: Pending, samlResponse: str) -> SAMLIdentity:
    now = self.clock()
    if now - pending.startedAt > self.pendingSeconds:
      raise SAMLRefused("the sign-in took too long; start again")
    try:
      response = parse(base64.b64decode("".join(samlResponse.split()), validate=True))
      return self._read(response, pending, now)
    except binascii.Error:
      raise SAMLRefused("the SAMLResponse is not base64") from None
    except (XMLRefused, SignatureRefused) as error:
      raise SAMLRefused(str(error)) from None

  def _issuer(self, element: Element, required: bool) -> None:
    issuer = element.only(assertionNamespace, "Issuer") if required else element.optional(assertionNamespace, "Issuer")
    if issuer is not None and issuer.text != self.identityProvider.entityID:
      raise SAMLRefused(f"issued by {issuer.text!r}, not {self.identityProvider.entityID!r}")

  def _read(self, response: Element, pending: Pending, now: float) -> SAMLIdentity:
    if not response.isA(protocolNamespace, "Response") or response.attribute("Version") != "2.0":
      raise SAMLRefused("not a SAML 2.0 Response")
    if response.attribute("Destination") != self.assertionConsumerURL:
      raise SAMLRefused(f"the response is for {response.attribute('Destination')!r}, not {self.assertionConsumerURL!r}")
    if response.attribute("InResponseTo") != pending.requestID:
      raise SAMLRefused("the response does not answer this sign-in's request")
    self._issuer(response, required=False)
    status = response.only(protocolNamespace, "Status").only(protocolNamespace, "StatusCode")
    if status.attribute("Value") != successStatus:
      message = response.only(protocolNamespace, "Status").optional(protocolNamespace, "StatusMessage")
      raise SAMLRefused(f"the identity provider answered {status.attribute('Value')}: {message.text if message else ''}".rstrip(": "))
    if response.childrenNamed(assertionNamespace, "EncryptedAssertion"):
      raise SAMLRefused("encrypted assertions are refused: decrypting needs a secret key; configure the provider not to encrypt")
    keys = list(self.identityProvider.signingKeys)
    responseSigned = bool(response.childrenNamed(dsig, "Signature"))
    if responseSigned:
      response = verifyEnveloped(response, keys)
    assertion = response.only(assertionNamespace, "Assertion")
    if assertion.childrenNamed(dsig, "Signature"):
      assertion = verifyEnveloped(assertion, keys)
    elif not responseSigned:
      raise SAMLRefused("neither the response nor its assertion is signed")
    return self._readAssertion(assertion, pending, now)

  def _readAssertion(self, assertion: Element, pending: Pending, now: float) -> SAMLIdentity:
    leeway = self.leewaySeconds
    if assertion.attribute("Version") != "2.0" or not assertion.attribute("ID"):
      raise SAMLRefused("not a SAML 2.0 Assertion with an ID")
    self._issuer(assertion, required=True)
    conditions = assertion.only(assertionNamespace, "Conditions")
    if conditions.attribute("NotBefore") is not None and _time(conditions.attribute("NotBefore"), "NotBefore") > now + leeway:
      raise SAMLRefused("the assertion is not valid yet")
    notOnOrAfter = _time(conditions.attribute("NotOnOrAfter"), "Conditions NotOnOrAfter")
    if notOnOrAfter <= now - leeway:
      raise SAMLRefused("the assertion has expired")
    restrictions = conditions.childrenNamed(assertionNamespace, "AudienceRestriction")
    if not restrictions:
      raise SAMLRefused("the assertion has no audience restriction")
    for restriction in restrictions:
      if self.entityID not in [audience.text for audience in restriction.childrenNamed(assertionNamespace, "Audience")]:
        raise SAMLRefused(f"the assertion is not for {self.entityID!r}")
    subject = assertion.only(assertionNamespace, "Subject")
    nameID = subject.only(assertionNamespace, "NameID")
    confirmations = [confirmation for confirmation in subject.childrenNamed(assertionNamespace, "SubjectConfirmation")
                     if confirmation.attribute("Method") == bearer]
    if not confirmations:
      raise SAMLRefused("the assertion has no bearer subject confirmation")
    if not any(self._confirms(confirmation, pending, now) for confirmation in confirmations):
      raise SAMLRefused("no subject confirmation is for this sign-in, this address and now")
    statement = assertion.optional(assertionNamespace, "AuthnStatement")
    attributes: dict[str, tuple[str, ...]] = {}
    for attributeStatement in assertion.childrenNamed(assertionNamespace, "AttributeStatement"):
      for attribute in attributeStatement.childrenNamed(assertionNamespace, "Attribute"):
        name = attribute.required("Name")
        values = tuple(value.text for value in attribute.childrenNamed(assertionNamespace, "AttributeValue"))
        attributes[name] = attributes.get(name, ()) + values
    self.replayCache.admit(assertion.required("ID"), notOnOrAfter + leeway, now)
    return SAMLIdentity(
      issuer=self.identityProvider.entityID, nameID=nameID.text, nameIDFormat=nameID.attribute("Format"),
      sessionIndex=statement.attribute("SessionIndex") if statement is not None else None, attributes=attributes,
    )

  def _confirms(self, confirmation: Element, pending: Pending, now: float) -> bool:
    data = confirmation.only(assertionNamespace, "SubjectConfirmationData")
    if data.attribute("Recipient") != self.assertionConsumerURL or data.attribute("InResponseTo") != pending.requestID:
      return False
    if data.attribute("NotBefore") is not None:
      return False
    return _time(data.attribute("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter") > now - self.leewaySeconds


def _attribute(text: str) -> str:
  return text.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
