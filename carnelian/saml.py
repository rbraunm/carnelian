# SPDX-License-Identifier: MIT
"""A SAML 2.0 service provider: the Web Browser SSO profile, Redirect binding out, POST binding back.

The identity provider is known from its metadata: its entity ID, its single sign-on
address for the Redirect binding, and its signing certificates. Sign-in has two halves, as
for OpenID Connect: `beginSignIn` gives the address to send the person to and a Pending
record to keep server-side; `finishSignIn` takes that record and the SAMLResponse posted
back, refused unread when longer than `maximumResponseLength` characters. The response or
its assertion must carry a signature by a trusted key (decided by
`xmldsig.verifyEnveloped`, which returns the element it verified, and only verified
elements are read). Then: destination, InResponseTo, issuer, status, one plain assertion
(EncryptedAssertion is refused by name: decrypting needs a secret key), its validity
window, conditions holding only audience restrictions (OneTimeUse, ProxyRestriction and any
other condition are refused by name) with this service provider in every one, a bearer
subject confirmation whose Recipient is this assertion consumer address and whose
InResponseTo is this request (its Address is not checked), one AuthnStatement whose
SessionNotOnOrAfter, when given, has not passed, and an assertion ID not seen before from
this issuer. NameID, Issuer, Audience and AttributeValue must be text only (an AttributeValue
may also be one NameID, the form eduPersonTargetedID takes); the NameID must not be blank.

Replay is kept by a ReplayStore: the default ReplayCache holds one process's memory, so a
deployment with several processes or hosts gives every ServiceProvider the same shared
store, whose `admit` is an atomic claim.

Requests are unsigned (signing needs a secret key); configure the identity provider not to
require signed requests.
"""

from __future__ import annotations

import base64
import datetime
import re
import secrets
import threading
import time
import urllib.parse
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from carnelian.der import publicKeyFromCertificate
from carnelian.signatures import ECPublicKey, RSAPublicKey
from carnelian.xmldsig import SignatureRefused, dsig, verifyEnveloped
from carnelian.xmlTree import Element, XMLRefused, parse

__all__ = ["SAMLRefused", "IdentityProvider", "identityProviderFromMetadata", "Pending", "SAMLIdentity",
           "ReplayStore", "ReplayCache", "ServiceProvider", "serviceProviderMetadata"]

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
    singleSignOnURL = services[0] if len(services) == 1 else None
    if singleSignOnURL is None or not singleSignOnURL.startswith("https://"):
      raise SAMLRefused(f"the metadata needs one https SingleSignOnService for the Redirect binding, got {services}")
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
  return IdentityProvider(entityID=found, singleSignOnURL=singleSignOnURL, signingKeys=tuple(keys))


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


class ReplayStore(Protocol):
  """Where assertion IDs are remembered, per issuer. Behind several processes, one shared store (a database
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


class ServiceProvider:
  def __init__(self, entityID: str, assertionConsumerURL: str, identityProvider: IdentityProvider,
               leewaySeconds: int = 60, pendingSeconds: int = 600, replayCache: ReplayStore | None = None,
               clock: Callable[[], float] = time.time) -> None:
    self.entityID = entityID
    self.assertionConsumerURL = assertionConsumerURL
    self.identityProvider = identityProvider
    self.leewaySeconds = leewaySeconds
    self.pendingSeconds = pendingSeconds
    self.replayCache: ReplayStore = replayCache if replayCache is not None else ReplayCache()
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
    if len(samlResponse) > maximumResponseLength:
      raise SAMLRefused(f"the SAMLResponse is longer than {maximumResponseLength} characters")
    try:
      document = base64.b64decode("".join(samlResponse.split()), validate=True)
    except ValueError:
      raise SAMLRefused("the SAMLResponse is not base64") from None
    try:
      return self._read(parse(document), pending, now)
    except (XMLRefused, SignatureRefused) as error:
      raise SAMLRefused(str(error)) from None

  def _issuer(self, element: Element, required: bool) -> None:
    issuer = element.only(assertionNamespace, "Issuer") if required else element.optional(assertionNamespace, "Issuer")
    if issuer is not None and issuer.simpleText != self.identityProvider.entityID:
      raise SAMLRefused(f"issued by {issuer.simpleText!r}, not {self.identityProvider.entityID!r}")

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
    assertionID = assertion.attribute("ID")
    if assertion.attribute("Version") != "2.0" or not assertionID:
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


def _attribute(text: str) -> str:
  return text.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")


def _attributeValue(value: Element) -> str:
  """An attribute's value as text; one NameID element is read as its text, the form eduPersonTargetedID takes."""
  elements = value.elements()
  if len(elements) == 1 and elements[0].isA(assertionNamespace, "NameID") and not value.text.replace(elements[0].text, "", 1).strip():
    return elements[0].simpleText
  return value.simpleText


def serviceProviderMetadata(entityID: str, assertionConsumerURL: str, displayNames: dict[str, str] | None = None,
                            informationURL: str | None = None, privacyStatementURL: str | None = None,
                            organizationName: str | None = None, technicalContact: str | None = None,
                            securityContact: str | None = None, entityCategories: tuple[str, ...] = ()) -> bytes:
  """This service provider's metadata, for an identity provider (or a federation) to register; unsigned.

  Only the entity ID and the assertion consumer address are needed; names, information and privacy pages, the
  organization, contacts and entity categories are written when given (a federation asks for all of them)."""
  for address in (assertionConsumerURL, informationURL, privacyStatementURL):
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
    f'xmlns:mdui="{uiNamespace}" xmlns:mdattr="{entityAttributeNamespace}" entityID="{_attribute(entityID)}">'
    f"{extensions}"
    '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
    'AuthnRequestsSigned="false" WantAssertionsSigned="true">'
    f"{information}"
    '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    f'Location="{_attribute(assertionConsumerURL)}" index="0" isDefault="true"/>'
    f"</md:SPSSODescriptor>{organization}{contacts}</md:EntityDescriptor>"
  )
  return document.encode("utf-8")
