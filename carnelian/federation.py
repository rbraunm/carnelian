# SPDX-License-Identifier: MIT
"""SAML research and education federations: InCommon, the national federations and eduGAIN.

A federation vouches for its institutions by signing their metadata. Each institution's
metadata is fetched by the Metadata Query protocol (MDQ: one small signed document per
entity, as InCommon serves its own and eduGAIN's), its signature checked against the
federation's signing certificate, and its validUntil required and honoured. What is read:
the identity provider (its single sign-on address and signing keys), its display names, the
federation that registered it, its entity categories, and its scopes.

A federation's identity is a scoped identifier, `value@scope`: SAML's subject-id or
pairwise-id (the SAML V2.0 Subject Identifier Attributes profile) or eduPersonPrincipalName.
An institution may only vouch for identifiers in the scopes its federation registered for
it, so one university cannot sign in another's people; a scope written as a regular
expression is refused by name. The service provider's own metadata, which the federation
registers, is written by `serviceProviderMetadata`.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from carnelian.der import publicKeyFromCertificate
from carnelian.fetching import DocumentFetcher
from carnelian.saml import IdentityProvider, SAMLIdentity, SAMLRefused, _attribute, _time, identityProviderFromDescriptor, metadataNamespace
from carnelian.xmldsig import SignatureRefused, verifyEnveloped
from carnelian.xmlTree import Element, XMLRefused, parse

__all__ = ["Federation", "Institution", "scopedIdentifier", "serviceProviderMetadata", "subjectID", "pairwiseID",
           "eduPersonPrincipalName", "mail", "displayName", "givenName", "surname", "researchAndScholarship",
           "hideFromDiscovery"]

shibbolethMetadata = "urn:mace:shibboleth:metadata:1.0"
uiNamespace = "urn:oasis:names:tc:SAML:metadata:ui"
registrationNamespace = "urn:oasis:names:tc:SAML:metadata:rpi"
entityAttributeNamespace = "urn:oasis:names:tc:SAML:metadata:attribute"
assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
entityCategory = "http://macedir.org/entity-category"
hideFromDiscovery = "http://refeds.org/category/hide-from-discovery"
researchAndScholarship = "http://refeds.org/category/research-and-scholarship"
metadataMediaType = "application/samlmetadata+xml"

subjectID = "urn:oasis:names:tc:SAML:attribute:subject-id"
pairwiseID = "urn:oasis:names:tc:SAML:attribute:pairwise-id"
eduPersonPrincipalName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
mail = "urn:oid:0.9.2342.19200300.100.1.3"
displayName = "urn:oid:2.16.840.1.113730.3.1.241"
givenName = "urn:oid:2.5.4.42"
surname = "urn:oid:2.5.4.4"
scopedIdentifiers = (subjectID, pairwiseID, eduPersonPrincipalName)

# The SAML V2.0 Subject Identifier Attributes profile, section 3.3.1 (and 3.4.1 for pairwise-id).
_subjectSyntax = re.compile(r"^[0-9A-Za-z][-=0-9A-Za-z]{0,126}@[0-9A-Za-z][-.0-9A-Za-z]{0,126}$")
_principalSyntax = re.compile(r"^[^@\s]+@[0-9A-Za-z][-.0-9A-Za-z]*$")


@dataclass(frozen=True)
class Institution:
  entityID: str
  displayNames: dict[str, str]
  registrationAuthority: str | None
  entityCategories: tuple[str, ...]
  scopes: tuple[str, ...]
  identityProvider: IdentityProvider
  validUntil: float

  def displayName(self, language: str) -> str:
    """The display name in a language, else in English, else the entity ID."""
    base = language.split("-")[0].lower()
    for wanted in (language.lower(), base, "en"):
      for name, text in self.displayNames.items():
        if name.lower() == wanted:
          return text
    return self.entityID

  @property
  def hiddenFromDiscovery(self) -> bool:
    return hideFromDiscovery in self.entityCategories


def _institution(root: Element, signedBy: str) -> Institution:
  identityProvider = identityProviderFromDescriptor(root)
  validUntil = _time(root.attribute("validUntil"), "the metadata's validUntil")
  descriptor = root.only(metadataNamespace, "IDPSSODescriptor")
  scopes, names = [], {}
  extensions = descriptor.optional(metadataNamespace, "Extensions")
  if extensions is not None:
    for scope in extensions.childrenNamed(shibbolethMetadata, "Scope"):
      if scope.attribute("regexp") not in (None, "false", "0"):
        raise SAMLRefused(f"{root.attribute('entityID')} has a scope written as a regular expression, which is refused")
      if scope.text.strip().lower() not in scopes:
        scopes.append(scope.text.strip().lower())
    information = extensions.optional(uiNamespace, "UIInfo")
    if information is not None:
      for name in information.childrenNamed(uiNamespace, "DisplayName"):
        names[name.attribute("lang", "http://www.w3.org/XML/1998/namespace") or ""] = name.text.strip()
  authority, categories = None, []
  entityExtensions = root.optional(metadataNamespace, "Extensions")
  if entityExtensions is not None:
    registration = entityExtensions.optional(registrationNamespace, "RegistrationInfo")
    authority = registration.attribute("registrationAuthority") if registration is not None else None
    attributes = entityExtensions.optional(entityAttributeNamespace, "EntityAttributes")
    if attributes is not None:
      for attribute in attributes.childrenNamed(assertionNamespace, "Attribute"):
        if attribute.attribute("Name") == entityCategory:
          categories += [value.text.strip() for value in attribute.childrenNamed(assertionNamespace, "AttributeValue")]
  if not scopes:
    raise SAMLRefused(f"{root.attribute('entityID')} has no scope in {signedBy}'s metadata, so it can vouch for no one")
  return Institution(entityID=root.required("entityID"), displayNames=names, registrationAuthority=authority,
                     entityCategories=tuple(categories), scopes=tuple(scopes), identityProvider=identityProvider,
                     validUntil=validUntil)


class Federation:
  """A federation's institutions, fetched one by one from its MDQ service and checked against its signing certificate."""

  def __init__(self, name: str, mdqURL: str, signingCertificate: str | bytes, fetcher: DocumentFetcher,
               maximumCacheSeconds: float = 6 * 3600, clock: Callable[[], float] = time.time) -> None:
    if not mdqURL.startswith("https://") or mdqURL.endswith("/"):
      raise ValueError("mdqURL must be an https address without a trailing slash")
    self.name, self.mdqURL, self.fetcher = name, mdqURL, fetcher
    self.signingKey = publicKeyFromCertificate(signingCertificate)
    self.maximumCacheSeconds, self.clock = maximumCacheSeconds, clock
    self._cache: dict[str, tuple[float, Institution]] = {}

  def institution(self, entityID: str) -> Institution:
    now = self.clock()
    cached = self._cache.get(entityID)
    if cached is not None and cached[0] > now:
      return cached[1]
    address = f"{self.mdqURL}/entities/{urllib.parse.quote(entityID, safe='')}"
    institution = self.read(self.fetcher.getBytes(address, metadataMediaType), entityID)
    self._cache[entityID] = (min(institution.validUntil, now + self.maximumCacheSeconds), institution)
    return institution

  def read(self, metadata: bytes, entityID: str) -> Institution:
    """One entity's signed metadata, as the MDQ service answers it, checked."""
    try:
      root = parse(metadata)
      if not root.isA(metadataNamespace, "EntityDescriptor"):
        raise SAMLRefused(f"{self.name} did not answer with an EntityDescriptor")
      if verifyEnveloped(root, [self.signingKey]) is not root:
        raise SAMLRefused(f"{self.name}'s signature does not cover the whole EntityDescriptor")
    except (XMLRefused, SignatureRefused) as error:
      raise SAMLRefused(f"{self.name}'s metadata for {entityID} is refused: {error}") from None
    if root.attribute("entityID") != entityID:
      raise SAMLRefused(f"{self.name} answered for {root.attribute('entityID')!r}, not {entityID!r}")
    institution = _institution(root, self.name)
    if institution.validUntil <= self.clock():
      raise SAMLRefused(f"{self.name}'s metadata for {entityID} expired")
    return institution


def scopedIdentifier(identity: SAMLIdentity, institution: Institution, attributeName: str) -> str:
  """The identity's scoped identifier, refused unless its scope is one the institution was registered for."""
  if attributeName not in scopedIdentifiers:
    raise ValueError(f"{attributeName} is not a scoped identifier attribute")
  if identity.issuer != institution.entityID:
    raise SAMLRefused(f"the identity was issued by {identity.issuer!r}, not {institution.entityID!r}")
  values = identity.attributes.get(attributeName, ())
  if len(values) != 1:
    raise SAMLRefused(f"{institution.entityID} sent {len(values)} values of {attributeName}, not one")
  value = values[0].strip()
  syntax = _principalSyntax if attributeName == eduPersonPrincipalName else _subjectSyntax
  if not syntax.match(value):
    raise SAMLRefused(f"{institution.entityID} sent a {attributeName} that is not a scoped identifier")
  scope = value.rpartition("@")[2].lower()
  if scope not in institution.scopes:
    raise SAMLRefused(f"{institution.entityID} may vouch for {', '.join(institution.scopes)}, not {scope}")
  # The profile makes subject-id and pairwise-id case-insensitive; eduPersonPrincipalName keeps its case.
  return value.lower() if attributeName != eduPersonPrincipalName else value


def serviceProviderMetadata(entityID: str, assertionConsumerURL: str, displayNames: dict[str, str],
                            informationURL: str, privacyStatementURL: str, organizationName: str,
                            technicalContact: str, securityContact: str | None = None,
                            entityCategories: tuple[str, ...] = (researchAndScholarship,)) -> bytes:
  """The service provider's metadata for its federation to register: unsigned (the federation signs what it publishes)."""
  for address in (assertionConsumerURL, informationURL, privacyStatementURL):
    if not address.startswith("https://"):
      raise ValueError(f"{address} must be an https address")
  for contact in (technicalContact, securityContact):
    if contact is not None and not re.match(r"^[^@\s]+@[^@\s]+$", contact):
      raise ValueError(f"{contact} is not an e-mail address")
  names = "".join(f'<mdui:DisplayName xml:lang="{_attribute(language)}">{_attribute(text)}</mdui:DisplayName>'
                  for language, text in sorted(displayNames.items()))
  categories = "".join(f"<saml:AttributeValue>{_attribute(category)}</saml:AttributeValue>" for category in entityCategories)
  security = ""
  if securityContact is not None:
    security = (f'<md:ContactPerson contactType="other" xmlns:remd="http://refeds.org/metadata" '
                f'remd:contactType="http://refeds.org/metadata/contactType/security">'
                f"<md:EmailAddress>mailto:{_attribute(securityContact)}</md:EmailAddress></md:ContactPerson>")
  document = (
    f'<md:EntityDescriptor xmlns:md="{metadataNamespace}" xmlns:saml="{assertionNamespace}" '
    f'xmlns:mdui="{uiNamespace}" xmlns:mdattr="{entityAttributeNamespace}" entityID="{_attribute(entityID)}">'
    + (f'<md:Extensions><mdattr:EntityAttributes><saml:Attribute Name="{entityCategory}" '
       f'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">{categories}</saml:Attribute>'
       f"</mdattr:EntityAttributes></md:Extensions>" if entityCategories else "")
    + '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
      'AuthnRequestsSigned="false" WantAssertionsSigned="true">'
      f"<md:Extensions><mdui:UIInfo>{names}"
      f'<mdui:InformationURL xml:lang="en">{_attribute(informationURL)}</mdui:InformationURL>'
      f'<mdui:PrivacyStatementURL xml:lang="en">{_attribute(privacyStatementURL)}</mdui:PrivacyStatementURL>'
      "</mdui:UIInfo></md:Extensions>"
      f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
      f'Location="{_attribute(assertionConsumerURL)}" index="0" isDefault="true"/>'
      "</md:SPSSODescriptor>"
      f'<md:Organization><md:OrganizationName xml:lang="en">{_attribute(organizationName)}</md:OrganizationName>'
      f'<md:OrganizationDisplayName xml:lang="en">{_attribute(organizationName)}</md:OrganizationDisplayName>'
      f'<md:OrganizationURL xml:lang="en">{_attribute(informationURL)}</md:OrganizationURL></md:Organization>'
      f'<md:ContactPerson contactType="technical"><md:EmailAddress>mailto:{_attribute(technicalContact)}'
      f"</md:EmailAddress></md:ContactPerson>{security}</md:EntityDescriptor>"
  )
  return document.encode("utf-8")
