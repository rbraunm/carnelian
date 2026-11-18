# SPDX-License-Identifier: MIT
"""A federation's metadata aggregate: every member in one signed EntitiesDescriptor, read as a stream.

An aggregate (eduGAIN's is about 95 MB, with thousands of identity providers) is too large
for a tree, so it is read in one pass: each EntityDescriptor is built as a small tree,
read, and dropped, while the document's exclusive canonical form is hashed as it goes by.
Memory follows the largest single entity, not the document.

Only one shape is accepted: an md:EntitiesDescriptor whose first child element is its
enveloped ds:Signature, whose one Reference names the EntitiesDescriptor's ID (or is "",
the whole document), with the transforms enveloped-signature then exclusive c14n; a
validUntil that has not passed; its own md:Extensions and md:EntityDescriptor children and
nothing else (a nested EntitiesDescriptor, a second Signature, or another element is
refused by name). No element but the EntitiesDescriptor may carry its ID.

Each entity with an IDPSSODescriptor is read as `Federation.read` reads one from MDQ (scopes,
display names, registration authority, entity categories, identity provider); its validity
is the aggregate's validUntil or its own, whichever is earlier. An entity that fails those
checks, has expired, or appears twice is left out and listed in `Aggregate.skipped` with
the reason; entities without an IDPSSODescriptor (service providers) are passed over. The
institutions are returned only once the signature has verified over the whole document.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Iterable

from carnelian.der import publicKeyFromCertificate
from carnelian.federation import Institution, _institution, metadataMediaType
from carnelian.fetching import DocumentFetcher
from carnelian.saml import SAMLRefused, _time, metadataNamespace
from carnelian.signatures import ECPublicKey, RSAPublicKey
from carnelian.xmldsig import (SignatureRefused, SignatureShape, checkDigest, checkSignatureValue, dsig, exclusiveC14N,
                               exclusiveC14NWithComments, signatureShape)
from carnelian.xmlTree import DocumentStream, Element, XMLRefused

__all__ = ["Aggregate", "readAggregate", "fetchAggregate"]

_chunkBytes = 1 << 16


class Aggregate:
  """A federation's verified aggregate: its institutions by entity ID, and the entities left out, each with the reason."""

  def __init__(self, name: str, validUntil: float, institutions: dict[str, Institution],
               skipped: tuple[tuple[str, str], ...], clock: Callable[[], float]) -> None:
    self.name, self.validUntil, self.institutions, self.skipped, self.clock = name, validUntil, institutions, skipped, clock

  def institution(self, entityID: str) -> Institution:
    found = self.institutions.get(entityID)
    if found is None:
      raise SAMLRefused(f"{entityID} is not an identity provider in {self.name}'s aggregate")
    if found.validUntil <= self.clock():
      raise SAMLRefused(f"{self.name}'s aggregate expired for {entityID}")
    return found


class _Reader:
  def __init__(self, name: str, signingKey: RSAPublicKey | ECPublicKey, clock: Callable[[], float], maximumBytes: int,
               maximumEntities: int) -> None:
    self.name, self.signingKey, self.clock, self.maximumEntities = name, signingKey, clock, maximumEntities
    self.stream = DocumentStream(self.root, self.child, maximumBytes)
    self.identifier: str | None = None
    self.validUntil = 0.0
    self.shape: SignatureShape | None = None
    self.digest: hashlib._Hash | None = None
    self.entityCount = 0
    self.seen: set[str] = set()
    self.institutions: dict[str, Institution] = {}
    self.skipped: list[tuple[str, str]] = []

  def root(self, root: Element) -> None:
    if not root.isA(metadataNamespace, "EntitiesDescriptor"):
      raise SAMLRefused(f"the document is <{root.qualifiedName}>, not an md:EntitiesDescriptor")
    self.identifier = root.attribute("ID")
    self.validUntil = _time(root.attribute("validUntil"), "its validUntil")
    if self.validUntil <= self.clock():
      raise SAMLRefused(f"it expired at {root.attribute('validUntil')}")

  def child(self, element: Element) -> None:
    if self.identifier is not None:
      for carrier in [element, *element.descendants()]:
        if any(local == "ID" and value == self.identifier for _, local, _, value in carrier.plainAttributes()):
          raise SAMLRefused(f"<{carrier.qualifiedName}> also carries the EntitiesDescriptor's ID {self.identifier!r}")
    if element.isA(dsig, "Signature"):
      if self.shape is not None:
        raise SAMLRefused("it has a second ds:Signature")
      self.signature(element)
    elif self.shape is None:
      raise SAMLRefused(f"it is not signed: its first element is <{element.qualifiedName}>, not ds:Signature")
    elif element.isA(metadataNamespace, "EntityDescriptor"):
      self.entity(element)
    elif element.isA(metadataNamespace, "EntitiesDescriptor"):
      raise SAMLRefused("a nested EntitiesDescriptor is refused")
    elif not element.isA(metadataNamespace, "Extensions"):
      raise SAMLRefused(f"<{element.qualifiedName}> is not accepted in an EntitiesDescriptor")

  def signature(self, signature: Element) -> None:
    shape = signatureShape(signature, (exclusiveC14N, exclusiveC14NWithComments))
    accepted = ("", f"#{self.identifier}") if self.identifier else ("",)
    if shape.referenceURI not in accepted:
      raise SignatureRefused(f"the reference {shape.referenceURI!r} is not to the EntitiesDescriptor's ID {self.identifier!r}")
    self.digest = hashlib.new(shape.digestName)
    self.stream.canonicalize(self.digest.update, shape.inclusivePrefixes, leaveOut=signature)
    self.shape = shape

  def entity(self, entity: Element) -> None:
    self.entityCount += 1
    if self.entityCount > self.maximumEntities:
      raise SAMLRefused(f"it has more than {self.maximumEntities} entities")
    if not entity.childrenNamed(metadataNamespace, "IDPSSODescriptor"):
      return
    entityID = entity.attribute("entityID") or ""
    if entityID in self.seen:
      self.institutions.pop(entityID, None)
      self.skipped.append((entityID, "it appears more than once in the aggregate"))
      return
    self.seen.add(entityID)
    try:
      own = entity.attribute("validUntil")
      validUntil = self.validUntil if own is None else min(self.validUntil, _time(own, "its validUntil"))
      if validUntil <= self.clock():
        raise SAMLRefused(f"it expired at {own}")
      self.institutions[entityID] = _institution(entity, self.name, validUntil)
    except (SAMLRefused, XMLRefused) as error:
      self.skipped.append((entityID, str(error)))

  def finish(self) -> Aggregate:
    self.stream.close()
    if self.shape is None or self.digest is None:
      raise SAMLRefused("it is not signed")
    checkDigest(self.shape, self.digest.digest())
    checkSignatureValue(self.shape, [self.signingKey])
    return Aggregate(self.name, self.validUntil, self.institutions, tuple(self.skipped), self.clock)


def readAggregate(document: bytes | Iterable[bytes], signingCertificate: str | bytes, name: str,
                  clock: Callable[[], float] = time.time, maximumBytes: int = 256 * 1024 * 1024,
                  maximumEntities: int = 100_000) -> Aggregate:
  """A federation's signed aggregate (its bytes, or an iterable of chunks), checked against its signing certificate."""
  reader = _Reader(name, publicKeyFromCertificate(signingCertificate), clock, maximumBytes, maximumEntities)
  chunks = ((document[offset:offset + _chunkBytes] for offset in range(0, len(document), _chunkBytes))
            if isinstance(document, bytes) else document)
  try:
    for chunk in chunks:
      reader.stream.feed(chunk)
    return reader.finish()
  except (SAMLRefused, XMLRefused, SignatureRefused) as error:
    raise SAMLRefused(f"{name}'s aggregate is refused: {error}") from None


def fetchAggregate(url: str, signingCertificate: str | bytes, fetcher: DocumentFetcher, name: str,
                   clock: Callable[[], float] = time.time, maximumBytes: int = 256 * 1024 * 1024,
                   maximumEntities: int = 100_000) -> Aggregate:
  """The aggregate at an https address, fetched and read; the fetcher's own maximumBytes must allow its size."""
  return readAggregate(fetcher.getBytes(url, metadataMediaType), signingCertificate, name, clock, maximumBytes,
                       maximumEntities)
