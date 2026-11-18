# SPDX-License-Identifier: MIT
"""Enveloped XML Signatures, verified the narrow way SAML uses them (XML-DSig 1.1).

Breadth is where XML signature attacks live, so only one shape is accepted: one
<ds:Signature> as a direct child of the element it signs; one <ds:Reference> whose URI is
'#' and that element's ID, an ID no other element in the document carries; exactly the
transforms enveloped-signature then Exclusive Canonicalization; exclusive canonicalization
for <ds:SignedInfo>; SHA-256/384/512 digests; RSA (PKCS #1 v1.5 or PSS) or ECDSA. SHA-1,
other transforms, other canonicalizations and missing, empty or external URIs are refused by name.
<ds:KeyInfo> is never trusted: the signature must verify with a key the caller already
trusts (the identity provider's, from its metadata). On success the very element that was
verified is returned, so the caller reads nothing that the signature did not cover.

`signatureShape`, `checkDigest` and `checkSignatureValue` are the same checks in pieces, for
a document too large for a tree whose digest is computed as it streams by. Such a caller
may also accept the transform exclusive c14n WithComments: a same-document reference
removes comments before any transform runs, so it canonicalizes exactly as without them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass

from carnelian.signatures import ECPublicKey, RSAPublicKey, SignatureError
from carnelian.xmlTree import Element, XMLRefused, canonical, writeCanonical

dsig = "http://www.w3.org/2000/09/xmldsig#"
exclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
exclusiveC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
envelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

_digests = {
  "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
  "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
  "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}
_signatureMethods = {
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": ("rsa", "sha256"),
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": ("rsa", "sha384"),
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": ("rsa", "sha512"),
  "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": ("pss", "sha256"),
  "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": ("pss", "sha384"),
  "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": ("pss", "sha512"),
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": ("ecdsa", "sha256"),
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": ("ecdsa", "sha384"),
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": ("ecdsa", "sha512"),
}
_refusedByName = {
  "http://www.w3.org/2000/09/xmldsig#sha1": "SHA-1 digests are refused",
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "RSA with SHA-1 is refused",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": "ECDSA with SHA-1 is refused",
}


class SignatureRefused(ValueError):
  """An XML signature that is missing, malformed, of a refused shape, or that does not verify."""


def _algorithm(element: Element) -> str:
  algorithm = element.attribute("Algorithm")
  if algorithm is None:
    raise SignatureRefused(f"<{element.localName}> names no Algorithm")
  if algorithm in _refusedByName:
    raise SignatureRefused(_refusedByName[algorithm])
  return algorithm


def _base64(text: str) -> bytes:
  try:
    return base64.b64decode("".join(text.split()), validate=True)
  except ValueError:
    raise SignatureRefused("a signature or digest value is not base64") from None


def _inclusivePrefixes(method: Element) -> tuple[str, ...]:
  found = method.childrenNamed(exclusiveC14N, "InclusiveNamespaces")
  if len(found) > 1:
    raise SignatureRefused("more than one InclusiveNamespaces")
  prefixList = found[0].attribute("PrefixList") if found else None
  return tuple(prefixList.split()) if prefixList else ()


def _documentRoot(element: Element) -> Element:
  while element.parent is not None:
    element = element.parent
  return element


@dataclass(frozen=True)
class SignatureShape:
  """A <ds:Signature> of the accepted shape, read but not yet verified."""
  referenceURI: str
  digestName: str
  inclusivePrefixes: tuple[str, ...]
  digestValue: bytes
  signedInfo: bytes
  signatureValue: bytes
  signatureMethod: str


def signatureShape(signature: Element, canonicalizations: tuple[str, ...] = (exclusiveC14N,)) -> SignatureShape:
  """The signature's single reference and values, its algorithms and transforms checked; the URI is the caller's to check."""
  try:
    signedInfo = signature.only(dsig, "SignedInfo")
    method = signedInfo.only(dsig, "CanonicalizationMethod")
    if _algorithm(method) != exclusiveC14N:
      raise SignatureRefused(f"SignedInfo canonicalization {_algorithm(method)} is refused; only exclusive c14n")
    signatureMethod = _algorithm(signedInfo.only(dsig, "SignatureMethod"))
    references = signedInfo.childrenNamed(dsig, "Reference")
    if len(references) != 1:
      raise SignatureRefused(f"SignedInfo has {len(references)} references; exactly one is accepted")
    reference = references[0]
    transforms = reference.only(dsig, "Transforms").childrenNamed(dsig, "Transform")
    algorithms = [_algorithm(transform) for transform in transforms]
    if len(algorithms) != 2 or algorithms[0] != envelopedSignature or algorithms[1] not in canonicalizations:
      raise SignatureRefused("the transforms must be exactly enveloped-signature, then exclusive c14n")
    digestMethod = _algorithm(reference.only(dsig, "DigestMethod"))
    if digestMethod not in _digests:
      raise SignatureRefused(f"digest method {digestMethod} is not supported")
    referenceURI = reference.attribute("URI")
    if referenceURI is None:
      raise SignatureRefused("the Reference has no URI; a same-document URI is required")
    return SignatureShape(referenceURI=referenceURI, digestName=_digests[digestMethod],
                          inclusivePrefixes=_inclusivePrefixes(transforms[1]),
                          digestValue=_base64(reference.only(dsig, "DigestValue").text),
                          signedInfo=canonical(signedInfo, _inclusivePrefixes(method)),
                          signatureValue=_base64(signature.only(dsig, "SignatureValue").text),
                          signatureMethod=signatureMethod)
  except XMLRefused as error:
    raise SignatureRefused(str(error)) from None


def checkDigest(shape: SignatureShape, digest: bytes) -> None:
  if not hmac.compare_digest(digest, shape.digestValue):
    raise SignatureRefused("the signed element's digest does not match: it was changed after signing")


def checkSignatureValue(shape: SignatureShape, trustedKeys: list[RSAPublicKey | ECPublicKey]) -> None:
  verifySignatureValue(shape.signedInfo, shape.signatureValue, shape.signatureMethod, trustedKeys)


def verifySignatureValue(signedBytes: bytes, value: bytes, signatureMethod: str,
                         trustedKeys: list[RSAPublicKey | ECPublicKey]) -> None:
  """Verify a signature value made by `signatureMethod` (an XML-DSig URI) over bytes, as the Redirect binding signs."""
  if not trustedKeys:
    raise SignatureRefused("no trusted key to verify with")
  if signatureMethod in _refusedByName:
    raise SignatureRefused(_refusedByName[signatureMethod])
  if signatureMethod not in _signatureMethods:
    raise SignatureRefused(f"signature method {signatureMethod} is not supported")
  kind, hashName = _signatureMethods[signatureMethod]
  for key in trustedKeys:
    try:
      if kind == "ecdsa":
        if not isinstance(key, ECPublicKey):
          continue
        key.verifyRaw(signedBytes, value, hashName)
      else:
        if not isinstance(key, RSAPublicKey):
          continue
        if kind == "rsa":
          key.verifyPKCS1v15(signedBytes, value, hashName)
        else:
          key.verifyPSS(signedBytes, value, hashName, hashlib.new(hashName).digest_size)
      return
    except SignatureError:
      continue
  raise SignatureRefused("the signature does not verify with any trusted key")


def verifyEnveloped(signed: Element, trustedKeys: list[RSAPublicKey | ECPublicKey]) -> Element:
  """Verify the enveloped signature of `signed`; returns `signed` itself when it verifies."""
  if not trustedKeys:
    raise SignatureRefused("no trusted key to verify with")
  try:
    signature = signed.only(dsig, "Signature")
  except XMLRefused as error:
    raise SignatureRefused(str(error)) from None
  shape = signatureShape(signature)
  identifier = signed.attribute("ID")
  if not identifier or shape.referenceURI != f"#{identifier}":
    raise SignatureRefused(f"the reference {shape.referenceURI!r} is not to the signed element's ID {identifier!r}")
  root = _documentRoot(signed)
  carriers = sum(1 for element in [root, *root.descendants()]
                 if any(local == "ID" and value == identifier for _, local, _, value in element.plainAttributes()))
  if carriers != 1:
    raise SignatureRefused(f"{carriers} elements carry ID {identifier!r}; it must be exactly one")
  digest = hashlib.new(shape.digestName)
  try:
    writeCanonical(signed, digest.update, shape.inclusivePrefixes, leaveOut=signature)
  except XMLRefused as error:
    raise SignatureRefused(str(error)) from None
  checkDigest(shape, digest.digest())
  checkSignatureValue(shape, trustedKeys)
  return signed
