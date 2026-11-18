# SPDX-License-Identifier: MIT
"""Enveloped XML Signatures, verified the narrow way SAML uses them (XML-DSig 1.1).

Breadth is where XML signature attacks live, so only one shape is accepted: one
<ds:Signature> as a direct child of the element it signs; one <ds:Reference> whose URI is
'#' and that element's ID, an ID no other element in the document carries; exactly the
transforms enveloped-signature then Exclusive Canonicalization; exclusive canonicalization
for <ds:SignedInfo>; SHA-256/384/512 digests; RSA (PKCS #1 v1.5 or PSS) or ECDSA. SHA-1,
other transforms, other canonicalizations and empty or external URIs are refused by name.
<ds:KeyInfo> is never trusted: the signature must verify with a key the caller already
trusts (the identity provider's, from its metadata). On success the very element that was
verified is returned, so the caller reads nothing that the signature did not cover.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from carnelian.signatures import ECPublicKey, RSAPublicKey, SignatureError
from carnelian.xmlTree import Element, XMLRefused, canonical

dsig = "http://www.w3.org/2000/09/xmldsig#"
exclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
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
  except binascii.Error:
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


def verifyEnveloped(signed: Element, trustedKeys: list[RSAPublicKey | ECPublicKey]) -> Element:
  """Verify the enveloped signature of `signed`; returns `signed` itself when it verifies."""
  if not trustedKeys:
    raise SignatureRefused("no trusted key to verify with")
  try:
    signature = signed.only(dsig, "Signature")
    signedInfo = signature.only(dsig, "SignedInfo")
    method = signedInfo.only(dsig, "CanonicalizationMethod")
    if _algorithm(method) != exclusiveC14N:
      raise SignatureRefused(f"SignedInfo canonicalization {_algorithm(method)} is refused; only exclusive c14n")
    signatureMethod = _algorithm(signedInfo.only(dsig, "SignatureMethod"))
    references = signedInfo.childrenNamed(dsig, "Reference")
    if len(references) != 1:
      raise SignatureRefused(f"SignedInfo has {len(references)} references; exactly one is accepted")
    reference = references[0]
    identifier = signed.attribute("ID")
    uri = reference.attribute("URI")
    if not identifier or uri != f"#{identifier}":
      raise SignatureRefused(f"the reference {uri!r} is not to the signed element's ID {identifier!r}")
    carriers = [element for element in [_documentRoot(signed), *_documentRoot(signed).descendants()]
                if any(local == "ID" and value == identifier for _, local, _, value in element.plainAttributes())]
    if len(carriers) != 1:
      raise SignatureRefused(f"{len(carriers)} elements carry ID {identifier!r}; it must be exactly one")
    transforms = reference.only(dsig, "Transforms").childrenNamed(dsig, "Transform")
    if [_algorithm(transform) for transform in transforms] != [envelopedSignature, exclusiveC14N]:
      raise SignatureRefused("the transforms must be exactly enveloped-signature, then exclusive c14n")
    digestMethod = _algorithm(reference.only(dsig, "DigestMethod"))
    if digestMethod not in _digests:
      raise SignatureRefused(f"digest method {digestMethod} is not supported")
    digest = hashlib.new(_digests[digestMethod],
                         canonical(signed, _inclusivePrefixes(transforms[1]), leaveOut=signature)).digest()
    if not hmac.compare_digest(digest, _base64(reference.only(dsig, "DigestValue").text)):
      raise SignatureRefused("the signed element's digest does not match: it was changed after signing")
    signedBytes = canonical(signedInfo, _inclusivePrefixes(method))
    value = _base64(signature.only(dsig, "SignatureValue").text)
  except XMLRefused as error:
    raise SignatureRefused(str(error)) from None
  verifySignatureValue(signedBytes, value, signatureMethod, trustedKeys)
  return signed


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
