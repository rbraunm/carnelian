# SPDX-License-Identifier: MIT
"""JSON Web Signatures in compact form, and JSON Web Keys (RFC 7515, 7517, 7518).

Verification only, with public keys. The accepted algorithms are RS256/384/512,
PS256/384/512 and ES256/384/512. 'none' and the HMAC algorithms (HS*) are refused by name:
the first proves nothing, the second needs a shared secret this library does not hold. The
key must suit the algorithm, a 'crit' header is refused (no extension is understood), and
base64url must be unpadded and canonical. A JWK carrying private members is refused, so a
private key handed over by mistake is not quietly used as a public one.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any

from carnelian.signatures import ECPublicKey, RSAPublicKey, SignatureError, curves


JSON = dict[str, Any]


class JOSEError(ValueError):
  """A token, header or key that is malformed or refused."""


_base64url = re.compile(r"^[A-Za-z0-9_-]*$")


def base64urlDecode(text: str) -> bytes:
  if not _base64url.match(text) or len(text) % 4 == 1:
    raise JOSEError("not unpadded base64url")
  try:
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
  except binascii.Error as error:
    raise JOSEError(f"not base64url: {error}") from None
  if base64urlEncode(data) != text:
    raise JOSEError("base64url is not in its canonical form")
  return data


def base64urlEncode(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _text(member: str, jwk: JSON) -> str:
  value = jwk.get(member)
  if not isinstance(value, str):
    raise JOSEError(f"the JWK has no '{member}'")
  return value


def _integer(member: str, jwk: JSON) -> int:
  return int.from_bytes(base64urlDecode(_text(member, jwk)), "big")


_privateMembers = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
_curveOfAlgorithm = {"ES256": ("P-256", "sha256"), "ES384": ("P-384", "sha384"), "ES512": ("P-521", "sha512")}
_rsaHash = {"RS256": "sha256", "RS384": "sha384", "RS512": "sha512", "PS256": "sha256", "PS384": "sha384", "PS512": "sha512"}
supportedAlgorithms = frozenset(_rsaHash) | frozenset(_curveOfAlgorithm)


def keyFromJWK(jwk: JSON) -> RSAPublicKey | ECPublicKey:
  """The public key a JWK describes."""
  if not isinstance(jwk, dict):
    raise JOSEError("a JWK is a JSON object")
  private = sorted(_privateMembers & set(jwk))
  if private:
    raise JOSEError(f"the JWK carries private members {private}; give the public key only")
  kind = jwk.get("kty")
  if kind == "RSA":
    return RSAPublicKey(_integer("n", jwk), _integer("e", jwk))
  if kind == "EC":
    curveName = jwk.get("crv")
    if curveName not in curves:
      raise JOSEError(f"JWK curve '{curveName}' is not one of {sorted(curves)}")
    size = curves[curveName].length
    for member in ("x", "y"):
      if len(base64urlDecode(_text(member, jwk))) != size:
        raise JOSEError(f"the JWK's '{member}' is not {size} bytes for {curveName}")
    return ECPublicKey(curveName, _integer("x", jwk), _integer("y", jwk))
  raise JOSEError(f"JWK key type '{kind}' is not supported")


@dataclass(frozen=True)
class VerifiedJWS:
  header: JSON
  payload: bytes


def readHeader(token: str) -> JSON:
  """The protected header of a compact JWS, before any check of its signature."""
  parts = token.split(".")
  if len(parts) != 3:
    raise JOSEError(f"a compact JWS has three parts, got {len(parts)}")
  try:
    header = json.loads(base64urlDecode(parts[0]))
  except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise JOSEError(f"the JWS header is not JSON: {error}") from None
  if not isinstance(header, dict):
    raise JOSEError("the JWS header is not a JSON object")
  return header


def acceptedAlgorithm(header: JSON, allowedAlgorithms: frozenset[str] = supportedAlgorithms) -> str:
  """The header's algorithm, if it is accepted; checked before any key is looked for."""
  algorithm: object = header.get("alg")
  if algorithm == "none" or (isinstance(algorithm, str) and algorithm.startswith("HS")):
    raise JOSEError(f"algorithm '{algorithm}' is refused")
  if algorithm not in supportedAlgorithms or algorithm not in allowedAlgorithms:
    raise JOSEError(f"algorithm '{algorithm}' is not one of {sorted(allowedAlgorithms & supportedAlgorithms)}")
  if "crit" in header:
    raise JOSEError(f"critical header extensions {header['crit']} are not understood")
  return algorithm


def verifyCompact(token: str, key: RSAPublicKey | ECPublicKey, allowedAlgorithms: frozenset[str] = supportedAlgorithms) -> VerifiedJWS:
  """Verify a compact JWS with a public key; returns its header and payload."""
  header = readHeader(token)
  algorithm = acceptedAlgorithm(header, allowedAlgorithms)
  headerPart, payloadPart, signaturePart = token.split(".")
  signingInput = f"{headerPart}.{payloadPart}".encode("ascii")
  signature = base64urlDecode(signaturePart)
  try:
    if algorithm in _rsaHash:
      if not isinstance(key, RSAPublicKey):
        raise JOSEError(f"algorithm '{algorithm}' needs an RSA key")
      hashName = _rsaHash[algorithm]
      if algorithm.startswith("RS"):
        key.verifyPKCS1v15(signingInput, signature, hashName)
      else:
        key.verifyPSS(signingInput, signature, hashName, {"sha256": 32, "sha384": 48, "sha512": 64}[hashName])
    else:
      curveName, hashName = _curveOfAlgorithm[algorithm]
      if not isinstance(key, ECPublicKey) or key.curveName != curveName:
        raise JOSEError(f"algorithm '{algorithm}' needs a {curveName} key")
      key.verifyRaw(signingInput, signature, hashName)
  except SignatureError as error:
    raise JOSEError(f"the JWS signature does not verify: {error}") from None
  return VerifiedJWS(header=header, payload=base64urlDecode(payloadPart))


class KeySet:
  """A JWK Set (RFC 7517 section 5). Keys are read when chosen, so keys of types not used here do not stop the rest."""

  def __init__(self, document: JSON) -> None:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
      raise JOSEError("a JWK Set is an object with a 'keys' list")
    self.keys = [key for key in document["keys"] if isinstance(key, dict)]

  def keyFor(self, header: JSON) -> RSAPublicKey | ECPublicKey:
    """The one signing key a token's header names by 'kid'."""
    keyID = header.get("kid")
    if not isinstance(keyID, str):
      raise JOSEError("the token names no key ('kid')")
    candidates = [key for key in self.keys if key.get("kid") == keyID and key.get("use", "sig") == "sig"]
    if len(candidates) != 1:
      raise JOSEError(f"the key set has {len(candidates)} signing keys with kid '{keyID}'")
    chosen = candidates[0]
    if "alg" in chosen and chosen["alg"] != header.get("alg"):
      raise JOSEError(f"key '{keyID}' is for '{chosen['alg']}', the token uses '{header.get('alg')}'")
    return keyFromJWK(chosen)
