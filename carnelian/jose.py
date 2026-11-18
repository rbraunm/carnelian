# SPDX-License-Identifier: MIT
"""JSON Web Signatures in compact form, and JSON Web Keys (RFC 7515, 7517, 7518).

Verification only, with public keys. The accepted algorithms are RS256/384/512,
PS256/384/512 and ES256/384/512. 'none' and the HMAC algorithms (HS*) are refused by name:
the first proves nothing, the second needs a shared secret this library does not hold. The
key must suit the algorithm, a 'crit' header is refused (no extension is understood), and
base64url must be unpadded and canonical, and JSON strict (no NaN, Infinity or numbers too
large to be finite). A JWK carrying private members is refused, so a private key handed over
by mistake is not quietly used as a public one; a JWK whose 'use' or 'key_ops' say it is not
for verifying signatures is not chosen to verify one.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from carnelian.fetching import HTTPFailure, parseJSON
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


def readJSON(data: bytes, what: str) -> object:
  try:
    return parseJSON(data)
  except ValueError as error:
    raise JOSEError(f"{what} is not JSON: {error}") from None


def _text(member: str, jwk: JSON) -> str:
  value = jwk.get(member)
  if not isinstance(value, str):
    raise JOSEError(f"the JWK has no '{member}' as text")
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
  kind = _text("kty", jwk)
  try:
    if kind == "RSA":
      return RSAPublicKey(_integer("n", jwk), _integer("e", jwk))
    if kind == "EC":
      curveName = _text("crv", jwk)
      if curveName not in curves:
        raise JOSEError(f"JWK curve '{curveName}' is not one of {sorted(curves)}")
      size = curves[curveName].length
      for member in ("x", "y"):
        if len(base64urlDecode(_text(member, jwk))) != size:
          raise JOSEError(f"the JWK's '{member}' is not {size} bytes for {curveName}")
      return ECPublicKey(curveName, _integer("x", jwk), _integer("y", jwk))
  except SignatureError as error:
    raise JOSEError(f"the JWK's key is refused: {error}") from None
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
  header = readJSON(base64urlDecode(parts[0]), "the JWS header")
  if not isinstance(header, dict):
    raise JOSEError("the JWS header is not a JSON object")
  return header


def acceptedAlgorithm(header: JSON, allowedAlgorithms: frozenset[str] = supportedAlgorithms) -> str:
  """The header's algorithm, if it is accepted; checked before any key is looked for."""
  algorithm = header.get("alg")
  if not isinstance(algorithm, str):
    raise JOSEError(f"the JWS header's 'alg' is not a name: {algorithm!r}")
  if algorithm == "none" or algorithm.startswith("HS"):
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
  payload = base64urlDecode(payloadPart)
  signature = base64urlDecode(signaturePart)
  signingInput = f"{headerPart}.{payloadPart}".encode("ascii")
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
  return VerifiedJWS(header=header, payload=payload)


def _verifies(jwk: JSON) -> bool:
  use = jwk.get("use", "sig")
  if not isinstance(use, str):
    raise JOSEError(f"a JWK's 'use' is not text: {use!r}")
  operations = jwk.get("key_ops", ["verify"])
  if not isinstance(operations, list) or not all(isinstance(operation, str) for operation in operations):
    raise JOSEError(f"a JWK's 'key_ops' is not a list of names: {operations!r}")
  return use == "sig" and "verify" in operations


class KeySet:
  """A JWK Set (RFC 7517 section 5). Keys are read when chosen, so keys of types not used here do not stop the rest."""

  def __init__(self, document: JSON) -> None:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
      raise JOSEError("a JWK Set is an object with a 'keys' list")
    self.keys = [key for key in document["keys"] if isinstance(key, dict)]

  def keyFor(self, header: JSON) -> RSAPublicKey | ECPublicKey:
    """The one signing key a token's header names by 'kid'."""
    keyID = header.get("kid")
    if keyID is None:
      raise JOSEError("the token names no key ('kid')")
    if not isinstance(keyID, str):
      raise JOSEError(f"the token's 'kid' is not text: {keyID!r}")
    candidates = [key for key in self.keys if key.get("kid") == keyID and _verifies(key)]
    if len(candidates) != 1:
      raise JOSEError(f"the key set has {len(candidates)} signing keys with kid '{keyID}'")
    chosen = candidates[0]
    if "alg" in chosen and chosen["alg"] != header.get("alg"):
      raise JOSEError(f"key '{keyID}' is for '{chosen['alg']}', the token uses '{header.get('alg')}'")
    return keyFromJWK(chosen)


_earliestNumericDate = -62_135_596_800
_latestNumericDate = 253_402_300_799


def numericDate(claims: JSON, member: str) -> float:
  """A JWT time claim: a number of seconds between the years 1 and 9999 (never a boolean, a string or 1e999)."""
  value = claims.get(member)
  if not isinstance(value, (int, float)) or isinstance(value, bool) or (isinstance(value, float) and not math.isfinite(value)):
    raise JOSEError(f"'{member}' is not a finite number: {value!r}")
  if not _earliestNumericDate <= value <= _latestNumericDate:
    raise JOSEError(f"'{member}' is not a time between the years 1 and 9999")
  return float(value)


minimumKeyRefreshSeconds = 60
maximumKeyRetrySeconds = 15 * 60
maximumKeyAgeSeconds = 24 * 60 * 60


class KeyCache:
  """An issuer's JWK set, fetched when first needed, again when a day old, and again when a token names a key it
  lacks or fails against the key it names, so rotation is followed. Fetches are spaced: one at a time, at most one
  a minute, and after each failed or malformed answer the wait doubles up to maximumKeyRetrySeconds; so tokens naming
  unknown keys, or an issuer that is down, cannot make every check fetch the keys. Keys are used until a day after
  the fetch that brought them, however later fetches fare, and never after."""

  def __init__(self, fetchKeys: Callable[[], JSON], clock: Callable[[], float]) -> None:
    self._fetch, self._clock = fetchKeys, clock
    self._lock = threading.Lock()
    self._keys: KeySet | None = None
    self._fetchedAt = float("-inf")
    self._attemptedAt = float("-inf")
    self._failures = 0
    self._lastFailure = ""

  def _current(self) -> KeySet | None:
    if self._keys is None or self._clock() - self._fetchedAt >= maximumKeyAgeSeconds:
      return None
    return self._keys

  def _nextAttempt(self) -> float:
    return self._attemptedAt + min(minimumKeyRefreshSeconds << min(self._failures, 10), maximumKeyRetrySeconds)

  def _refreshed(self) -> KeySet:
    now = self._clock()
    if now < self._nextAttempt():
      raise JOSEError(f"the issuer's keys {self._lastFailure or 'were fetched moments ago'}; "
                      f"the next fetch is in {self._nextAttempt() - now:.0f} seconds")
    self._attemptedAt = now
    try:
      keys = KeySet(self._fetch())
    except (HTTPFailure, JOSEError) as error:
      self._failures += 1
      self._lastFailure = f"could not be fetched ({error})"
      raise JOSEError(f"the issuer's keys {self._lastFailure}") from None
    self._keys, self._fetchedAt, self._failures, self._lastFailure = keys, now, 0, ""
    return keys

  def _keysAfter(self, used: KeySet | None) -> KeySet:
    with self._lock:
      current = self._current()
      if current is not None and current is not used:
        return current
      return self._refreshed()

  def verify(self, token: str, allowedAlgorithms: frozenset[str]) -> VerifiedJWS:
    header = readHeader(token)
    acceptedAlgorithm(header, allowedAlgorithms)
    keys = self._current() or self._keysAfter(None)
    try:
      return verifyCompact(token, keys.keyFor(header), allowedAlgorithms)
    except JOSEError as refusal:
      try:
        newer = self._keysAfter(keys)
      except JOSEError as again:
        raise JOSEError(f"{refusal}; {again}") from None
    return verifyCompact(token, newer.keyFor(header), allowedAlgorithms)
