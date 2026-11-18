# SPDX-License-Identifier: MIT
"""Signature verification with public keys: RSA (PKCS #1 v1.5 and PSS) and ECDSA.

Only verification: no secret key is ever handled, so the timing of these computations
reveals nothing worth protecting. RSA PKCS #1 v1.5 is checked by building the one encoding
a valid signature must decrypt to and comparing it whole (RFC 8017 section 8.2.2), never by
parsing what the signature decrypts to -- parsing is where signature forgeries live. RSA
keys below 2048 bits and unknown hashes are refused; an ECDSA public point must lie on its
curve and signatures must be in range.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


class SignatureError(ValueError):
  """A signature that does not verify, or a key or algorithm that is refused."""


minimumRSABits = 2048

# DER DigestInfo prefixes, RFC 8017 section 9.2 note 1.
_digestInfoPrefix = {
  "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
  "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
  "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _hash(hashName: str, data: bytes) -> bytes:
  if hashName not in _digestInfoPrefix:
    raise SignatureError(f"hash '{hashName}' is not one of {sorted(_digestInfoPrefix)}")
  return hashlib.new(hashName, data).digest()


@dataclass(frozen=True)
class RSAPublicKey:
  modulus: int
  exponent: int

  def __post_init__(self) -> None:
    if self.modulus.bit_length() < minimumRSABits:
      raise SignatureError(f"an RSA key of {self.modulus.bit_length()} bits is refused; {minimumRSABits} or more")
    if self.exponent < 3 or self.exponent % 2 == 0:
      raise SignatureError(f"RSA exponent {self.exponent} is not a valid public exponent")

  @property
  def length(self) -> int:
    return (self.modulus.bit_length() + 7) // 8

  def _opened(self, signature: bytes) -> bytes:
    if len(signature) != self.length:
      raise SignatureError(f"an RSA signature for this key is {self.length} bytes, got {len(signature)}")
    value = int.from_bytes(signature, "big")
    if value >= self.modulus:
      raise SignatureError("the RSA signature is not below the modulus")
    return pow(value, self.exponent, self.modulus).to_bytes(self.length, "big")

  def verifyPKCS1v15(self, message: bytes, signature: bytes, hashName: str) -> None:
    digestInfo = _digestInfoPrefix.get(hashName, b"") + _hash(hashName, message)
    padding = self.length - len(digestInfo) - 3
    if padding < 8:
      raise SignatureError("the RSA key is too short for this hash")
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + digestInfo
    if not hmac.compare_digest(self._opened(signature), expected):
      raise SignatureError("the RSA signature does not verify")

  def verifyPSS(self, message: bytes, signature: bytes, hashName: str, saltLength: int) -> None:
    """EMSA-PSS-VERIFY (RFC 8017 section 9.1.2) with MGF1 on the same hash."""
    messageHash = _hash(hashName, message)
    hashLength = len(messageHash)
    emBits = self.modulus.bit_length() - 1
    emLength = (emBits + 7) // 8
    opened = self._opened(signature)
    if len(opened) > emLength:
      if opened[0] != 0:
        raise SignatureError("the RSA-PSS signature does not verify")
      opened = opened[1:]
    encoded = opened
    if emLength < hashLength + saltLength + 2 or encoded[-1] != 0xBC:
      raise SignatureError("the RSA-PSS signature does not verify")
    maskedDB, hashed = encoded[:emLength - hashLength - 1], encoded[emLength - hashLength - 1:-1]
    unusedBits = 8 * emLength - emBits
    if unusedBits and maskedDB[0] >> (8 - unusedBits):
      raise SignatureError("the RSA-PSS signature does not verify")
    mask = _mgf1(hashName, hashed, len(maskedDB))
    db = bytearray(a ^ b for a, b in zip(maskedDB, mask))
    if unusedBits:
      db[0] &= 0xFF >> unusedBits
    separator = emLength - hashLength - saltLength - 2
    if any(db[:separator]) or db[separator] != 0x01:
      raise SignatureError("the RSA-PSS signature does not verify")
    salt = bytes(db[separator + 1:])
    recomputed = hashlib.new(hashName, b"\x00" * 8 + messageHash + salt).digest()
    if not hmac.compare_digest(recomputed, hashed):
      raise SignatureError("the RSA-PSS signature does not verify")


def _mgf1(hashName: str, seed: bytes, length: int) -> bytes:
  output = b""
  counter = 0
  while len(output) < length:
    output += hashlib.new(hashName, seed + counter.to_bytes(4, "big")).digest()
    counter += 1
  return output[:length]


@dataclass(frozen=True)
class Curve:
  name: str
  prime: int
  a: int
  b: int
  gx: int
  gy: int
  order: int

  @property
  def length(self) -> int:
    return (self.prime.bit_length() + 7) // 8


# The NIST curves' domain parameters, as RFC 5903 section 3 prints them.
curves = {
  curve.name: curve for curve in (
    Curve(
      "P-256",
      int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16),
      int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16) - 3,
      int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
      int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
      int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
      int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
    ),
    Curve(
      "P-384",
      int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16),
      int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16) - 3,
      int("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16),
      int("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
      int("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16),
      int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
    ),
    Curve(
      "P-521",
      int("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16),
      int("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) - 3,
      int("51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16),
      int("C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
      int("11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16),
      int("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
    ),
  )
}


def _add(curve: Curve, first: tuple[int, int] | None, second: tuple[int, int] | None) -> tuple[int, int] | None:
  if first is None:
    return second
  if second is None:
    return first
  (x1, y1), (x2, y2) = first, second
  p = curve.prime
  if x1 == x2 and (y1 + y2) % p == 0:
    return None
  if first == second:
    slope = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, p) % p
  else:
    slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
  x3 = (slope * slope - x1 - x2) % p
  return x3, (slope * (x1 - x3) - y1) % p


def _multiply(curve: Curve, scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
  result = None
  addend: tuple[int, int] | None = point
  while scalar:
    if scalar & 1:
      result = _add(curve, result, addend)
    addend = _add(curve, addend, addend)
    scalar >>= 1
  return result


@dataclass(frozen=True)
class ECPublicKey:
  curveName: str
  x: int
  y: int

  def __post_init__(self) -> None:
    if self.curveName not in curves:
      raise SignatureError(f"curve '{self.curveName}' is not one of {sorted(curves)}")
    curve = curves[self.curveName]
    if not (0 <= self.x < curve.prime and 0 <= self.y < curve.prime):
      raise SignatureError("the EC public point is out of range")
    if (self.y * self.y - (self.x ** 3 + curve.a * self.x + curve.b)) % curve.prime:
      raise SignatureError(f"the EC public point is not on {self.curveName}")

  def verify(self, message: bytes, r: int, s: int, hashName: str) -> None:
    """ECDSA verification (SEC 1 section 4.1.4); the hash is truncated to the order's length."""
    curve = curves[self.curveName]
    n = curve.order
    if not (1 <= r < n and 1 <= s < n):
      raise SignatureError("the ECDSA signature is out of range")
    digest = _hash(hashName, message)
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - n.bit_length()
    if excess > 0:
      e >>= excess
    w = pow(s, -1, n)
    point = _add(curve, _multiply(curve, e * w % n, (curve.gx, curve.gy)),
                 _multiply(curve, r * w % n, (self.x, self.y)))
    if point is None or point[0] % n != r:
      raise SignatureError("the ECDSA signature does not verify")

  def verifyRaw(self, message: bytes, signature: bytes, hashName: str) -> None:
    """A signature as JOSE writes it: r then s, each the curve's length (RFC 7518 section 3.4)."""
    size = curves[self.curveName].length
    if len(signature) != 2 * size:
      raise SignatureError(f"an ECDSA signature on {self.curveName} is {2 * size} bytes, got {len(signature)}")
    self.verify(message, int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"), hashName)
