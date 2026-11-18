# SPDX-License-Identifier: MIT
"""Just enough DER (X.690) to read public keys: SubjectPublicKeyInfo and X.509 certificates.

Strict DER only: definite, minimally encoded lengths, and nothing left over where a
structure ends. Keys are RSA or EC on P-256, P-384 and P-521 with uncompressed points.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from carnelian.signatures import ECPublicKey, RSAPublicKey, curves


class DERError(ValueError):
  """Bytes that are not the strict DER expected here."""


@dataclass(frozen=True)
class Element:
  tag: int
  content: bytes


def readElement(data: bytes, offset: int = 0) -> tuple[Element, int]:
  """One TLV at `offset`; returns it and the offset just past it."""
  if offset + 2 > len(data):
    raise DERError("truncated DER element")
  tag = data[offset]
  if tag & 0x1F == 0x1F:
    raise DERError("multi-byte DER tags are not used here")
  first = data[offset + 1]
  position = offset + 2
  if first < 0x80:
    length = first
  else:
    count = first & 0x7F
    if count == 0:
      raise DERError("indefinite lengths are not DER")
    if count > 4 or position + count > len(data):
      raise DERError("DER length out of range")
    length = int.from_bytes(data[position:position + count], "big")
    if length < 0x80 or data[position] == 0:
      raise DERError("DER length is not minimally encoded")
    position += count
  end = position + length
  if end > len(data):
    raise DERError("truncated DER content")
  return Element(tag, data[position:end]), end


def readAll(data: bytes) -> list[Element]:
  """Every element of a constructed value's content, which must be used up exactly."""
  elements, offset = [], 0
  while offset < len(data):
    element, offset = readElement(data, offset)
    elements.append(element)
  return elements


def readOne(data: bytes) -> Element:
  element, end = readElement(data)
  if end != len(data):
    raise DERError("bytes left after the DER value")
  return element


def _expect(element: Element, tag: int, what: str) -> Element:
  if element.tag != tag:
    raise DERError(f"{what}: expected tag 0x{tag:02x}, got 0x{element.tag:02x}")
  return element


def readInteger(element: Element) -> int:
  _expect(element, 0x02, "INTEGER")
  content = element.content
  if not content or (len(content) > 1 and ((content[0] == 0 and content[1] < 0x80) or (content[0] == 0xFF and content[1] >= 0x80))):
    raise DERError("INTEGER is not minimally encoded")
  return int.from_bytes(content, "big", signed=True)


# Wide enough for the UUID arcs under 2.25.
maximumOIDComponentBits = 128


def readOID(element: Element) -> str:
  content = _expect(element, 0x06, "OBJECT IDENTIFIER").content
  if not content:
    raise DERError("empty OBJECT IDENTIFIER")
  values, current = [], 0
  for index, byte in enumerate(content):
    if current == 0 and byte == 0x80:
      raise DERError("OBJECT IDENTIFIER is not minimally encoded")
    current = (current << 7) | (byte & 0x7F)
    if current.bit_length() > maximumOIDComponentBits:
      raise DERError(f"an OBJECT IDENTIFIER component is longer than {maximumOIDComponentBits} bits")
    if not byte & 0x80:
      values.append(current)
      current = 0
    elif index == len(content) - 1:
      raise DERError("truncated OBJECT IDENTIFIER")
  first = min(values[0] // 40, 2)
  return ".".join(str(part) for part in [first, values[0] - 40 * first, *values[1:]])


def readBitString(element: Element) -> bytes:
  content = _expect(element, 0x03, "BIT STRING").content
  if not content or content[0] != 0:
    raise DERError("a key's BIT STRING has whole bytes")
  return content[1:]


rsaEncryption = "1.2.840.113549.1.1.1"
ecPublicKey = "1.2.840.10045.2.1"
curveForOID = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521"}


def publicKeyFromInfo(info: bytes) -> RSAPublicKey | ECPublicKey:
  """The key in a DER SubjectPublicKeyInfo."""
  elements = readAll(_expect(readOne(info), 0x30, "SubjectPublicKeyInfo").content)
  if len(elements) != 2:
    raise DERError("a SubjectPublicKeyInfo has two parts")
  parts = readAll(_expect(elements[0], 0x30, "AlgorithmIdentifier").content)
  if not 1 <= len(parts) <= 2:
    raise DERError(f"an AlgorithmIdentifier has an algorithm and at most one parameter, not {len(parts)} parts")
  kind = readOID(parts[0])
  keyBytes = readBitString(elements[1])
  if kind == rsaEncryption:
    if len(parts) == 2 and parts[1] != Element(0x05, b""):
      raise DERError("rsaEncryption's parameters are NULL or absent")
    numbers = readAll(_expect(readOne(keyBytes), 0x30, "RSAPublicKey").content)
    if len(numbers) != 2:
      raise DERError("an RSAPublicKey has two integers")
    return RSAPublicKey(readInteger(numbers[0]), readInteger(numbers[1]))
  if kind == ecPublicKey:
    if len(parts) != 2:
      raise DERError("an ecPublicKey AlgorithmIdentifier names its curve")
    curveOID = readOID(parts[1])
    if curveOID not in curveForOID:
      raise DERError(f"EC curve {curveOID} is not supported")
    curveName = curveForOID[curveOID]
    size = curves[curveName].length
    if len(keyBytes) != 1 + 2 * size or keyBytes[0] != 0x04:
      raise DERError("an EC public point is uncompressed (0x04, then x and y)")
    return ECPublicKey(curveName, int.from_bytes(keyBytes[1:1 + size], "big"), int.from_bytes(keyBytes[1 + size:], "big"))
  raise DERError(f"public key algorithm {kind} is not supported")


def subjectPublicKeyInfo(certificate: bytes) -> bytes:
  """The SubjectPublicKeyInfo of a DER X.509 certificate, as DER."""
  outer = readAll(_expect(readOne(certificate), 0x30, "Certificate").content)
  if len(outer) != 3:
    raise DERError("a Certificate has three parts")
  fields = readAll(_expect(outer[0], 0x30, "TBSCertificate").content)
  if fields and fields[0].tag == 0xA0:
    fields = fields[1:]
  if len(fields) < 6:
    raise DERError("TBSCertificate is too short")
  info = _expect(fields[5], 0x30, "SubjectPublicKeyInfo")
  return bytes([0x30]) + _length(len(info.content)) + info.content


def _length(length: int) -> bytes:
  if length < 0x80:
    return bytes([length])
  body = length.to_bytes((length.bit_length() + 7) // 8, "big")
  return bytes([0x80 | len(body)]) + body


_pemBlock = re.compile(r"-----BEGIN ([A-Z ]+)-----\s*(.*?)\s*-----END \1-----", re.S)


def fromPEM(text: str, label: str) -> bytes:
  """The DER inside the one PEM block with this label."""
  blocks = [(found, body) for found, body in _pemBlock.findall(text) if found == label]
  if len(blocks) != 1:
    raise DERError(f"expected one PEM block '{label}', found {len(blocks)}")
  try:
    return base64.b64decode("".join(blocks[0][1].split()), validate=True)
  except ValueError as error:
    raise DERError(f"the PEM block '{label}' is not base64: {error}") from None


def publicKeyFromCertificate(certificate: bytes | str) -> RSAPublicKey | ECPublicKey:
  """The key of an X.509 certificate given as DER bytes or PEM text."""
  der = fromPEM(certificate, "CERTIFICATE") if isinstance(certificate, str) else certificate
  return publicKeyFromInfo(subjectPublicKeyInfo(der))
