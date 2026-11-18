# SPDX-License-Identifier: MIT
"""Operations with a private key, behind a small interface, and one backend for it on pyca/cryptography.

This is the only module that imports `cryptography`, installed with the `carnelian[keys]` extra;
nothing else in Carnelian imports this module, so an application that never builds a key never
loads it. The interface is three operations, so that a hardware or cloud key service can stand
in for the backend here:

- `SigningKey.sign`: a signature over bytes (the SAML Redirect binding signs its query string).
- `DecryptionKey.unwrapKey`: RSA-OAEP decryption of a content key, with the OAEP digest and the
  MGF1 digest named separately, as XML Encryption names them.
- `DecryptionKey.decryptContent`: AES-GCM or AES-CBC decryption of the content with that key.

A key used to sign is never used to decrypt: give each its own key pair. Every decryption
failure, of the key or of the content, raises the same `DecryptionFailed` with the same
message, whatever went wrong.
"""

from __future__ import annotations

from typing import Protocol

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["SigningKey", "DecryptionKey", "DecryptionFailed", "LocalSigningKey", "LocalDecryptionKey",
           "rsaSHA256", "rsaSHA384", "rsaSHA512", "ecdsaSHA256", "ecdsaSHA384", "ecdsaSHA512"]

rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
rsaSHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
rsaSHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
ecdsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
ecdsaSHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
ecdsaSHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

minimumRSABits = 2048

_hashes: dict[str, type[hashes.HashAlgorithm]] = {
  "sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512,
}
_signatureAlgorithms: dict[str, tuple[str, type[hashes.HashAlgorithm]]] = {
  rsaSHA256: ("rsa", hashes.SHA256), rsaSHA384: ("rsa", hashes.SHA384), rsaSHA512: ("rsa", hashes.SHA512),
  ecdsaSHA256: ("ecdsa", hashes.SHA256), ecdsaSHA384: ("ecdsa", hashes.SHA384), ecdsaSHA512: ("ecdsa", hashes.SHA512),
}
_curves = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
_contentKeyLengths = {"aes128-gcm": 16, "aes256-gcm": 32, "aes128-cbc": 16, "aes256-cbc": 32}
_gcmIVLength = 12
_gcmTagLength = 16
_blockLength = 16
_doesNotDecrypt = "this does not decrypt with this key"


class SigningKey(Protocol):
  """A private key that signs, held here or in a key service."""

  @property
  def certificate(self) -> bytes:
    """The key's X.509 certificate, DER, as published in metadata."""

  @property
  def signatureAlgorithm(self) -> str:
    """The XML-DSig URI of the signatures this key makes (rsaSHA256 and the others above)."""

  def sign(self, data: bytes) -> bytes:
    """The signature over `data` in the XML-DSig form of signatureAlgorithm (ECDSA: r then s, each the curve's length)."""


class DecryptionKey(Protocol):
  """An RSA private key that unwraps content keys, held here or in a key service, and the AES that uses them."""

  @property
  def certificate(self) -> bytes:
    """The key's X.509 certificate, DER, as published in metadata."""

  def unwrapKey(self, wrappedKey: bytes, oaepDigest: str, maskDigest: str) -> bytes:
    """The content key RSA-OAEP decrypts from `wrappedKey`, with no label; digests are sha1, sha256, sha384 or sha512.
    Any failure raises ValueError, the same for every cause."""

  def decryptContent(self, algorithm: str, contentKey: bytes, cipherData: bytes) -> bytes:
    """The plaintext of XML Encryption cipher data: aes128-gcm or aes256-gcm (a 12-byte IV, the ciphertext, a
    16-byte tag) or aes128-cbc or aes256-cbc (a 16-byte IV, the ciphertext, XML Encryption padding).
    Any failure raises ValueError, the same for every cause."""


class DecryptionFailed(ValueError):
  """Something that does not decrypt; deliberately the same for every cause."""


def _text(value: str | bytes) -> bytes:
  return value.encode("ascii") if isinstance(value, str) else value


def _loaded(privateKeyPEM: str | bytes, certificatePEM: str | bytes,
            password: bytes | None) -> tuple[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, x509.Certificate]:
  privateKey = serialization.load_pem_private_key(_text(privateKeyPEM), password=password)
  certificate = x509.load_pem_x509_certificate(_text(certificatePEM))
  if isinstance(privateKey, rsa.RSAPrivateKey):
    if privateKey.key_size < minimumRSABits:
      raise ValueError(f"an RSA key of {privateKey.key_size} bits is refused; at least {minimumRSABits}")
    certified = certificate.public_key()
    if not isinstance(certified, rsa.RSAPublicKey) or certified.public_numbers() != privateKey.public_key().public_numbers():
      raise ValueError("the certificate is not for this private key")
    return privateKey, certificate
  if isinstance(privateKey, ec.EllipticCurvePrivateKey):
    if not isinstance(privateKey.curve, _curves):
      raise ValueError(f"EC curve {privateKey.curve.name} is refused; P-256, P-384 or P-521")
    certified = certificate.public_key()
    if not isinstance(certified, ec.EllipticCurvePublicKey) or certified.public_numbers() != privateKey.public_key().public_numbers():
      raise ValueError("the certificate is not for this private key")
    return privateKey, certificate
  raise ValueError(f"a {type(privateKey).__name__} is refused; RSA or EC keys only")


class LocalSigningKey:
  """A SigningKey from a PEM private key (PKCS #8 or traditional, encrypted when `password` is given) and its certificate."""

  def __init__(self, privateKeyPEM: str | bytes, certificatePEM: str | bytes, signatureAlgorithm: str = rsaSHA256,
               password: bytes | None = None) -> None:
    if signatureAlgorithm not in _signatureAlgorithms:
      raise ValueError(f"signature algorithm {signatureAlgorithm} is not supported; one of {sorted(_signatureAlgorithms)}")
    self._key, certificate = _loaded(privateKeyPEM, certificatePEM, password)
    kind = _signatureAlgorithms[signatureAlgorithm][0]
    if (kind == "rsa") != isinstance(self._key, rsa.RSAPrivateKey):
      raise ValueError(f"signature algorithm {signatureAlgorithm} does not suit a {type(self._key).__name__}")
    self._certificate = certificate.public_bytes(serialization.Encoding.DER)
    self._signatureAlgorithm = signatureAlgorithm

  @property
  def certificate(self) -> bytes:
    return self._certificate

  @property
  def signatureAlgorithm(self) -> str:
    return self._signatureAlgorithm

  def sign(self, data: bytes) -> bytes:
    digest = _signatureAlgorithms[self._signatureAlgorithm][1]()
    if isinstance(self._key, rsa.RSAPrivateKey):
      return self._key.sign(data, padding.PKCS1v15(), digest)
    r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(digest)))
    length = (self._key.curve.key_size + 7) // 8
    return r.to_bytes(length, "big") + s.to_bytes(length, "big")


class LocalDecryptionKey:
  """A DecryptionKey from a PEM RSA private key (encrypted when `password` is given) and its certificate."""

  def __init__(self, privateKeyPEM: str | bytes, certificatePEM: str | bytes, password: bytes | None = None) -> None:
    key, certificate = _loaded(privateKeyPEM, certificatePEM, password)
    if not isinstance(key, rsa.RSAPrivateKey):
      raise ValueError("a decryption key is RSA (XML Encryption's RSA-OAEP key transport)")
    self._key = key
    self._certificate = certificate.public_bytes(serialization.Encoding.DER)

  @property
  def certificate(self) -> bytes:
    return self._certificate

  def unwrapKey(self, wrappedKey: bytes, oaepDigest: str, maskDigest: str) -> bytes:
    if oaepDigest not in _hashes or maskDigest not in _hashes:
      raise ValueError(f"OAEP digests are {sorted(_hashes)}, not {oaepDigest!r} and {maskDigest!r}")
    try:
      return self._key.decrypt(wrappedKey, padding.OAEP(mgf=padding.MGF1(_hashes[maskDigest]()),
                                                        algorithm=_hashes[oaepDigest](), label=None))
    except ValueError:
      raise DecryptionFailed(_doesNotDecrypt) from None

  def decryptContent(self, algorithm: str, contentKey: bytes, cipherData: bytes) -> bytes:
    if algorithm not in _contentKeyLengths:
      raise ValueError(f"content algorithm {algorithm!r} is not one of {sorted(_contentKeyLengths)}")
    if len(contentKey) != _contentKeyLengths[algorithm]:
      raise DecryptionFailed(_doesNotDecrypt)
    if algorithm.endswith("-gcm"):
      if len(cipherData) < _gcmIVLength + _gcmTagLength:
        raise DecryptionFailed(_doesNotDecrypt)
      try:
        return AESGCM(contentKey).decrypt(cipherData[:_gcmIVLength], cipherData[_gcmIVLength:], None)
      except InvalidTag:
        raise DecryptionFailed(_doesNotDecrypt) from None
    if len(cipherData) < 2 * _blockLength or len(cipherData) % _blockLength:
      raise DecryptionFailed(_doesNotDecrypt)
    decryptor = Cipher(algorithms.AES(contentKey), modes.CBC(cipherData[:_blockLength])).decryptor()
    padded = decryptor.update(cipherData[_blockLength:]) + decryptor.finalize()
    if not 1 <= padded[-1] <= _blockLength:
      raise DecryptionFailed(_doesNotDecrypt)
    return padded[:-padded[-1]]
