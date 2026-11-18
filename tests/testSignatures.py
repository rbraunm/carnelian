# SPDX-License-Identifier: MIT
"""Signature verification and key reading, checked against OpenSSL through `cryptography`."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from carnelian.der import DERError, publicKeyFromCertificate, publicKeyFromInfo, readElement
from carnelian.signatures import ECPublicKey, RSAPublicKey, SignatureError

message = b"the plot values of trial 42"
hashesByName = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}


def rsaKey(bits):
  private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
  numbers = private.public_key().public_numbers()
  return private, RSAPublicKey(numbers.n, numbers.e)


@pytest.mark.parametrize("bits", [2048, 3072, 4096])
@pytest.mark.parametrize("hashName", ["sha256", "sha384", "sha512"])
def testPKCS1v15SignaturesFromOpenSSLVerify(bits, hashName):
  private, public = rsaKey(bits)
  signature = private.sign(message, padding.PKCS1v15(), hashesByName[hashName])
  public.verifyPKCS1v15(message, signature, hashName)
  with pytest.raises(SignatureError, match="does not verify"):
    public.verifyPKCS1v15(message + b".", signature, hashName)
  with pytest.raises(SignatureError, match="does not verify"):
    public.verifyPKCS1v15(message, signature, "sha512" if hashName != "sha512" else "sha256")


@pytest.mark.parametrize("bits", [2048, 2049, 3072])
@pytest.mark.parametrize("hashName", ["sha256", "sha384"])
def testPSSSignaturesFromOpenSSLVerify(bits, hashName):
  private, public = rsaKey(bits)
  saltLength = hashesByName[hashName].digest_size
  signature = private.sign(message, padding.PSS(mgf=padding.MGF1(hashesByName[hashName]), salt_length=saltLength),
                           hashesByName[hashName])
  public.verifyPSS(message, signature, hashName, saltLength)
  with pytest.raises(SignatureError, match="does not verify"):
    public.verifyPSS(message + b".", signature, hashName, saltLength)
  with pytest.raises(SignatureError, match="does not verify"):
    public.verifyPSS(message, signature, hashName, saltLength - 1)


def testRSAKeysAndSignaturesOutOfBoundsAreRefused():
  small = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
  with pytest.raises(SignatureError, match="an RSA key of 1024 bits is refused"):
    RSAPublicKey(small.n, small.e)
  _, public = rsaKey(2048)
  with pytest.raises(SignatureError, match="is 256 bytes, got 255"):
    public.verifyPKCS1v15(message, b"\x01" * 255, "sha256")
  with pytest.raises(SignatureError, match="not below the modulus"):
    public.verifyPKCS1v15(message, b"\xff" * 256, "sha256")
  with pytest.raises(SignatureError, match="hash 'md5' is not one of"):
    public.verifyPKCS1v15(message, b"\x01" * 256, "md5")


@pytest.mark.parametrize("curve, curveName, hashName", [
  (ec.SECP256R1(), "P-256", "sha256"), (ec.SECP384R1(), "P-384", "sha384"), (ec.SECP521R1(), "P-521", "sha512"),
  (ec.SECP256R1(), "P-256", "sha512"),
])
def testECDSASignaturesFromOpenSSLVerify(curve, curveName, hashName):
  private = ec.generate_private_key(curve)
  numbers = private.public_key().public_numbers()
  public = ECPublicKey(curveName, numbers.x, numbers.y)
  for _ in range(5):
    r, s = decode_dss_signature(private.sign(message, ec.ECDSA(hashesByName[hashName])))
    public.verify(message, r, s, hashName)
    with pytest.raises(SignatureError, match="does not verify"):
      public.verify(message + b".", r, s, hashName)
  with pytest.raises(SignatureError, match="out of range"):
    public.verify(message, 0, s, hashName)


def testAPointOffTheCurveIsRefused():
  numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
  with pytest.raises(SignatureError, match="not on P-256"):
    ECPublicKey("P-256", numbers.x, numbers.y + 1)
  with pytest.raises(SignatureError, match="curve 'P-192' is not one of"):
    ECPublicKey("P-192", numbers.x, numbers.y)


def certificate(private):
  name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "identity provider")])
  start = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
  return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(start)
          .not_valid_after(start + datetime.timedelta(days=365)).sign(private, hashes.SHA256()))


@pytest.mark.parametrize("private", [
  rsa.generate_private_key(public_exponent=65537, key_size=2048),
  ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP521R1()),
], ids=["rsa2048", "p256", "p384", "p521"])
def testKeysAreReadFromCertificatesAndKeyInfo(private):
  made = certificate(private)
  numbers = private.public_key().public_numbers()
  expected = (numbers.n, numbers.e) if isinstance(private, rsa.RSAPrivateKey) else (numbers.x, numbers.y)
  for source in (made.public_bytes(serialization.Encoding.DER), made.public_bytes(serialization.Encoding.PEM).decode()):
    key = publicKeyFromCertificate(source)
    found = (key.modulus, key.exponent) if isinstance(key, RSAPublicKey) else (key.x, key.y)
    assert found == expected
  info = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
  assert publicKeyFromInfo(info) == publicKeyFromCertificate(made.public_bytes(serialization.Encoding.DER))


@pytest.mark.parametrize("data, message", [
  (bytes.fromhex("3080"), "indefinite lengths are not DER"),
  (bytes.fromhex("30810100"), "not minimally encoded"),
  (bytes.fromhex("3005020100"), "truncated DER content"),
])
def testOnlyStrictDERIsRead(data, message):
  with pytest.raises(DERError, match=message):
    readElement(data)
