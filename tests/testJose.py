# SPDX-License-Identifier: MIT
"""JSON Web Signatures: RFC 7515's own examples, and tokens signed by OpenSSL."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from carnelian.jose import JOSEError, KeySet, base64urlDecode, base64urlEncode, keyFromJWK, verifyCompact

vectors = json.loads((Path(__file__).parent / "vectors" / "rfc7515.json").read_text(encoding="ascii"))


@pytest.mark.parametrize("vector", vectors, ids=[vector["alg"] for vector in vectors])
def testTheRFCExamplesVerify(vector):
  verified = verifyCompact(vector["jws"], keyFromJWK(vector["jwk"]))
  assert verified.header == {"alg": vector["alg"]}
  if vector["alg"] != "ES512":
    assert json.loads(verified.payload) == {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
  else:
    assert verified.payload == b"Payload"
  header, payload, signature = vector["jws"].split(".")
  tampered = f"{header}.{base64urlEncode(b'{\"iss\":\"eve\"}')}.{signature}"
  with pytest.raises(JOSEError, match="does not verify"):
    verifyCompact(tampered, keyFromJWK(vector["jwk"]))


def signed(header, payload, private):
  signingInput = f"{base64urlEncode(json.dumps(header).encode())}.{base64urlEncode(json.dumps(payload).encode())}"
  algorithm = header["alg"]
  hashFor = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}[algorithm[2:]]
  if algorithm.startswith("RS"):
    signature = private.sign(signingInput.encode(), padding.PKCS1v15(), hashFor)
  elif algorithm.startswith("PS"):
    signature = private.sign(signingInput.encode(), padding.PSS(mgf=padding.MGF1(hashFor), salt_length=hashFor.digest_size), hashFor)
  else:
    r, s = decode_dss_signature(private.sign(signingInput.encode(), ec.ECDSA(hashFor)))
    size = (private.curve.key_size + 7) // 8
    signature = r.to_bytes(size, "big") + s.to_bytes(size, "big")
  return f"{signingInput}.{base64urlEncode(signature)}"


def jwkOf(private, keyID):
  numbers = private.public_key().public_numbers()
  if isinstance(private, rsa.RSAPrivateKey):
    return {"kty": "RSA", "kid": keyID, "n": base64urlEncode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": base64urlEncode(numbers.e.to_bytes(3, "big"))}
  size = (private.curve.key_size + 7) // 8
  return {"kty": "EC", "kid": keyID, "crv": {256: "P-256", 384: "P-384", 521: "P-521"}[private.curve.key_size],
          "x": base64urlEncode(numbers.x.to_bytes(size, "big")), "y": base64urlEncode(numbers.y.to_bytes(size, "big"))}


rsaKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ecKeys = {"ES256": ec.generate_private_key(ec.SECP256R1()), "ES384": ec.generate_private_key(ec.SECP384R1()),
          "ES512": ec.generate_private_key(ec.SECP521R1())}


@pytest.mark.parametrize("algorithm", ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"])
def testEveryAlgorithmFromAKeySet(algorithm):
  private = ecKeys[algorithm] if algorithm.startswith("ES") else rsaKey
  keys = KeySet({"keys": [jwkOf(rsaKey, "r"), jwkOf(ecKeys["ES256"], "e256"), jwkOf(ecKeys["ES384"], "e384"),
                          jwkOf(ecKeys["ES512"], "e512"), {"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": "AA"}]})
  keyID = {"ES256": "e256", "ES384": "e384", "ES512": "e512"}.get(algorithm, "r")
  token = signed({"alg": algorithm, "kid": keyID}, {"sub": "ana"}, private)
  header = json.loads(base64urlDecode(token.split(".")[0]))
  assert json.loads(verifyCompact(token, keys.keyFor(header)).payload) == {"sub": "ana"}


@pytest.mark.parametrize("header, message", [
  ({"alg": "none"}, "algorithm 'none' is refused"),
  ({"alg": "HS256"}, "algorithm 'HS256' is refused"),
  ({"alg": "RS1"}, "algorithm 'RS1' is not one of"),
  ({"alg": "RS256", "crit": ["exp"]}, "critical header extensions"),
  ({"alg": "ES256"}, "algorithm 'ES256' needs a P-256 key"),
])
def testRefusedHeaders(header, message):
  token = f"{base64urlEncode(json.dumps(header).encode())}.{base64urlEncode(b'{}')}.{base64urlEncode(b'x' * 256)}"
  with pytest.raises(JOSEError, match=message):
    verifyCompact(token, keyFromJWK(jwkOf(rsaKey, "r")))


def testAnAllowListNarrowsTheAlgorithms():
  token = signed({"alg": "RS256", "kid": "r"}, {}, rsaKey)
  with pytest.raises(JOSEError, match=r"algorithm 'RS256' is not one of \['ES256'\]"):
    verifyCompact(token, keyFromJWK(jwkOf(rsaKey, "r")), frozenset({"ES256"}))


@pytest.mark.parametrize("text, message", [("YQ==", "not unpadded"), ("YR", "canonical"), ("a+b", "not unpadded")])
def testBase64urlIsStrict(text, message):
  with pytest.raises(JOSEError, match=message):
    base64urlDecode(text)


def testKeysAreChosenStrictly():
  keys = KeySet({"keys": [jwkOf(rsaKey, "a"), jwkOf(rsaKey, "a") | {"use": "enc"}, jwkOf(rsaKey, "b") | {"alg": "PS256"}]})
  assert keys.keyFor({"kid": "a", "alg": "RS256"}) is not None
  with pytest.raises(JOSEError, match="has 0 signing keys with kid 'c'"):
    keys.keyFor({"kid": "c", "alg": "RS256"})
  with pytest.raises(JOSEError, match="key 'b' is for 'PS256', the token uses 'RS256'"):
    keys.keyFor({"kid": "b", "alg": "RS256"})
  with pytest.raises(JOSEError, match=r"private members \['d'\]"):
    keyFromJWK(jwkOf(rsaKey, "a") | {"d": "AQAB"})


smallKey = rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.mark.parametrize("jwk, message", [
  ({"kty": "EC", "crv": "P-256", "x": 5, "y": "AAAA"}, "has no 'x'"),
  ({"kty": "RSA", "n": ["AQAB"], "e": "AQAB"}, "has no 'n'"),
  ({"kty": ["RSA"], "n": "AQAB", "e": "AQAB"}, "has no 'kty' as text"),
  ({"kty": 1, "n": "AQAB", "e": "AQAB"}, "has no 'kty' as text"),
  ({"kty": "EC", "crv": ["P-256"], "x": "AA", "y": "AA"}, "has no 'crv' as text"),
  (jwkOf(smallKey, "s"), "key is refused: an RSA key of 1024 bits"),
  (jwkOf(ecKeys["ES256"], "e") | {"y": base64urlEncode(b"\x01" * 32)}, "key is refused: the EC public point is not on P-256"),
])
def testAJWKMemberOfTheWrongKindIsRefusedByName(jwk, message):
  with pytest.raises(JOSEError, match=message):
    keyFromJWK(jwk)


@pytest.mark.parametrize("header, message", [
  ({"alg": ["RS256"], "kid": "r"}, r"'alg' is not a name: \['RS256'\]"),
  ({"alg": 256, "kid": "r"}, "'alg' is not a name: 256"),
])
def testAnAlgorithmOfTheWrongKindIsRefusedByName(header, message):
  token = f"{base64urlEncode(json.dumps(header).encode())}.{base64urlEncode(b'{}')}.{base64urlEncode(b'x' * 256)}"
  with pytest.raises(JOSEError, match=message):
    verifyCompact(token, keyFromJWK(jwkOf(rsaKey, "r")))


@pytest.mark.parametrize("header, message", [
  ({"kid": ["r"], "alg": "RS256"}, r"'kid' is not text: \['r'\]"),
  ({"kid": 7, "alg": "RS256"}, "'kid' is not text: 7"),
  ({"alg": "RS256"}, r"names no key \('kid'\)"),
])
def testAKeyIDOfTheWrongKindIsRefusedByName(header, message):
  with pytest.raises(JOSEError, match=message):
    KeySet({"keys": [jwkOf(rsaKey, "r")]}).keyFor(header)


@pytest.mark.parametrize("members, chosen", [
  ({"key_ops": ["verify"]}, True), ({"key_ops": ["sign", "verify"]}, True), ({"key_ops": ["encrypt"]}, False),
  ({"key_ops": []}, False), ({"use": "sig"}, True), ({"use": "enc"}, False),
])
def testOnlyAKeyForVerifyingIsChosen(members, chosen):
  keys = KeySet({"keys": [jwkOf(rsaKey, "r") | members]})
  if chosen:
    assert keys.keyFor({"kid": "r", "alg": "RS256"}) == keyFromJWK(jwkOf(rsaKey, "r"))
  else:
    with pytest.raises(JOSEError, match="has 0 signing keys with kid 'r'"):
      keys.keyFor({"kid": "r", "alg": "RS256"})


@pytest.mark.parametrize("members, message", [
  ({"key_ops": "verify"}, "'key_ops' is not a list of names"),
  ({"key_ops": [1]}, "'key_ops' is not a list of names"),
  ({"use": ["sig"]}, "'use' is not text"),
])
def testKeyUsesOfTheWrongKindAreRefusedByName(members, message):
  with pytest.raises(JOSEError, match=message):
    KeySet({"keys": [jwkOf(rsaKey, "r") | members]}).keyFor({"kid": "r", "alg": "RS256"})


def testANonASCIIPayloadSegmentIsRefusedByName():
  header, _, signature = signed({"alg": "RS256", "kid": "r"}, {}, rsaKey).split(".")
  with pytest.raises(JOSEError, match="not unpadded base64url"):
    verifyCompact(f"{header}.e30\u00e9.{signature}", keyFromJWK(jwkOf(rsaKey, "r")))


@pytest.mark.parametrize("headerText, message", [
  ('{"alg": "RS256", "x": NaN}', "NaN is not a JSON number"),
  ('{"alg": "RS256", "x": 1e999}', "too large for a number"),
  ('{"alg": "RS256", "x": ' + "[" * 50_000 + "]" * 50_000 + "}", "nests deeper than 32"),
])
def testAHeaderThatIsNotStrictJSONIsRefusedByName(headerText, message):
  token = f"{base64urlEncode(headerText.encode())}.{base64urlEncode(b'{}')}.{base64urlEncode(b'x' * 256)}"
  with pytest.raises(JOSEError, match=message):
    verifyCompact(token, keyFromJWK(jwkOf(rsaKey, "r")))
