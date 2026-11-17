# SPDX-License-Identifier: MIT
"""The OpenID Connect relying party: ID token checks with a stand-in network, then a real Keycloak."""

import html.parser
import http.cookiejar
import json
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from carnelian.fetching import Fetcher, HTTPFailure, secureContext
from carnelian.jose import base64urlEncode
from carnelian.oidc import Pending, Provider, RelyingParty, SignInRefused, discover

issuer = "https://id.example.org/realms/test"
signingKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
numbers = signingKey.public_key().public_numbers()
jwks = {"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
                  "n": base64urlEncode(numbers.n.to_bytes(256, "big")), "e": base64urlEncode(numbers.e.to_bytes(3, "big"))}]}


class StandInNetwork(Fetcher):
  """The provider's JWK set, served without a network: a double for the network boundary only."""

  def __init__(self):
    super().__init__(secureContext())
    self.fetched = 0

  def getJSON(self, url, headers=None):
    assert url == f"{issuer}/keys"
    self.fetched += 1
    return jwks


def idToken(claims, header=None):
  header = header or {"alg": "RS256", "kid": "k1"}
  signingInput = f"{base64urlEncode(json.dumps(header).encode())}.{base64urlEncode(json.dumps(claims).encode())}"
  signature = signingKey.sign(signingInput.encode(), padding.PKCS1v15(), hashes.SHA256())
  return f"{signingInput}.{base64urlEncode(signature)}"


now = 1_800_000_000


def party():
  provider = Provider(issuer=issuer, authorizationEndpoint=f"{issuer}/auth", tokenEndpoint=f"{issuer}/token",
                      jwksURI=f"{issuer}/keys", userinfoEndpoint=None, signingAlgorithms=frozenset({"RS256"}))
  return RelyingParty(provider, "app", "secret", "https://app.example.org/callback", StandInNetwork(), clock=lambda: now)


good = {"iss": issuer, "aud": "app", "sub": "s-1", "exp": now + 300, "iat": now - 5, "nonce": "n-1"}


def testAGoodIDTokenPassesAndKeysAreFetchedOnce():
  relyingParty = party()
  assert relyingParty.checkIDToken(idToken(good), "n-1")["sub"] == "s-1"
  relyingParty.checkIDToken(idToken(good), "n-1")
  assert relyingParty.fetcher.fetched == 1


@pytest.mark.parametrize("change, message", [
  ({"iss": "https://evil.example.org"}, "issuer 'https://evil.example.org' is not"),
  ({"aud": "other"}, "not for client 'app'"),
  ({"aud": ["app", "other"]}, "authorized party is None"),
  ({"azp": "other"}, "authorized party is 'other'"),
  ({"exp": now - 61}, "has expired"),
  ({"iat": now + 61}, "issued in the future"),
  ({"nonce": "n-2"}, "nonce does not match"),
  ({"sub": ""}, "names no subject"),
  ({"exp": "soon"}, "no numeric 'exp'"),
])
def testEachIDTokenCheckRefuses(change, message):
  with pytest.raises(SignInRefused, match=message):
    party().checkIDToken(idToken(good | change), "n-1")


def testALeewayOfAMinuteIsAllowed():
  assert party().checkIDToken(idToken(good | {"exp": now - 59, "iat": now + 59}), "n-1")


@pytest.mark.parametrize("header, message", [
  ({"alg": "none", "kid": "k1"}, "algorithm 'none' is refused"),
  ({"alg": "RS256", "kid": "k9"}, "0 signing keys with kid 'k9'"),
  ({"alg": "PS256", "kid": "k1"}, r"algorithm 'PS256' is not one of \['RS256'\]"),
])
def testATokenSignedWrongIsRefused(header, message):
  with pytest.raises(SignInRefused, match=message):
    party().checkIDToken(idToken(good, header), "n-1")


def testTheReturnMustMatchThePendingSignIn():
  relyingParty = party()
  pending = Pending(state="s", nonce="n-1", codeVerifier="v", startedAt=now)
  with pytest.raises(SignInRefused, match="state does not match"):
    relyingParty.finishSignIn(pending, {"state": "t", "code": "c"})
  with pytest.raises(SignInRefused, match="the provider refused: no consent"):
    relyingParty.finishSignIn(pending, {"state": "s", "error": "access_denied", "error_description": "no consent"})
  stale = Pending(state="s", nonce="n-1", codeVerifier="v", startedAt=now - 601)
  with pytest.raises(SignInRefused, match="took too long"):
    relyingParty.finishSignIn(stale, {"state": "s", "code": "c"})


def testTheSignInAddressCarriesPKCEAndTheNonce():
  address, pending = party().beginSignIn()
  query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(address).query))
  assert query["code_challenge_method"] == "S256" and query["state"] == pending.state and query["nonce"] == pending.nonce
  import base64
  import hashlib
  assert query["code_challenge"] == base64.urlsafe_b64encode(hashlib.sha256(pending.codeVerifier.encode()).digest()).rstrip(b"=").decode()


# ---- against the testbed's Keycloak ----------------------------------------

class _Form(html.parser.HTMLParser):
  def __init__(self):
    super().__init__()
    self.action = None

  def handle_starttag(self, tag, attributes):
    attributes = dict(attributes)
    if tag == "form" and attributes.get("id") == "kc-form-login":
      self.action = attributes["action"]


class _Stop(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, request, fp, code, message, headers, newURL):
    raise urllib.error.HTTPError(newURL, code, message, headers, fp)


def signInAtKeycloak(address, userName, password, context):
  """What a person does in the browser: open the address, fill in the form; returns the query sent back."""
  opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                       urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _Stop())
  form = _Form()
  with opener.open(address, timeout=20) as response:
    form.feed(response.read().decode("utf-8"))
  assert form.action, "Keycloak's login form was not found"
  data = urllib.parse.urlencode({"username": userName, "password": password, "credentialId": ""}).encode()
  try:
    with opener.open(urllib.request.Request(form.action, data=data, method="POST"), timeout=20) as response:
      return None, response.read().decode("utf-8")
  except urllib.error.HTTPError as redirect:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect.url).query)), None


@pytest.fixture(scope="module")
def keycloak(testbed):
  fetcher = Fetcher(secureContext(testbed["certificateAuthority"]))
  settings = testbed["openIDConnect"]
  provider = discover(settings["issuer"], fetcher)
  return RelyingParty(provider, settings["clientID"], settings["clientSecret"], settings["redirectURI"], fetcher), fetcher


def account(testbed, userName):
  return next(account for account in testbed["accounts"] if account["userName"] == userName)


@pytest.mark.parametrize("userName", ["ana", "jose", "layla", "wei", "manygroups"])
def testEveryoneInTheDatasetSignsIn(testbed, keycloak, userName):
  relyingParty, fetcher = keycloak
  expected = account(testbed, userName)
  address, pending = relyingParty.beginSignIn()
  query, page = signInAtKeycloak(address, userName, expected["password"], fetcher.context)
  assert query is not None, page[:500]
  identity = relyingParty.finishSignIn(pending, query)
  assert identity.userName == userName
  assert identity.displayName == f"{expected['firstName']} {expected['lastName']}"
  assert identity.email == expected["email"]
  assert sorted(identity.groups) == sorted(expected["groups"])
  with pytest.raises((SignInRefused, HTTPFailure)):
    relyingParty.finishSignIn(pending, query)


def testADisabledAccountDoesNotSignIn(testbed, keycloak):
  relyingParty, fetcher = keycloak
  address, _ = relyingParty.beginSignIn()
  query, page = signInAtKeycloak(address, "disabled", account(testbed, "disabled")["password"], fetcher.context)
  assert query is None and "disabled" in page.lower()


def testAWrongPasswordDoesNotSignIn(testbed, keycloak):
  relyingParty, fetcher = keycloak
  address, _ = relyingParty.beginSignIn()
  query, _ = signInAtKeycloak(address, "ana", "not the password", fetcher.context)
  assert query is None


def testTheDiscoveryDocumentIsTheProvidersOwn(testbed, keycloak):
  relyingParty, fetcher = keycloak
  assert relyingParty.provider.issuer == testbed["openIDConnect"]["issuer"]
  with pytest.raises(SignInRefused, match="discovery document names issuer"):
    discover(testbed["openIDConnect"]["issuer"] + "/", fetcher)
