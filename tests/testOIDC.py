# SPDX-License-Identifier: MIT
"""The OpenID Connect relying party: ID token checks with a stand-in network, then a real Keycloak."""

import base64
import dataclasses
import hashlib
import html.parser
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from carnelian.fetching import Fetcher, HTTPFailure, secureContext
from carnelian.jose import base64urlEncode
from carnelian.oidc import Pending, Provider, RelyingParty, SignInRefused, discover, maximumKeyAgeSeconds

issuer = "https://id.example.org/realms/test"


def jwkSetOf(private, keyID="k1"):
  numbers = private.public_key().public_numbers()
  return {"keys": [{"kty": "RSA", "kid": keyID, "use": "sig", "alg": "RS256",
                    "n": base64urlEncode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                    "e": base64urlEncode(numbers.e.to_bytes(3, "big"))}]}


signingKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwks = jwkSetOf(signingKey)


class StandInNetwork(Fetcher):
  """The provider's JWK set, served without a network: a double for the network boundary only."""

  def __init__(self, keySet=jwks):
    super().__init__(secureContext())
    self.keySet = keySet
    self.fetched = 0

  def getJSON(self, url, headers=None):
    assert url == f"{issuer}/keys"
    self.fetched += 1
    return self.keySet


def signedText(payload, header=None, key=signingKey):
  header = header or {"alg": "RS256", "kid": "k1"}
  signingInput = f"{base64urlEncode(json.dumps(header).encode())}.{base64urlEncode(payload.encode())}"
  signature = key.sign(signingInput.encode(), padding.PKCS1v15(), hashes.SHA256())
  return f"{signingInput}.{base64urlEncode(signature)}"


def idToken(claims, header=None, key=signingKey):
  return signedText(json.dumps(claims), header, key)


now = 1_800_000_000


def makeProvider(**changes):
  return dataclasses.replace(Provider(
    issuer=issuer, authorizationEndpoint=f"{issuer}/auth", tokenEndpoint=f"{issuer}/token", jwksURI=f"{issuer}/keys",
    userinfoEndpoint=None, signingAlgorithms=frozenset({"RS256"}), issuerInResponseRequired=False), **changes)


def party(network=None, clock=lambda: now, provider=None):
  return RelyingParty(provider or makeProvider(), "app", "secret", "https://app.example.org/callback",
                      network or StandInNetwork(), clock=clock)


def pendingFor(**changes):
  return dataclasses.replace(
    Pending(issuer=issuer, clientID="app", state="s", nonce="n-1", codeVerifier="v", startedAt=now), **changes)


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
  ({"aud": ["app", 7], "azp": "app"}, "audience is not a name or a list of names"),
  ({"aud": []}, "audience is not a name or a list of names"),
  ({"aud": ""}, "audience is not a name or a list of names"),
  ({"aud": 5}, "audience is not a name or a list of names"),
  ({"exp": now - 61}, "has expired"),
  ({"iat": now + 61}, "issued in the future"),
  ({"nbf": now + 61}, r"not valid yet \('nbf'\)"),
  ({"nbf": "later"}, "'nbf' is not a finite number"),
  ({"nonce": "n-2"}, "nonce does not match"),
  ({"nonce": "n-\u00e9"}, "nonce does not match"),
  ({"nonce": 5}, "no nonce as text"),
  ({"nonce": None}, "no nonce as text"),
  ({"sub": ""}, "names no subject"),
  ({"exp": "soon"}, "'exp' is not a finite number"),
  ({"iat": True}, "'iat' is not a finite number"),
])
def testEachIDTokenCheckRefuses(change, message):
  with pytest.raises(SignInRefused, match=message):
    party().checkIDToken(idToken(good | change), "n-1")


@pytest.mark.parametrize("claimsText, message", [
  ('{"exp": 1e999}', "1e999 is too large for a number"),
  ('{"exp": -1e999}', "-1e999 is too large for a number"),
  ('{"exp": Infinity}', "Infinity is not a JSON number"),
  ('{"iat": NaN}', "NaN is not a JSON number"),
  ('{"a": ' + "[" * 50_000 + "]" * 50_000 + "}", "nested too deeply"),
])
def testClaimsThatAreNotFiniteJSONAreRefused(claimsText, message):
  with pytest.raises(SignInRefused, match=message):
    party().checkIDToken(signedText(claimsText), "n-1")


def testALeewayOfAMinuteIsAllowed():
  assert party().checkIDToken(idToken(good | {"exp": now - 59, "iat": now + 59, "nbf": now + 59}), "n-1")


@pytest.mark.parametrize("header, message", [
  ({"alg": "none", "kid": "k1"}, "algorithm 'none' is refused"),
  ({"alg": "RS256", "kid": "k9"}, "0 signing keys with kid 'k9'"),
  ({"alg": "PS256", "kid": "k1"}, r"algorithm 'PS256' is not one of \['RS256'\]"),
  ({"alg": ["RS256"], "kid": "k1"}, "'alg' is not a name"),
])
def testATokenSignedWrongIsRefused(header, message):
  with pytest.raises(SignInRefused, match=message):
    party().checkIDToken(idToken(good, header), "n-1")


def testAKeyTooSmallInTheKeySetIsASignInRefusal():
  small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
  with pytest.raises(SignInRefused, match="key is refused: an RSA key of 1024 bits"):
    party(StandInNetwork(jwkSetOf(small))).checkIDToken(idToken(good, key=small), "n-1")


def testTheReturnMustMatchThePendingSignIn():
  relyingParty = party()
  with pytest.raises(SignInRefused, match="state does not match"):
    relyingParty.finishSignIn(pendingFor(), {"state": "t", "code": "c"})
  with pytest.raises(SignInRefused, match="state does not match"):
    relyingParty.finishSignIn(pendingFor(), {"state": "\u00e9", "code": "c"})
  with pytest.raises(SignInRefused, match="state does not match"):
    relyingParty.finishSignIn(pendingFor(), {"code": "c"})
  with pytest.raises(SignInRefused, match="the provider refused: no consent"):
    relyingParty.finishSignIn(pendingFor(), {"state": "s", "error": "access_denied", "error_description": "no consent"})
  with pytest.raises(SignInRefused, match="took too long"):
    relyingParty.finishSignIn(pendingFor(startedAt=now - 601), {"state": "s", "code": "c"})


def testTheSignInAddressCarriesPKCEAndTheNonce():
  address, pending = party().beginSignIn()
  query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(address).query))
  assert query["code_challenge_method"] == "S256" and query["state"] == pending.state and query["nonce"] == pending.nonce
  assert query["code_challenge"] == base64.urlsafe_b64encode(hashlib.sha256(pending.codeVerifier.encode()).digest()).rstrip(b"=").decode()
  assert (pending.issuer, pending.clientID) == (issuer, "app")


@pytest.mark.parametrize("change, message", [
  ({"tokenEndpoint": "http://id.example.org/token"}, "token endpoint is not an https URL"),
  ({"authorizationEndpoint": "https:///auth"}, "authorization endpoint is not an https URL"),
  ({"jwksURI": "ftp://id.example.org/keys"}, "JWK set endpoint is not an https URL"),
  ({"userinfoEndpoint": "http://id.example.org/userinfo"}, "userinfo endpoint is not an https URL"),
])
def testAHandMadeProviderMustUseHTTPS(change, message):
  with pytest.raises(SignInRefused, match=message):
    party(provider=makeProvider(**change))


def testAnUnknownKeyCannotMakeEverySignInFetchTheKeysAgain():
  ticks = [now]
  relyingParty = party(clock=lambda: ticks[0])
  for _ in range(5):
    with pytest.raises(SignInRefused, match="kid 'k9'"):
      relyingParty.checkIDToken(idToken(good, {"alg": "RS256", "kid": "k9"}), "n-1")
  assert relyingParty.fetcher.fetched == 1
  ticks[0] = now + 60
  with pytest.raises(SignInRefused, match="kid 'k9'"):
    relyingParty.checkIDToken(idToken(good | {"exp": now + 400}, {"alg": "RS256", "kid": "k9"}), "n-1")
  assert relyingParty.fetcher.fetched == 2


def testAKeyRotatedUnderTheSameKeyIDIsFetchedAgainAtMostOnceAMinute():
  ticks = [now]
  network = StandInNetwork()
  relyingParty = party(network, clock=lambda: ticks[0])
  relyingParty.checkIDToken(idToken(good), "n-1")
  rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  network.keySet = jwkSetOf(rotated)
  with pytest.raises(SignInRefused, match="does not verify"):
    relyingParty.checkIDToken(idToken(good, key=rotated), "n-1")
  assert network.fetched == 1
  ticks[0] = now + 60
  assert relyingParty.checkIDToken(idToken(good, key=rotated), "n-1")["sub"] == "s-1"
  assert network.fetched == 2


def testKeysOlderThanTheirMaximumAgeAreFetchedAgain():
  ticks = [now]
  network = StandInNetwork()
  relyingParty = party(network, clock=lambda: ticks[0])
  lasting = good | {"exp": now + 2 * maximumKeyAgeSeconds}
  relyingParty.checkIDToken(idToken(lasting), "n-1")
  ticks[0] = now + maximumKeyAgeSeconds - 1
  relyingParty.checkIDToken(idToken(lasting), "n-1")
  assert network.fetched == 1
  ticks[0] = now + maximumKeyAgeSeconds
  relyingParty.checkIDToken(idToken(lasting), "n-1")
  assert network.fetched == 2


class StandInProvider(StandInNetwork):
  """A provider's discovery document and token endpoint, served without a network."""

  def __init__(self, document=None, claims=None):
    super().__init__()
    self.document, self.claims = document, claims
    self.posted = 0

  def getJSON(self, url, headers=None):
    if url.endswith("/.well-known/openid-configuration"):
      return self.document
    return super().getJSON(url, headers)

  def postForm(self, url, fields, headers=None):
    assert url == f"{issuer}/token" and fields["code"] == "c"
    self.posted += 1
    return {"id_token": idToken(self.claims)}


discovery = {"issuer": issuer, "authorization_endpoint": f"{issuer}/auth", "token_endpoint": f"{issuer}/token",
             "jwks_uri": f"{issuer}/keys", "id_token_signing_alg_values_supported": ["RS256"]}


@pytest.mark.parametrize("change, message", [
  ({"id_token_signing_alg_values_supported": None}, "is not a list of names"),
  ({"id_token_signing_alg_values_supported": "RS256"}, "is not a list of names"),
  ({"code_challenge_methods_supported": "S256"}, "is not a list of names"),
  ({"code_challenge_methods_supported": ["plain"]}, "does not offer PKCE"),
  ({"token_endpoint": "http://id.example.org/token"}, "not an https URL"),
  ({"authorization_response_iss_parameter_supported": "yes"}, "is not true or false"),
])
def testADiscoveryDocumentThatIsNotWhatTheStandardSaysIsRefused(change, message):
  document = {key: value for key, value in (discovery | change).items() if value is not None}
  with pytest.raises(SignInRefused, match=message):
    discover(issuer, StandInProvider(document))


def testADiscoveryDocumentWithoutPKCEMethodsStillGetsPKCE():
  provider = discover(issuer, StandInProvider(discovery))
  assert provider.signingAlgorithms == frozenset({"RS256"}) and provider.userinfoEndpoint is None
  assert provider.issuerInResponseRequired is False


def testDiscoveryCarriesWhetherTheProviderNamesItselfInItsAnswer():
  document = discovery | {"authorization_response_iss_parameter_supported": True}
  assert discover(issuer, StandInProvider(document)).issuerInResponseRequired is True


def finishing(claims, provider=None):
  network = StandInProvider(claims=claims)
  return party(network, provider=provider), network


def finishedWith(claims):
  relyingParty, _ = finishing(claims)
  return relyingParty.finishSignIn(pendingFor(), {"state": "s", "code": "c"})


def testTheIdentityCarriesTheClaims():
  identity = finishedWith(good | {"preferred_username": "ana", "email": "ana@example.org", "name": "Ana", "groups": ["/a"]})
  assert (identity.subject, identity.userName, identity.email, identity.emailVerified, identity.displayName, identity.groups) == (
    "s-1", "ana", "ana@example.org", False, "Ana", ("/a",))


@pytest.mark.parametrize("verified, expected", [(True, True), (False, False), ("true", False), (1, False)])
def testTheEmailIsVerifiedOnlyWhenTheClaimIsTrue(verified, expected):
  identity = finishedWith(good | {"email": "ana@example.org", "email_verified": verified})
  assert (identity.email, identity.emailVerified) == ("ana@example.org", expected)


@pytest.mark.parametrize("change, message", [
  ({"issuer": "https://other.example.org"}, "begun with 'https://other.example.org' for client 'app'"),
  ({"clientID": "other"}, "for client 'other'"),
])
def testAPendingSignInFromAnotherProviderOrClientIsRefusedBeforeTheCodeIsSent(change, message):
  relyingParty, network = finishing(good)
  with pytest.raises(SignInRefused, match=message):
    relyingParty.finishSignIn(pendingFor(**change), {"state": "s", "code": "c"})
  assert network.posted == 0


def testAnAnswerNamingAnotherIssuerIsRefusedBeforeTheCodeIsSent():
  relyingParty, network = finishing(good)
  with pytest.raises(SignInRefused, match="comes from issuer 'https://evil.example.org'"):
    relyingParty.finishSignIn(pendingFor(), {"state": "s", "code": "c", "iss": "https://evil.example.org"})
  with pytest.raises(SignInRefused, match="comes from issuer"):
    relyingParty.finishSignIn(pendingFor(), {"state": "s", "error": "access_denied", "iss": "https://evil.example.org"})
  assert network.posted == 0
  assert relyingParty.finishSignIn(pendingFor(), {"state": "s", "code": "c", "iss": issuer}).subject == "s-1"


def testAProviderThatAnnouncesItsIssuerInAnswersMustSendIt():
  relyingParty, network = finishing(good, makeProvider(issuerInResponseRequired=True))
  with pytest.raises(SignInRefused, match=r"names itself in its answer \('iss'\)"):
    relyingParty.finishSignIn(pendingFor(), {"state": "s", "code": "c"})
  assert network.posted == 0
  assert relyingParty.finishSignIn(pendingFor(), {"state": "s", "code": "c", "iss": issuer}).subject == "s-1"


@pytest.mark.parametrize("change, message", [
  ({"_claim_names": {"groups": "src1"}, "_claim_sources": {"src1": {"endpoint": "https://graph.example.org"}}},
   "left the groups out"),
  ({"name": 5}, "'name' is not text"),
  ({"preferred_username": ["ana"]}, "'preferred_username' is not text"),
  ({"groups": "/a"}, "not a list of names"),
])
def testAGroupsOverageOrClaimsOfTheWrongKindAreRefused(change, message):
  with pytest.raises(SignInRefused, match=message):
    finishedWith(good | change)


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


@pytest.mark.parametrize("userName", ["ana", "jose", "layla", "wei", "\u0645\u0631\u064a\u0645", "manygroups"])
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
