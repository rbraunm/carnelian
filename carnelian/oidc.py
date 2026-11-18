# SPDX-License-Identifier: MIT
"""An OpenID Connect relying party: the authorization-code flow with PKCE (OpenID Connect Core 1.0).

Sign-in has two halves. `beginSignIn` gives the address to send the person to and a
Pending record the application keeps server-side; `finishSignIn` takes that record and the
query the provider sent back, exchanges the code, and returns the Identity once the ID
token passes every check of Core section 3.1.3.7: signature by a key from the provider's
JWK set, issuer, audience and authorized party, an accepted algorithm, expiry and issue
time (with a small leeway), and the nonce. The state is compared in constant time, a
pending sign-in expires, and a provider error is raised with its own words.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from carnelian.fetching import JSON, JSONFetcher
from carnelian.jose import JOSEError, KeySet, acceptedAlgorithm, readHeader, supportedAlgorithms, verifyCompact

__all__ = ["SignInRefused", "Provider", "discover", "Pending", "Identity", "RelyingParty"]

minimumKeyRefreshSeconds = 60


class SignInRefused(ValueError):
  """A sign-in that did not complete, with why."""


@dataclass(frozen=True)
class Provider:
  issuer: str
  authorizationEndpoint: str
  tokenEndpoint: str
  jwksURI: str
  userinfoEndpoint: str | None
  signingAlgorithms: frozenset[str]


def _names(document: JSON, member: str) -> list[str]:
  value = document.get(member)
  if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
    raise SignInRefused(f"the provider's '{member}' is not a list of names: {value!r}")
  return value


def _optionalText(claims: JSON, name: str) -> str | None:
  value = claims.get(name)
  if value is not None and not isinstance(value, str):
    raise SignInRefused(f"the ID token's '{name}' is not text")
  return value


def _optionalHTTPSURL(document: JSON, member: str) -> str | None:
  return None if document.get(member) is None else _httpsURL(document, member)


def _httpsURL(document: JSON, member: str) -> str:
  value = document.get(member)
  if not isinstance(value, str) or not value.startswith("https://"):
    raise SignInRefused(f"the provider's '{member}' is not an https URL: {value!r}")
  return value


def discover(issuer: str, fetcher: JSONFetcher) -> Provider:
  """The provider at `issuer`, from its discovery document, which must name exactly that issuer."""
  if not issuer.startswith("https://"):
    raise SignInRefused(f"an issuer is an https URL, not {issuer!r}")
  document = fetcher.getJSON(issuer.rstrip("/") + "/.well-known/openid-configuration")
  if document.get("issuer") != issuer:
    raise SignInRefused(f"the discovery document names issuer {document.get('issuer')!r}, not {issuer!r}")
  offered = _names(document, "id_token_signing_alg_values_supported")
  accepted = frozenset(offered) & supportedAlgorithms
  if not accepted:
    raise SignInRefused(f"the provider signs ID tokens with {offered}, none of which is accepted")
  # Some providers (Entra ID among them) support PKCE without announcing it; the challenge is sent either way.
  if "code_challenge_methods_supported" in document and "S256" not in _names(document, "code_challenge_methods_supported"):
    raise SignInRefused("the provider does not offer PKCE with S256")
  return Provider(
    issuer=issuer, authorizationEndpoint=_httpsURL(document, "authorization_endpoint"),
    tokenEndpoint=_httpsURL(document, "token_endpoint"), jwksURI=_httpsURL(document, "jwks_uri"),
    userinfoEndpoint=_optionalHTTPSURL(document, "userinfo_endpoint"), signingAlgorithms=accepted,
  )


@dataclass(frozen=True)
class Pending:
  """What the application keeps, server-side, between sending the person away and their return."""

  state: str
  nonce: str
  codeVerifier: str
  startedAt: float


@dataclass(frozen=True)
class Identity:
  issuer: str
  subject: str
  userName: str | None
  email: str | None
  displayName: str | None
  groups: tuple[str, ...]
  claims: JSON = field(repr=False)


class RelyingParty:
  def __init__(self, provider: Provider, clientID: str, clientSecret: str, redirectURI: str, fetcher: JSONFetcher,
               scopes: tuple[str, ...] = ("openid", "profile", "email"), leewaySeconds: int = 60,
               pendingSeconds: int = 600, clock: Callable[[], float] = time.time) -> None:
    if "openid" not in scopes:
      raise SignInRefused("the scopes must include 'openid'")
    self.provider = provider
    self.clientID = clientID
    self._clientSecret = clientSecret
    self.redirectURI = redirectURI
    self.fetcher = fetcher
    self.scopes = scopes
    self.leewaySeconds = leewaySeconds
    self.pendingSeconds = pendingSeconds
    self.clock = clock
    self._keys: KeySet | None = None
    self._keysFetchedAt = float("-inf")

  def beginSignIn(self) -> tuple[str, Pending]:
    pending = Pending(state=secrets.token_urlsafe(32), nonce=secrets.token_urlsafe(32),
                      codeVerifier=secrets.token_urlsafe(64), startedAt=self.clock())
    challenge = base64.urlsafe_b64encode(hashlib.sha256(pending.codeVerifier.encode("ascii")).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({
      "response_type": "code", "client_id": self.clientID, "redirect_uri": self.redirectURI,
      "scope": " ".join(self.scopes), "state": pending.state, "nonce": pending.nonce,
      "code_challenge": challenge, "code_challenge_method": "S256",
    })
    separator = "&" if "?" in self.provider.authorizationEndpoint else "?"
    return f"{self.provider.authorizationEndpoint}{separator}{query}", pending

  def finishSignIn(self, pending: Pending, query: dict[str, str]) -> Identity:
    if self.clock() - pending.startedAt > self.pendingSeconds:
      raise SignInRefused("the sign-in took too long; start again")
    if not hmac.compare_digest(str(query.get("state", "")), pending.state):
      raise SignInRefused("the sign-in's state does not match")
    if "error" in query:
      raise SignInRefused(f"the provider refused: {query.get('error_description') or query['error']}")
    code = query.get("code")
    if not code:
      raise SignInRefused("the provider sent no code")
    credentials = f"{urllib.parse.quote(self.clientID, safe='')}:{urllib.parse.quote(self._clientSecret, safe='')}"
    tokens = self.fetcher.postForm(self.provider.tokenEndpoint, {
      "grant_type": "authorization_code", "code": code, "redirect_uri": self.redirectURI,
      "code_verifier": pending.codeVerifier,
    }, {"Authorization": "Basic " + base64.b64encode(credentials.encode()).decode("ascii")})
    idToken = tokens.get("id_token")
    if not isinstance(idToken, str):
      raise SignInRefused("the token response has no ID token")
    claims = self.checkIDToken(idToken, pending.nonce)
    overage = claims.get("_claim_names")
    if isinstance(overage, dict) and "groups" in overage:
      raise SignInRefused("the provider left the groups out of the ID token (too many to include); "
                          "have it send only the groups assigned to this application")
    groups = claims.get("groups", [])
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
      raise SignInRefused("the ID token's groups are not a list of names")
    return Identity(
      issuer=claims["iss"], subject=claims["sub"], userName=_optionalText(claims, "preferred_username"), email=_optionalText(claims, "email"),
      displayName=_optionalText(claims, "name"), groups=tuple(groups), claims=claims,
    )

  def _keySet(self, refresh: bool) -> KeySet:
    # A token naming an unknown key must not make every sign-in fetch the provider's keys again.
    if self._keys is None or (refresh and self.clock() - self._keysFetchedAt >= minimumKeyRefreshSeconds):
      self._keys = KeySet(self.fetcher.getJSON(self.provider.jwksURI))
      self._keysFetchedAt = self.clock()
    return self._keys

  def checkIDToken(self, idToken: str, nonce: str) -> JSON:
    """The claims of an ID token that passes every check, or SignInRefused saying which failed."""
    try:
      header = readHeader(idToken)
      acceptedAlgorithm(header, self.provider.signingAlgorithms)
      try:
        key = self._keySet(refresh=False).keyFor(header)
      except JOSEError:
        key = self._keySet(refresh=True).keyFor(header)
      payload = verifyCompact(idToken, key, self.provider.signingAlgorithms).payload
      claims = json.loads(payload)
    except (JOSEError, UnicodeDecodeError, json.JSONDecodeError) as error:
      raise SignInRefused(f"the ID token is refused: {error}") from None
    if not isinstance(claims, dict):
      raise SignInRefused("the ID token's claims are not an object")
    now = self.clock()
    if claims.get("iss") != self.provider.issuer:
      raise SignInRefused(f"the ID token's issuer {claims.get('iss')!r} is not {self.provider.issuer!r}")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or self.clientID not in audiences:
      raise SignInRefused(f"the ID token is not for client {self.clientID!r}")
    if (len(audiences) > 1 or "azp" in claims) and claims.get("azp") != self.clientID:
      raise SignInRefused(f"the ID token's authorized party is {claims.get('azp')!r}, not {self.clientID!r}")
    for member in ("exp", "iat"):
      if not isinstance(claims.get(member), (int, float)) or isinstance(claims.get(member), bool):
        raise SignInRefused(f"the ID token has no numeric '{member}'")
    if claims["exp"] <= now - self.leewaySeconds:
      raise SignInRefused("the ID token has expired")
    if claims["iat"] > now + self.leewaySeconds:
      raise SignInRefused("the ID token is issued in the future")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
      raise SignInRefused("the ID token's nonce does not match")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
      raise SignInRefused("the ID token names no subject")
    return claims
