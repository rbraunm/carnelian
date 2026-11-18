# SPDX-License-Identifier: MIT
"""An OpenID Connect relying party: the authorization-code flow with PKCE (OpenID Connect Core 1.0).

Sign-in has two halves. `beginSignIn` gives the address to send the person to and a
Pending record the application keeps server-side; `finishSignIn` takes that record and the
query the provider sent back, exchanges the code, and returns the Identity once the ID
token passes every check of Core section 3.1.3.7: signature by a key from the provider's
JWK set, issuer, audience and authorized party, an accepted algorithm, expiry, issue and
not-before times (with a small leeway), and the nonce. A pending sign-in belongs to the
provider and client that began it, and the issuer the provider names in its answer (RFC
9207) must be that provider, so an answer meant for one provider is never taken to another
(mix-up). The state is compared in constant time, a pending sign-in expires, and a
provider error is raised with its own words.

The provider's keys are kept for at most a day; a token whose key is not known, or whose
signature does not verify with the known key (a key rotated under the same 'kid'), fetches
them again, at most once a minute.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from carnelian.fetching import JSON, JSONFetcher
from carnelian.jose import JOSEError, KeyCache, numericDate, readHeader, readJSON, supportedAlgorithms

__all__ = ["SignInRefused", "Provider", "discover", "Pending", "Identity", "RelyingParty", "LogoutNotice"]



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
  issuerInResponseRequired: bool
  endSessionEndpoint: str | None


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


def _isLoopback(value: str) -> bool:
  parts = urllib.parse.urlsplit(value)
  return parts.scheme == "http" and parts.hostname in ("127.0.0.1", "::1", "localhost")


def _isHTTPSURL(value: object) -> bool:
  if not isinstance(value, str):
    return False
  try:
    parts = urllib.parse.urlsplit(value)
  except ValueError:
    return False
  return parts.scheme == "https" and bool(parts.hostname)


def _httpsURL(document: JSON, member: str) -> str:
  value = document.get(member)
  if not isinstance(value, str) or not _isHTTPSURL(value):
    raise SignInRefused(f"the provider's '{member}' is not an https URL: {value!r}")
  return value


def _sameText(given: object, expected: str) -> bool:
  return isinstance(given, str) and hmac.compare_digest(given.encode("utf-8", "surrogatepass"), expected.encode("utf-8"))


def _numericDate(claims: JSON, member: str) -> float:
  try:
    return numericDate(claims, member)
  except JOSEError as error:
    raise SignInRefused(f"the ID token's {error}") from None


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
  issuerInResponse = document.get("authorization_response_iss_parameter_supported", False)
  if not isinstance(issuerInResponse, bool):
    raise SignInRefused(f"the provider's 'authorization_response_iss_parameter_supported' is not true or false: {issuerInResponse!r}")
  return Provider(
    issuer=issuer, authorizationEndpoint=_httpsURL(document, "authorization_endpoint"),
    tokenEndpoint=_httpsURL(document, "token_endpoint"), jwksURI=_httpsURL(document, "jwks_uri"),
    userinfoEndpoint=_optionalHTTPSURL(document, "userinfo_endpoint"), signingAlgorithms=accepted,
    issuerInResponseRequired=issuerInResponse, endSessionEndpoint=_optionalHTTPSURL(document, "end_session_endpoint"),
  )


@dataclass(frozen=True)
class Pending:
  """What the application keeps, server-side, between sending the person away and their return."""

  issuer: str
  clientID: str
  state: str
  nonce: str
  codeVerifier: str
  startedAt: float


@dataclass(frozen=True)
class LogoutNotice:
  """A provider's back-channel logout: end the sessions of `subject`, or the one session `sessionID`, or both.
  `tokenID` (the token's jti) is the application's to remember until `expiresAt`, so a notice is acted on once."""

  subject: str | None
  sessionID: str | None
  tokenID: str
  expiresAt: float


backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"


@dataclass(frozen=True)
class Identity:
  issuer: str
  subject: str
  userName: str | None
  email: str | None
  emailVerified: bool
  displayName: str | None
  groups: tuple[str, ...]
  claims: JSON = field(repr=False)
  idToken: str = field(repr=False)


class RelyingParty:
  def __init__(self, provider: Provider, clientID: str, clientSecret: str, redirectURI: str, fetcher: JSONFetcher,
               scopes: tuple[str, ...] = ("openid", "profile", "email"), leewaySeconds: int = 60,
               pendingSeconds: int = 600, clock: Callable[[], float] = time.time) -> None:
    if "openid" not in scopes:
      raise SignInRefused("the scopes must include 'openid'")
    endpoints = {"authorization": provider.authorizationEndpoint, "token": provider.tokenEndpoint, "JWK set": provider.jwksURI}
    if provider.userinfoEndpoint is not None:
      endpoints["userinfo"] = provider.userinfoEndpoint
    for name, address in endpoints.items():
      if not _isHTTPSURL(address):
        raise SignInRefused(f"the provider's {name} endpoint is not an https URL: {address!r}")
    self.provider = provider
    self.clientID = clientID
    self._clientSecret = clientSecret
    self.redirectURI = redirectURI
    self.fetcher = fetcher
    self.scopes = scopes
    self.leewaySeconds = leewaySeconds
    self.pendingSeconds = pendingSeconds
    self.clock = clock
    self._keys = KeyCache(lambda: self.fetcher.getJSON(self.provider.jwksURI), lambda: self.clock())

  def beginSignIn(self) -> tuple[str, Pending]:
    pending = Pending(issuer=self.provider.issuer, clientID=self.clientID, state=secrets.token_urlsafe(32),
                      nonce=secrets.token_urlsafe(32), codeVerifier=secrets.token_urlsafe(64), startedAt=self.clock())
    challenge = base64.urlsafe_b64encode(hashlib.sha256(pending.codeVerifier.encode("ascii")).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({
      "response_type": "code", "client_id": self.clientID, "redirect_uri": self.redirectURI,
      "scope": " ".join(self.scopes), "state": pending.state, "nonce": pending.nonce,
      "code_challenge": challenge, "code_challenge_method": "S256",
    })
    separator = "&" if "?" in self.provider.authorizationEndpoint else "?"
    return f"{self.provider.authorizationEndpoint}{separator}{query}", pending

  def finishSignIn(self, pending: Pending, query: dict[str, str]) -> Identity:
    if pending.issuer != self.provider.issuer or pending.clientID != self.clientID:
      raise SignInRefused(f"the sign-in was begun with {pending.issuer!r} for client {pending.clientID!r}, "
                          f"not with {self.provider.issuer!r} for {self.clientID!r}")
    if self.clock() - pending.startedAt > self.pendingSeconds:
      raise SignInRefused("the sign-in took too long; start again")
    if not _sameText(query.get("state"), pending.state):
      raise SignInRefused("the sign-in's state does not match")
    if "iss" in query:
      if not _sameText(query["iss"], self.provider.issuer):
        raise SignInRefused(f"the answer comes from issuer {query['iss']!r}, not {self.provider.issuer!r}")
    elif self.provider.issuerInResponseRequired:
      raise SignInRefused("the provider announces that it names itself in its answer ('iss'), and this answer does not")
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
      issuer=claims["iss"], subject=claims["sub"], userName=_optionalText(claims, "preferred_username"),
      email=_optionalText(claims, "email"), emailVerified=claims.get("email_verified") is True,
      displayName=_optionalText(claims, "name"), groups=tuple(groups), claims=claims, idToken=idToken,
    )

  def _verifiedPayload(self, idToken: str) -> bytes:
    return self._keys.verify(idToken, self.provider.signingAlgorithms).payload

  def logoutAddress(self, idTokenHint: str | None = None, postLogoutRedirectURI: str | None = None,
                    state: str | None = None) -> str:
    """Where to send the person to sign out at the provider too (OpenID Connect RP-Initiated Logout)."""
    if self.provider.endSessionEndpoint is None:
      raise SignInRefused("the provider offers no end_session_endpoint to sign out at")
    if postLogoutRedirectURI is not None and not _isHTTPSURL(postLogoutRedirectURI) and not _isLoopback(postLogoutRedirectURI):
      raise SignInRefused(f"a post-logout address is https (or http on the loopback), not {postLogoutRedirectURI!r}")
    fields = {"client_id": self.clientID}
    for name, value in (("id_token_hint", idTokenHint), ("post_logout_redirect_uri", postLogoutRedirectURI), ("state", state)):
      if value is not None:
        fields[name] = value
    separator = "&" if "?" in self.provider.endSessionEndpoint else "?"
    return f"{self.provider.endSessionEndpoint}{separator}{urllib.parse.urlencode(fields)}"

  def checkLogoutToken(self, logoutToken: str) -> LogoutNotice:
    """A back-channel logout token (OpenID Connect Back-Channel Logout 1.0, section 2.6) that passes every check."""
    try:
      verified = self._keys.verify(logoutToken, self.provider.signingAlgorithms)
      header = readHeader(logoutToken)
      claims = readJSON(verified.payload, "the logout token's claims")
    except JOSEError as error:
      raise SignInRefused(f"the logout token is refused: {error}") from None
    if header.get("typ") not in (None, "logout+jwt", "application/logout+jwt"):
      raise SignInRefused(f"the token's type is {header.get('typ')!r}, not a logout token")
    if not isinstance(claims, dict):
      raise SignInRefused("the logout token's claims are not an object")
    now = self.clock()
    if claims.get("iss") != self.provider.issuer:
      raise SignInRefused(f"the logout token's issuer {claims.get('iss')!r} is not {self.provider.issuer!r}")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or self.clientID not in audiences or not all(isinstance(name, str) for name in audiences):
      raise SignInRefused(f"the logout token is not for client {self.clientID!r}")
    if _numericDate(claims, "iat") > now + self.leewaySeconds:
      raise SignInRefused("the logout token is issued in the future")
    expiresAt = _numericDate(claims, "exp") if "exp" in claims else _numericDate(claims, "iat") + 2 * 60
    if expiresAt <= now - self.leewaySeconds:
      raise SignInRefused("the logout token has expired")
    events = claims.get("events")
    if not isinstance(events, dict) or not isinstance(events.get(backchannelLogoutEvent), dict):
      raise SignInRefused("the token does not carry the back-channel logout event")
    if "nonce" in claims:
      raise SignInRefused("a logout token never carries a nonce; this one does, so it is refused")
    tokenID = claims.get("jti")
    if not isinstance(tokenID, str) or not tokenID:
      raise SignInRefused("the logout token has no jti")
    subject, sessionID = claims.get("sub"), claims.get("sid")
    for name, value in (("sub", subject), ("sid", sessionID)):
      if value is not None and (not isinstance(value, str) or not value):
        raise SignInRefused(f"the logout token's {name} is not text")
    if subject is None and sessionID is None:
      raise SignInRefused("the logout token names neither a subject nor a session")
    return LogoutNotice(subject=subject, sessionID=sessionID, tokenID=tokenID, expiresAt=expiresAt)

  def checkIDToken(self, idToken: str, nonce: str) -> JSON:
    """The claims of an ID token that passes every check, or SignInRefused saying which failed."""
    try:
      claims = readJSON(self._verifiedPayload(idToken), "the ID token's claims")
    except JOSEError as error:
      raise SignInRefused(f"the ID token is refused: {error}") from None
    if not isinstance(claims, dict):
      raise SignInRefused("the ID token's claims are not an object")
    now = self.clock()
    if claims.get("iss") != self.provider.issuer:
      raise SignInRefused(f"the ID token's issuer {claims.get('iss')!r} is not {self.provider.issuer!r}")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or not audiences or not all(isinstance(name, str) and name for name in audiences):
      raise SignInRefused(f"the ID token's audience is not a name or a list of names: {audience!r}")
    if self.clientID not in audiences:
      raise SignInRefused(f"the ID token is not for client {self.clientID!r}")
    if (len(audiences) > 1 or "azp" in claims) and claims.get("azp") != self.clientID:
      raise SignInRefused(f"the ID token's authorized party is {claims.get('azp')!r}, not {self.clientID!r}")
    if _numericDate(claims, "exp") <= now - self.leewaySeconds:
      raise SignInRefused("the ID token has expired")
    if _numericDate(claims, "iat") > now + self.leewaySeconds:
      raise SignInRefused("the ID token is issued in the future")
    if "nbf" in claims and _numericDate(claims, "nbf") > now + self.leewaySeconds:
      raise SignInRefused("the ID token is not valid yet ('nbf')")
    if not isinstance(claims.get("nonce"), str):
      raise SignInRefused("the ID token has no nonce as text")
    if not _sameText(claims["nonce"], nonce):
      raise SignInRefused("the ID token's nonce does not match")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
      raise SignInRefused("the ID token names no subject")
    return claims
