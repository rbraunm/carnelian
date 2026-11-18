# SPDX-License-Identifier: MIT
"""Tokens a CI system or cloud platform issues to a running workload, so it can sign in with no stored secret:
GitHub Actions, GitLab CI, and the cloud providers' workload identity.

The workload asks its platform for a short-lived OpenID Connect token for your audience and
presents it; Carnelian checks the platform's signature with the keys its discovery document
names, then the issuer, the audience, the times, and that every claim you require has exactly
the value you require. Those required claims are what make a token yours: a token from any
pipeline on the same platform carries the same issuer and is signed with the same keys, so a
verifier with no required claims is refused when it is made.

For GitHub Actions the issuer is `https://token.actions.githubusercontent.com`, and the usual
required claims are `repository` (or the stabler `repository_id`), `ref` or `environment`,
and `workflow_ref` when only one workflow may sign in.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from carnelian.fetching import JSON, HTTPFailure, JSONFetcher
from carnelian.jose import JOSEError, KeyCache, numericDate, readJSON, supportedAlgorithms

__all__ = ["WorkloadRefused", "WorkloadIssuer", "discoverIssuer", "WorkloadIdentity", "WorkloadVerifier", "githubActions"]

githubActions = "https://token.actions.githubusercontent.com"


class WorkloadRefused(ValueError):
  """A workload token, or an issuer's discovery document, refused, with why."""


@dataclass(frozen=True)
class WorkloadIssuer:
  issuer: str
  jwksURI: str
  signingAlgorithms: frozenset[str]


def discoverIssuer(issuer: str, fetcher: JSONFetcher) -> WorkloadIssuer:
  """The issuer at `issuer`, from its discovery document, which must name exactly that issuer."""
  if not issuer.startswith("https://") or issuer.endswith("/"):
    raise WorkloadRefused(f"an issuer is an https URL without a trailing slash, not {issuer!r}")
  try:
    document = fetcher.getJSON(issuer + "/.well-known/openid-configuration")
  except HTTPFailure as error:
    raise WorkloadRefused(f"the issuer's discovery document cannot be fetched: {error}") from None
  if document.get("issuer") != issuer:
    raise WorkloadRefused(f"the discovery document names issuer {document.get('issuer')!r}, not {issuer!r}")
  jwksURI = document.get("jwks_uri")
  if not isinstance(jwksURI, str) or not jwksURI.startswith("https://"):
    raise WorkloadRefused(f"the issuer's jwks_uri is not an https URL: {jwksURI!r}")
  offered = document.get("id_token_signing_alg_values_supported")
  if not isinstance(offered, list) or not offered or not all(isinstance(name, str) for name in offered):
    raise WorkloadRefused(f"the issuer's id_token_signing_alg_values_supported is not a list of names: {offered!r}")
  accepted = frozenset(offered) & supportedAlgorithms
  if not accepted:
    raise WorkloadRefused(f"the issuer signs with {offered}, none of which is accepted")
  return WorkloadIssuer(issuer=issuer, jwksURI=jwksURI, signingAlgorithms=accepted)


@dataclass(frozen=True)
class WorkloadIdentity:
  issuer: str
  subject: str
  claims: JSON = field(repr=False)


class WorkloadVerifier:
  """Checks tokens from one issuer, for one audience, carrying exactly the required claims."""

  def __init__(self, issuer: WorkloadIssuer, audience: str, requiredClaims: Mapping[str, str], fetcher: JSONFetcher,
               leewaySeconds: int = 60, clock: Callable[[], float] = time.time) -> None:
    if not audience:
      raise ValueError("an audience is required: the value the workload asks its platform to put in 'aud'")
    if not requiredClaims or not all(isinstance(value, str) and value for value in requiredClaims.values()):
      raise ValueError("name the claims that make a token yours (for GitHub, at least the repository); "
                       "without them a token from any workload at the issuer would pass")
    for reserved in ("iss", "aud", "exp", "iat", "nbf"):
      if reserved in requiredClaims:
        raise ValueError(f"'{reserved}' is checked by the verifier itself; it is not a required claim")
    self.issuer, self.audience, self.requiredClaims = issuer, audience, dict(requiredClaims)
    self.leewaySeconds, self.clock = leewaySeconds, clock
    self._keys = KeyCache(lambda: fetcher.getJSON(issuer.jwksURI), clock)

  def verify(self, token: str) -> WorkloadIdentity:
    try:
      claims = readJSON(self._keys.verify(token, self.issuer.signingAlgorithms).payload, "the token's claims")
      if not isinstance(claims, dict):
        raise WorkloadRefused("the token's claims are not an object")
      now = self.clock()
      if numericDate(claims, "exp") <= now - self.leewaySeconds:
        raise WorkloadRefused("the token has expired")
      if numericDate(claims, "iat") > now + self.leewaySeconds:
        raise WorkloadRefused("the token is issued in the future")
      if "nbf" in claims and numericDate(claims, "nbf") > now + self.leewaySeconds:
        raise WorkloadRefused("the token is not valid yet ('nbf')")
    except JOSEError as error:
      raise WorkloadRefused(f"the token is refused: {error}") from None
    if claims.get("iss") != self.issuer.issuer:
      raise WorkloadRefused(f"the token's issuer {claims.get('iss')!r} is not {self.issuer.issuer!r}")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or not audiences or not all(isinstance(name, str) and name for name in audiences):
      raise WorkloadRefused(f"the token's audience is not a name or a list of names: {audience!r}")
    if self.audience not in audiences:
      raise WorkloadRefused(f"the token is not for audience {self.audience!r}")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
      raise WorkloadRefused("the token names no subject")
    for name, value in self.requiredClaims.items():
      if claims.get(name) != value:
        raise WorkloadRefused(f"the token's {name} is {claims.get(name)!r}, not {value!r}")
    return WorkloadIdentity(issuer=self.issuer.issuer, subject=subject, claims=claims)
