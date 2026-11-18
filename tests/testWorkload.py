# SPDX-License-Identifier: MIT
"""Workload tokens: the required claims that make a token yours, the checks around them, and real tokens from
GitHub Actions (live discovery with --live; a token the workflow asks GitHub for, when the run provides one)."""

import json
import os

import pytest

from carnelian.fetching import Fetcher, HTTPFailure, secureContext
from carnelian.workload import WorkloadIssuer, WorkloadRefused, WorkloadVerifier, discoverIssuer, githubActions

from testOIDC import idToken, jwks, signedText

issuer = "https://token.example.org"
now = 1_800_000_000
good = {"iss": issuer, "aud": "carnelian-ci", "sub": "repo:example/app:ref:refs/heads/main", "exp": now + 300,
        "iat": now - 5, "repository": "example/app", "ref": "refs/heads/main", "environment": "production"}


class StandInIssuer:
  """The issuer's discovery document and keys, served without a network: a double for the network boundary only."""

  def __init__(self, document=None):
    self.document = document if document is not None else {
      "issuer": issuer, "jwks_uri": f"{issuer}/keys", "id_token_signing_alg_values_supported": ["RS256"]}
    self.fetched = []

  def getJSON(self, url, headers=None):
    self.fetched.append(url)
    return jwks if url == f"{issuer}/keys" else self.document

  def getBytes(self, url, accept):
    raise AssertionError("not used")

  def postForm(self, url, fields, headers=None):
    raise AssertionError("not used")


def verifier(requiredClaims=None, audience="carnelian-ci"):
  network = StandInIssuer()
  return WorkloadVerifier(discoverIssuer(issuer, network), audience,
                          requiredClaims if requiredClaims is not None else {"repository": "example/app", "ref": "refs/heads/main"},
                          network, clock=lambda: now)


def testATokenFromTheRequiredPipelinePasses():
  identity = verifier().verify(idToken(good))
  assert (identity.issuer, identity.subject, identity.claims["environment"]) == (issuer, good["sub"], "production")


@pytest.mark.parametrize("change, message", [
  ({"repository": "attacker/app"}, "repository is 'attacker/app', not 'example/app'"),
  ({"ref": "refs/heads/feature"}, "ref is 'refs/heads/feature'"),
  ({"repository": None}, "repository is None"),
  ({"aud": "someone-else"}, "not for audience 'carnelian-ci'"),
  ({"aud": ["carnelian-ci", 7]}, "not a name or a list of names"),
  ({"iss": "https://evil.example.org"}, "issuer 'https://evil.example.org' is not"),
  ({"exp": now - 61}, "has expired"),
  ({"iat": now + 61}, "issued in the future"),
  ({"nbf": now + 61}, "not valid yet"),
  ({"exp": 1e300 * 1e300}, "Infinity is not a JSON number"),
  ({"sub": ""}, "names no subject"),
])
def testATokenThatIsNotExactlyTheRequiredPipelinesIsRefused(change, message):
  claims = {key: value for key, value in (good | change).items() if value is not None}
  with pytest.raises(WorkloadRefused, match=message):
    verifier().verify(idToken(claims))


def testATokenSignedWithAKeyTheIssuerDoesNotHaveIsRefused():
  with pytest.raises(WorkloadRefused, match="kid 'k9'"):
    verifier().verify(idToken(good, {"alg": "RS256", "kid": "k9"}))
  with pytest.raises(WorkloadRefused, match="algorithm 'none' is refused"):
    verifier().verify(idToken(good, {"alg": "none", "kid": "k1"}))


class UnreachableKeys(StandInIssuer):
  def getJSON(self, url, headers=None):
    if url == f"{issuer}/keys":
      raise HTTPFailure(f"{url}: ConnectionRefusedError")
    return super().getJSON(url, headers)


def testAnIssuerWhoseKeysCannotBeFetchedIsAWorkloadRefusal():
  network = UnreachableKeys()
  unreachable = WorkloadVerifier(discoverIssuer(issuer, network), "carnelian-ci", {"repository": "example/app"}, network,
                                 clock=lambda: now)
  with pytest.raises(WorkloadRefused, match="keys could not be fetched .*ConnectionRefusedError"):
    unreachable.verify(idToken(good))


def testATimeTooLargeForAFloatIsAWorkloadRefusal():
  claimsText = json.dumps(good)[:-1] + ', "nbf": 1' + "0" * 400 + "}"
  with pytest.raises(WorkloadRefused, match="'nbf' is not a time between the years 1 and 9999"):
    verifier().verify(signedText(claimsText))


@pytest.mark.parametrize("requiredClaims, audience, message", [
  ({}, "carnelian-ci", "name the claims that make a token yours"),
  ({"repository": ""}, "carnelian-ci", "name the claims that make a token yours"),
  ({"aud": "carnelian-ci"}, "carnelian-ci", "'aud' is checked by the verifier itself"),
  ({"repository": "example/app"}, "", "an audience is required"),
])
def testAVerifierThatWouldTakeAnyonesTokenIsRefusedWhenMade(requiredClaims, audience, message):
  with pytest.raises(ValueError, match=message):
    verifier(requiredClaims, audience)


@pytest.mark.parametrize("document, message", [
  ({"issuer": "https://other.example.org", "jwks_uri": f"{issuer}/keys", "id_token_signing_alg_values_supported": ["RS256"]},
   "names issuer 'https://other.example.org'"),
  ({"issuer": issuer, "jwks_uri": "http://token.example.org/keys", "id_token_signing_alg_values_supported": ["RS256"]},
   "not an https URL"),
  ({"issuer": issuer, "jwks_uri": f"{issuer}/keys", "id_token_signing_alg_values_supported": ["HS256"]},
   "none of which is accepted"),
  ({"issuer": issuer, "jwks_uri": f"{issuer}/keys"}, "not a list of names"),
])
def testADiscoveryDocumentThatIsNotTheIssuersIsRefused(document, message):
  with pytest.raises(WorkloadRefused, match=message):
    discoverIssuer(issuer, StandInIssuer(document))


def testGitHubActionsDiscoveryIsReadLive(request):
  if not request.config.getoption("--live"):
    pytest.skip("live test: run with --live to read GitHub Actions' discovery document")
  found = discoverIssuer(githubActions, Fetcher(secureContext()))
  assert found == WorkloadIssuer(githubActions, f"{githubActions}/.well-known/jwks", frozenset({"RS256"}))


def testARealGitHubActionsTokenIsVerified():
  token = os.environ.get("CARNELIAN_GITHUB_TOKEN")
  if not token:
    pytest.skip("needs a GitHub Actions run that asked for an OIDC token (the workflow's providers job does)")
  fetcher = Fetcher(secureContext())
  github = discoverIssuer(githubActions, fetcher)
  identity = WorkloadVerifier(github, "carnelian-ci", {"repository": os.environ["GITHUB_REPOSITORY"]}, fetcher).verify(token)
  assert identity.claims["repository"] == os.environ["GITHUB_REPOSITORY"] and identity.subject.startswith("repo:")
  with pytest.raises(WorkloadRefused, match="repository is"):
    WorkloadVerifier(github, "carnelian-ci", {"repository": "someone/else"}, fetcher).verify(token)
