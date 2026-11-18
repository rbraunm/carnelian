# Security

Carnelian decides who may sign in, so a flaw in it is a flaw in every application that uses
it. Please report one privately, never in a public issue.

## Reporting a vulnerability

Use GitHub's private reporting: the repository's **Security** tab, then **Report a
vulnerability**. Say what is affected (the module and the version), how to reproduce it,
and what an attacker gains. You will get an answer in the advisory; a fix is released as a
new version with a GitHub security advisory that credits you unless you ask otherwise.

## Supported versions

Only the newest release is supported while Carnelian is below 1.0. Fixes are not backported.

## What Carnelian promises, and what it leaves to you

- **It checks:** signatures (RSA PKCS #1 v1.5 and PSS, ECDSA on the NIST curves) against
  keys you configured or fetched from a provider you named; the claims and conditions each
  protocol defines (issuer, audience, expiry, nonce or state, InResponseTo, recipient,
  replay); TLS certificates and host names, through Python's own `ssl`.
- **It refuses rather than guesses:** an unknown algorithm, element or attribute, a
  signature that does not cover what is read, an expired or unsigned answer, a weaker
  algorithm than configured. Every refusal says why.
- **It never implements private-key cryptography itself.** The core only verifies.
  Decrypting and signing, when needed, go through the optional `keys` extra on
  pyca/cryptography.
- **It leaves to the application:** keeping each sign-in's pending record server-side and
  tied to the browser; sessions and cookies after sign-in; deciding which identities may
  do what; keeping its own configuration (keys, client secrets, provider addresses) safe.
  The guides in `docs/` show each of these in place.
