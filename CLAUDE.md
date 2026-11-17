# CLAUDE.md -- Carnelian

Sign-in for Python applications on the standard library alone: an OpenID Connect relying
party, a SAML 2.0 service provider, an LDAP client and a SCIM 2.0 service provider. It
began as the sign-in layer of OpenFurrow (decision 0039 there) and exists so that no
third-party licence limits where it, or what uses it, can go.

## Rules that make the project

- **Standard library only at run time.** `dependencies` stays empty. Test oracles (pytest,
  `cryptography`) are test extras and never imported by `carnelian/`.
- **Verification-only cryptography.** Signatures are checked with public keys (RSA PKCS #1
  v1.5 and PSS, ECDSA on the NIST curves); nothing signs or decrypts with a secret key.
  TLS is Python's `ssl`. A feature that would need a secret key is refused by name, not
  half-built (encrypted SAML assertions, for now).
- **Fail loud, refuse by name.** Every check that fails raises with the reason; nothing is
  accepted "leniently", nothing falls back to a weaker algorithm, and an unknown or
  unsupported algorithm, element or attribute is an error.
- **Tested against the specifications and real providers.** Each protocol is checked
  against its specification's own test vectors and against real identity providers
  (Keycloak, Samba Active Directory, Entra-like SCIM clients) started for the test run.
- **Security over convenience.** Defaults are the strict choice; anything looser is an
  explicit, named option.

## House style

The owner's global standards apply (drinkingCamelCase names, 2-space indentation, ASCII in
code, almost no comments, no dead code, work on `claude`, commit at each checkpoint, no PRs
unless asked). Python 3.13 or newer; invoke as `python`. No owner name and no lab host
names anywhere in this public repository.
