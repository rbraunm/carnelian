# CLAUDE.md -- Carnelian

Sign-in for Python applications on the standard library alone: an OpenID Connect relying
party, a SAML 2.0 service provider, an LDAP client and a SCIM 2.0 service provider. It
began as the sign-in layer of OpenFurrow (decision 0039 there) and exists so that no
third-party licence limits where it, or what uses it, can go.

## Rules that make the project

- **Standard library only at run time.** `dependencies` stays empty. Test oracles (pytest,
  `cryptography`) are test extras and never imported by `carnelian/`.
- **No private-key cryptography of our own.** The core only verifies: signatures are
  checked with public keys (RSA PKCS #1 v1.5 and PSS, ECDSA on the NIST curves), in our own
  code, since verification touches nothing secret. TLS is Python's `ssl`. Operations with a
  private key (decrypting SAML assertions, signing requests and logout messages) go through
  the optional extra `carnelian[keys]`, built on pyca/cryptography (owner, 2026-11-17, after
  independent reviews), behind a small interface (unwrap a key, decrypt content, sign bytes)
  that a deployment can also back with a hardware or cloud key service. Without the extra,
  such features are refused by name. Never write private-key arithmetic in Python.
- **XML Encryption by policy, not by the document.** RSA PKCS #1 v1.5 key transport is
  always refused; RSA-OAEP with AES-GCM is the default; AES-CBC only where a provider's
  configuration allows it and the signed outer response has been checked first. The allowed
  algorithms come from configuration, never from the encrypted document.
- **Licences stated per part.** The core is MIT and dependency-free. The `keys` extra brings
  pyca/cryptography (Apache-2.0 or BSD) and, in its wheels, OpenSSL 3 (Apache-2.0); say so
  plainly for GPLv2-only users rather than promising more.
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
