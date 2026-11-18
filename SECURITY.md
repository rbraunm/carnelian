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
  replay); TLS certificates and host names, through Python's own `ssl` -- a TLS context
  that does not check certificates and host names is refused, when it is given and before
  every connection.
- **It refuses rather than guesses:** an unknown algorithm, a signature that does not cover
  what is read, an expired or unsigned answer, a weaker algorithm than configured, a
  protocol condition it does not implement, a value of the wrong type or shape in what it
  reads. Elements and attributes it does not read are not looked at. Every refusal is the
  module's own exception (`SignInRefused`, `SAMLRefused`, `CASRefused`, `DirectoryRefused`,
  `SCIMRefused`, and so on, all `ValueError`s) and says why.
- **It bounds what an attacker can make it do:** input sizes, XML depth, elements,
  attributes and namespace declarations, JSON nesting and number sizes, filter length and
  comparisons, LDAP messages, entries and time per operation, and the time a fetch may take.
  Every run of the test suite fuzzes the parsers an attacker can reach (DER, XML and XML
  signatures, BER for LDAP, SCIM filters and requests, JOSE, SAML responses and the issuer
  read from a logout message, CAS answers and
  the OpenID Connect and CAS callbacks) with generated input, 300 cases each (20,000 with
  `CARNELIAN_FUZZ=deep`): each may fail only with its own refusal, a signed SAML
  response with one byte changed is refused or read exactly as before, and an ID token with
  one byte changed is refused.
- **It never implements private-key cryptography itself.** The core only verifies.
  Decrypting SAML assertions and signing SAML requests and logout messages go through the
  interface of `carnelian.keys` (sign bytes, unwrap a content key, decrypt content): the
  optional `keys` extra backs it with pyca/cryptography, or a deployment backs it with a
  hardware or cloud key service. Nothing else imports that module, so without it these
  features are refused by name. Which XML Encryption algorithms are accepted is set by
  configuration, never by the document: RSA PKCS #1 v1.5 key transport is always refused,
  AES-CBC is decrypted only when configured and under a verified signature on the whole
  Response, and every failure to decrypt is the same refusal after the same work (every key
  tried, a failed unwrap continuing with a random content key). A decrypted assertion
  without its own signature must declare every namespace prefix it uses.
- **It leaves to the application**, and the guides in `docs/` show each in place:
  - keeping each sign-in's pending record server-side, tied to the browser and used once;
  - a shared, atomic replay store when SAML runs in several processes (`ReplayStore`);
  - sessions and cookies after sign-in, and deciding which identities may do what;
  - never linking accounts by an e-mail address the provider has not verified
    (`emailVerified`), or by an attribute an institution's scope does not cover;
  - for SCIM, that an accepted bearer token may do everything the service does on the
    store, and that each request runs in one transaction;
  - keeping its own configuration (keys, client secrets, provider addresses) safe.
