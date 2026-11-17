# Carnelian

Sign-in for Python applications on the standard library alone:

- **OpenID Connect** relying party (discovery, the authorization-code flow with PKCE, ID
  token checks);
- **SAML 2.0** service provider (requests, responses, XML signatures with exclusive
  canonicalization, protection against signature wrapping);
- **LDAP** client for Active Directory and other directories (bind and search over TLS);
- **SCIM 2.0** service provider (users, groups, filters, PATCH, deactivation).

No third-party packages, so nothing but its own MIT licence governs where it can be used.
Its cryptography only *verifies* signatures with public keys -- it never signs or decrypts
with a secret -- and it leaves TLS to Python's own `ssl` module.

Status: being built. It starts life as the sign-in layer of
[OpenFurrow](https://github.com/rbraunm/openfurrow) and is tested against real identity
providers.

## License

MIT. See [LICENSE](LICENSE).
