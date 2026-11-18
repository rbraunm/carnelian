# Carnelian

Sign-in for Python applications on the standard library alone:

- **OpenID Connect** relying party (discovery, the authorization-code flow with PKCE, ID
  token checks);
- **SAML 2.0** service provider (requests, responses, XML signatures with exclusive
  canonicalization, protection against signature wrapping);
- **Research and education federations** (InCommon, the national federations, eduGAIN):
  institutions' signed metadata by the Metadata Query protocol, their scopes, scoped
  identifiers (subject-id, pairwise-id, eduPersonPrincipalName), and the service provider's
  own metadata to register;
- **CAS** client (Apereo CAS protocol 3.0), the sign-in many universities in France, Spain
  and Latin America run;
- **LDAP** client for Active Directory and other directories (bind and search over TLS);
- **SCIM 2.0** service provider (users with the enterprise extension, groups, the full
  filter grammar, PATCH, paging, attribute selection, discovery), behind the application's
  own store and web server; checked against the RFC examples and Microsoft Entra ID's
  documented requests.

No third-party packages, so nothing but its own MIT licence governs where it can be used.
Its cryptography only *verifies* signatures with public keys -- it never signs or decrypts
with a secret -- and it leaves TLS to Python's own `ssl` module.

It began as the sign-in layer of [OpenFurrow](https://github.com/rbraunm/openfurrow) and is
tested against real identity providers: Keycloak, Samba Active Directory, Apereo CAS, a
test federation and InCommon's live metadata.

## Guides

One per protocol, each with a complete sign-in example, what it checks and what it refuses:
[OpenID Connect](docs/openIDConnect.md), [SAML 2.0](docs/saml.md),
[research federations](docs/federations.md), [CAS](docs/cas.md),
[LDAP and Active Directory](docs/ldap.md), [SCIM 2.0](docs/scim.md).
What Carnelian promises and what it leaves to you: [SECURITY.md](SECURITY.md).

The supported interface is what each of the modules `carnelian.oidc`, `carnelian.saml`,
`carnelian.federation`, `carnelian.cas`, `carnelian.ldap`, `carnelian.scim` and
`carnelian.fetching` lists in its `__all__`. Everything else is internal and may change
in any release.

## Install

```bash
python -m pip install carnelian
```

Python 3.13 or newer; nothing else is installed with it.

## Releases

A release is a version tag `v<version>` on a commit of `main` whose `carnelian/version.py`
names that version; the `publish` workflow builds it and publishes it to PyPI by trusted
publishing, with no token stored anywhere.

## License

MIT. See [LICENSE](LICENSE).
