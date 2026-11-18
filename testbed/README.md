# Testbed

Real identity providers for the integration tests, defined once and used two ways: the
`providers` job of the validation workflow starts them for one run and throws them away,
and a development host can keep them running.

- **Keycloak** over HTTPS on port 8443: OpenID Connect and SAML 2.0, with one realm loaded
  from the dataset.
- **Samba Active Directory** (the compose profile `directory`) on 389 (StartTLS) and 636
  (LDAPS). It needs a privileged container, so it runs on Docker in a VM or on a CI runner,
  not inside an unprivileged LXC container.

`dataset.json` holds the people and groups every provider is loaded with, chosen to break
things: names in several scripts, a disabled account, nested groups, an account in forty
groups.

## Start it

With Carnelian's test extras installed (`prepare.py` uses `cryptography` for the test
certificates):

```bash
export CARNELIAN_TESTBED_SECRET=<any long random string; every password derives from it>
python testbed/prepare.py --host <the name the tests reach the host by>
docker compose --file testbed/compose.yaml --env-file testbed/generated/keycloak.env --profile directory up --detach --build
python testbed/prepare.py --host <the same name> --wait --directory
```

`prepare.py` writes everything to `testbed/generated/` (git-ignored): a test certificate
authority and the server's certificate, the Keycloak realm, the environment files for
compose, the directory's seed script, and `testbed.json`, which tells the tests where each
provider is and what every account's password is. The same secret always gives the same
files. Leave out `--profile directory` and `--directory` to run Keycloak alone.

## Run the tests against it

```bash
python -m pytest --testbed=testbed/generated/testbed.json --directory
```

Without `--testbed` the integration tests are skipped; without `--directory` the LDAP ones
are. Write the option with `=`: given as a separate argument, the path is taken for a test
file.
