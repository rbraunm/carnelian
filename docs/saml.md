# SAML 2.0

Sign people in through a SAML identity provider: Shibboleth, Microsoft Entra ID or ADFS,
Okta, Keycloak, SimpleSAMLphp. Carnelian is the service provider of the Web Browser SSO
profile: the request goes out by the Redirect binding, the response comes back by the POST
binding, and nothing in it is read until a signature by the provider's key covers it.

For a research and education federation (InCommon, eduGAIN and the national ones), where
many universities' providers come from one signed source, see [federations](federations.md).

## What you configure

| Setting | Where it comes from |
|---|---|
| Your entity ID | A URL you choose, e.g. `https://app.example.org/saml`; registered at the provider |
| Assertion consumer URL | Your POST address, e.g. `https://app.example.org/signin/saml`; registered at the provider |
| The provider's metadata | Its metadata URL or file: entity ID, single sign-on address, signing certificates |

Configure the provider to sign its responses or its assertions (or both), to send a
persistent or otherwise stable NameID or an attribute you will use as the identity, and,
while the `keys` extra is not in use, not to encrypt assertions or require signed requests.

## Signing in

```python
import dataclasses, secrets
from flask import Flask, redirect, request, session, abort
from carnelian.fetching import Fetcher, secureContext
from carnelian.saml import Pending, SAMLRefused, ServiceProvider, identityProviderFromMetadata

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
metadata = Fetcher(secureContext()).getBytes("https://idp.example.org/metadata", "application/samlmetadata+xml")
serviceProvider = ServiceProvider("https://app.example.org/saml", "https://app.example.org/signin/saml",
                                  identityProviderFromMetadata(metadata, "https://idp.example.org/idp"))
waiting: dict[str, dict] = {}  # your database or cache in production: one entry per sign-in, used once

@app.get("/signin")
def signIn():
  address, pending = serviceProvider.beginSignIn()
  key = secrets.token_urlsafe(32)
  waiting[key] = dataclasses.asdict(pending)
  response = redirect(address)
  # The response comes back by a cross-site POST, which only a SameSite=None (and so Secure) cookie goes with.
  response.set_cookie("signin", key, max_age=600, httponly=True, secure=True, samesite="None")
  return response

@app.post("/signin/saml")
def signInReturn():
  stored = waiting.pop(request.cookies.get("signin", ""), None)
  if stored is None:
    abort(400, "no sign-in is waiting in this browser")
  try:
    identity = serviceProvider.finishSignIn(Pending(**stored), request.form["SAMLResponse"])
  except SAMLRefused as refusal:
    abort(401, str(refusal))
  session["subject"] = identity.nameID
  return redirect("/")
```

The assertion consumer route takes a POST from the provider's site, so leave it out of any
cross-site-request protection that checks the Origin: the signed response is its proof.
If your session cookie is `SameSite=Strict`, answer this POST with a page of your own site
that moves the browser on, so the session cookie travels from then on.

## What you get

`SAMLIdentity` carries `issuer`, `nameID` and its `nameIDFormat`, `sessionIndex`, and
`attributes`: every attribute by its `Name`, each a tuple of values. A transient NameID
changes at every sign-in; use a persistent one, or an attribute, to recognise a person.

## What is refused

A response for another destination or request, from another issuer, or with a failure
status; an assertion that is unsigned, signed by a key not in the metadata, outside its
time window, for another audience, without a bearer confirmation for this request and
address, or seen before (the replay cache); the signature-wrapping attacks (anything read
must be the element the signature covers); a DTD or entity in the XML; an encrypted
assertion while the `keys` extra is not in use.

`ReplayCache` is kept in memory. Behind several processes, use one shared store for it, so
an assertion used on one process is refused on the others.
