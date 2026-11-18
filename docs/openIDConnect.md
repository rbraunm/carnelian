# OpenID Connect

Sign people in through an OpenID Connect provider: Microsoft Entra ID, Google, Keycloak,
Okta, Auth0 and the rest. Carnelian is the relying party: it sends the person to the
provider with the authorization-code flow and PKCE, takes the code back, exchanges it, and
checks the ID token (signature, issuer, audience, expiry, nonce) before it believes a word.

## What you configure

| Setting | Where it comes from |
|---|---|
| Issuer | The provider's issuer URL, e.g. `https://login.microsoftonline.com/<tenant>/v2.0` |
| Client ID and secret | Registering your application at the provider |
| Redirect URI | Your callback address, registered at the provider exactly as you give it here |

## Signing in

`beginSignIn` gives the address to send the browser to and a `Pending` record; keep the
record **server-side**, found by a random key in a cookie of its own, and hand it back to
`finishSignIn` with the query the browser returns with.

```python
import dataclasses, secrets
from flask import Flask, redirect, request, session, abort
from carnelian.fetching import Fetcher, secureContext
from carnelian.oidc import Pending, RelyingParty, SignInRefused, discover

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
fetcher = Fetcher(secureContext())
provider = discover("https://login.example.org/realms/staff", fetcher)
relyingParty = RelyingParty(provider, "my-app", clientSecret, "https://app.example.org/signin/return", fetcher)
waiting: dict[str, dict] = {}  # use your database or cache in production: one entry per sign-in, used once

@app.get("/signin")
def signIn():
  address, pending = relyingParty.beginSignIn()
  key = secrets.token_urlsafe(32)
  waiting[key] = dataclasses.asdict(pending)
  response = redirect(address)
  response.set_cookie("signin", key, max_age=600, httponly=True, secure=True, samesite="Lax")
  return response

@app.get("/signin/return")
def signInReturn():
  stored = waiting.pop(request.cookies.get("signin", ""), None)
  if stored is None:
    abort(400, "no sign-in is waiting in this browser")
  try:
    identity = relyingParty.finishSignIn(Pending(**stored), dict(request.args))
  except SignInRefused as refusal:
    abort(401, str(refusal))
  session["subject"] = identity.subject  # identity.issuer + identity.subject name the person for good
  return redirect("/")
```

The pending cookie is `SameSite=Lax` because the provider's answer is a top-level
navigation from another site; your own session cookie can stay `Strict`.

## What you get

`Identity` carries `issuer` and `subject` (together, the person's permanent identity at
this provider), and `userName` (`preferred_username`), `email`, `emailVerified`,
`displayName` (`name`) and `groups` when the provider sends them, plus every claim in
`claims`.

Recognise a person by `issuer` and `subject`, never by e-mail or user name alone: in a
multi-tenant provider anyone can create an account with someone else's address. If you
must link to an existing account by e-mail, do it only when `emailVerified` is true and the
provider is one you trust for that domain.

## More than one provider

The `Pending` record names the issuer and client it was made for, and `finishSignIn`
refuses a record from another provider before sending any code anywhere. When the provider
sends `iss` with its answer (RFC 9207), it must match; when its discovery document says it
always does, it is required. Give each provider its own redirect URI all the same, so an
answer can only arrive where it belongs.

## Provider notes

- **Entra ID:** use the v2.0 issuer. To get `groups`, add the groups claim in the
  application's token configuration; large tenants send an overage marker instead, which
  Carnelian refuses rather than guess.
- **Google:** issuer `https://accounts.google.com`; no groups claim.
- **Keycloak:** issuer `https://<host>/realms/<realm>`; add a group-membership mapper with
  `full.path` if you want `/parent/child` group names.

## What is refused

An unsigned token or one signed with `none`, any HMAC algorithm (HS256 and the like, which
would turn the client secret into a signing key), an algorithm the provider did not
announce, a token for another audience or issuer, an expired one, a `state` that does not
match the pending sign-in, a missing or wrong `nonce`, and anything over plain HTTP. Keep
each pending record for one use only, as above, so an answer cannot be replayed.
