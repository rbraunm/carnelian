# CAS

Sign people in through an Apereo CAS server (protocol 3.0), the sign-in many universities
in France, Spain and Latin America run. The browser goes to the CAS login page and comes
back with a one-time service ticket; Carnelian asks the CAS server itself, over HTTPS,
whose ticket it is (`/p3/serviceValidate`) and what attributes it releases.

## What you configure

| Setting | Example |
|---|---|
| The CAS server's address | `https://cas.example.edu/cas` (where `/login` lives) |
| Your service address | `https://app.example.org/signin/cas`, registered in the CAS service registry |

Register the service address in CAS with an attribute release policy for what you need
(for example `mail`, `displayName`, `memberOf`). Carnelian adds a `state` parameter to it
for each sign-in, so register it as a pattern that allows a query string.

## Signing in

```python
import dataclasses, secrets
from flask import Flask, redirect, request, session, abort
from carnelian.cas import CASRefused, CASServer, Pending
from carnelian.fetching import Fetcher, secureContext

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
cas = CASServer("https://cas.example.edu/cas", "https://app.example.org/signin/cas", Fetcher(secureContext()))
waiting: dict[str, dict] = {}  # your database or cache in production: one entry per sign-in, used once

@app.get("/signin")
def signIn():
  address, pending = cas.beginSignIn()
  key = secrets.token_urlsafe(32)
  waiting[key] = dataclasses.asdict(pending)
  response = redirect(address)
  response.set_cookie("signin", key, max_age=600, httponly=True, secure=True, samesite="Lax")
  return response

@app.get("/signin/cas")
def signInReturn():
  stored = waiting.pop(request.cookies.get("signin", ""), None)
  if stored is None:
    abort(400, "no sign-in is waiting in this browser")
  try:
    identity = cas.finishSignIn(Pending(**stored), dict(request.args))
  except CASRefused as refusal:
    abort(401, str(refusal))
  session["user"] = identity.userName
  return redirect("/")
```

## What you get

`CASIdentity` carries `userName` (the CAS user) and `attributes`: each released attribute
by its name, as a tuple of values.

## What is refused

A ticket for another sign-in (the `state` does not match), a missing or malformed service
ticket, a proxy ticket or a ticket that came through a proxy, the server's refusal (with its
code, e.g. `INVALID_TICKET` for a ticket already used), an answer that is not a CAS service
response, a DTD or entity in it, and anything over plain HTTP.
