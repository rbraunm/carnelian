# SCIM 2.0

Let an identity provider (Microsoft Entra ID, Okta, OneLogin and others) create, update,
deactivate and group your users. Carnelian is the SCIM service provider: it takes each HTTP
request below your SCIM base address, checks the bearer token, parses and validates it
against the SCIM schemas, and answers; your application keeps the users and groups.

Offered: users with the enterprise extension, groups, the whole filter grammar of
RFC 7644, paging, attribute selection, POST, GET, PUT, PATCH, DELETE and the discovery
endpoints.

## What you provide

A **store**, with five methods over dictionaries (each resource as SCIM builds it):

```python
class MyStore:
  def create(self, resourceType: str, resource: dict) -> None: ...
  def get(self, resourceType: str, resourceID: str) -> dict | None: ...
  def replace(self, resourceType: str, resource: dict) -> None: ...
  def delete(self, resourceType: str, resourceID: str) -> None: ...
  def search(self, resourceType: str, query) -> list[dict]: ...  # query is None or a parsed filter
```

`search` can filter in memory with `carnelian.scim.matches(resourceTypes[resourceType],
query, resource)`, or translate the parsed filter (`Compare`, `Present`, `And`, `Or`, `Not`,
`ValuePath`) to your database's query language. Raise `SCIMRefused(409, ..., "uniqueness")`
where your own constraints refuse a resource. This is also where a SCIM user becomes one of
your accounts, and a SCIM group one of your groups.

And a **token check**: a function that takes the bearer token and says whether it is
accepted. Keep only a hash of the token and compare in constant time.

## Answering requests

```python
import hashlib, hmac
from flask import Flask, Response, request
from carnelian.scim import SCIMService

tokenHash = hashlib.sha256(provisioningToken.encode()).hexdigest()
service = SCIMService(MyStore(), "https://app.example.org/scim/v2",
                      lambda token: hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), tokenHash))

app = Flask(__name__)

@app.route("/scim/v2/<path:rest>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def scim(rest):
  answer = service.handle(request.method, "/" + rest, request.query_string.decode("ascii"),
                          dict(request.headers), request.get_data())
  return Response(answer.body, status=answer.status, headers=answer.headers)
```

Run each request in one database transaction, committed only when the answer's status is
below 400: Carnelian checks a request (uniqueness, members, group cycles) and then writes it
in several calls to your store.

An accepted bearer token may do everything the service does on your store. If one service
serves several tenants, or a token should reach less, enforce that in your token check and
your store. Resource IDs are UUIDs Carnelian makes; any other ID in a request is answered
404 without reaching your store.

## Provider notes

- **Entra ID:** set the tenant URL to your base address and the secret token to the bearer
  token. Entra matches users by `userName` and groups by `displayName` (which Carnelian keeps
  unique), sends PATCH operation names in any case, and removes group members by listing
  them in `value`; all of these are handled. A group's PATCH is answered with 204.
- **Okta:** the same base address and token, with "Push Groups" for groups. Okta sends a
  `password` with every new user even when it syncs none, so give the service
  `discardPasswords=True`: passwords are then dropped from requests (Carnelian keeps none
  either way); without it they are refused. Okta renames a group with a PATCH that restates
  its `id`, which is accepted as long as it is the group's own.

## What is refused

A request without the token; an unknown attribute; a value of the wrong type (the string
`"False"` for a boolean); a second primary value; a duplicate key; a password (Carnelian
takes none over SCIM); an unknown query parameter, including sorting; more results than
`maximumResults`; a member that is not a user or group here; a body that is not JSON or not
the SCIM media type. Each refusal is a SCIM error with its status and `scimType`.
