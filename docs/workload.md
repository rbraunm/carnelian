# Workload tokens (CI and cloud)

Let a pipeline or a cloud workload sign in to your service with no stored secret. GitHub
Actions, GitLab CI and the cloud providers hand a running job a short-lived OpenID Connect
token on request; the job sends it to you, and Carnelian checks it: the platform's
signature, the issuer, your audience, the times, and that every claim you require has
exactly the value you require. This is how PyPI's trusted publishing works.

## The claims that make a token yours

Every job on a platform gets tokens from the same issuer, signed with the same keys. What
tells your pipeline apart is its claims, so a verifier must name at least one, and naming
none is refused when the verifier is made. For GitHub Actions:

| Claim | Pins the token to |
|---|---|
| `repository_id` (or `repository`) | Your repository; the id survives a rename, the name does not |
| `ref` | A branch or tag, e.g. `refs/heads/main` |
| `environment` | A GitHub environment, which can require reviewers before the job runs |
| `workflow_ref` | One workflow file at one ref |

## Verifying

```python
from carnelian.fetching import Fetcher, secureContext
from carnelian.workload import WorkloadRefused, WorkloadVerifier, discoverIssuer, githubActions

fetcher = Fetcher(secureContext())
verifier = WorkloadVerifier(discoverIssuer(githubActions, fetcher), "my-service",
                            {"repository_id": "123456789", "ref": "refs/heads/main", "environment": "production"}, fetcher)
try:
  identity = verifier.verify(bearerToken)  # from the request's Authorization header
except WorkloadRefused as refusal:
  ...  # answer 401 with the reason
```

Write the issuer exactly as its tokens name it. Some end in a slash (Entra ID's
`https://sts.windows.net/<tenant>/`, Auth0's); the slash is part of the name, and a token
naming the issuer without it is another issuer's.

Keep one verifier for the life of the process: it caches the issuer's keys, fetching them
again when they are a day old or when a token names a key it does not have. Fetches go one
at a time, at most once a minute, and after a failed or malformed answer the wait doubles
up to 15 minutes, so unknown keys or an issuer that is down cannot make every request fetch
them; keys already fetched stay in use until a day after the fetch that brought them. An
issuer that cannot be reached is a `WorkloadRefused` like any other refusal.

In the workflow, ask for the token with your audience and send it:

```yaml
permissions:
  id-token: write
steps:
  - run: |
      token=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=my-service" | jq -r .value)
      curl -H "Authorization: Bearer $token" https://my-service.example.org/api/...
```

## What is refused

A token not signed by the issuer's keys, or signed with `none` or an HMAC algorithm; one
from another issuer, for another audience, expired, issued in the future or not yet valid;
one without a subject; one whose required claims differ in any way from what you require.
