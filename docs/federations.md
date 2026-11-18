# Research and education federations

Universities and research institutes mostly sign in through a federation: InCommon in the
United States, and national ones elsewhere (RENATER, SIR, CAFe, SAFIRE, the UK federation,
KENET, and many more), joined worldwide by eduGAIN. A federation vouches for its members by
signing their metadata; a service trusts the federation's key, not each university's.

Carnelian fetches each institution's metadata by the Metadata Query protocol (MDQ: one
small signed document per institution, as InCommon serves its own members and eduGAIN's),
checks the federation's signature and the metadata's expiry, and reads the institution's
identity provider, names and scopes. It then signs a person in through ordinary [SAML](saml.md).

## What you configure

| Setting | Example |
|---|---|
| The federation's MDQ address | `https://mdq.incommon.org` |
| The federation's metadata signing certificate | Downloaded once, checked against the fingerprint the federation publishes |
| The institutions you offer | Their entity IDs, e.g. `urn:mace:incommon:arizona.edu` |
| The scoped identifier you use | `subjectID`, `pairwiseID` or `eduPersonPrincipalName` |

Register your service with the federation using the metadata `serviceProviderMetadata`
writes: your entity ID, assertion consumer address, display names, information and privacy
pages, organization and contacts, and the Research and Scholarship category by default.

## Signing in

```python
from carnelian.federation import Federation, scopedIdentifier, subjectID
from carnelian.fetching import Fetcher, secureContext
from carnelian.saml import ServiceProvider

federation = Federation("InCommon", "https://mdq.incommon.org", open("inc-md-cert-mdq.pem").read(), Fetcher(secureContext()))

institution = federation.institution("urn:mace:incommon:arizona.edu")   # checked, cached until its validUntil
print(institution.displayName("es"))                                     # for your "choose your institution" page
serviceProvider = ServiceProvider("https://app.example.org/saml", "https://app.example.org/signin/saml",
                                  institution.identityProvider)
# ... begin and finish exactly as in the SAML guide, keeping the chosen institution with the pending record ...
person = scopedIdentifier(identity, institution, subjectID)              # e.g. "a1b2c3@arizona.edu"
```

`scopedIdentifier` refuses an identifier whose scope (the part after `@`) is not one the
federation registered for that institution, so one university cannot sign in another's
people. Use `pairwiseID` where the institution releases it (a different identifier for each
service, better for privacy), `subjectID` for one identifier across services, and
`eduPersonPrincipalName` where neither is released.

## What is refused

Metadata not signed by the federation's key, or whose signature does not cover the whole
entity; metadata past its `validUntil` or without one; an answer for another entity; a scope
written as a regular expression; an institution with no scope; an identifier from another
issuer, out of scope, malformed, or sent more than once.
