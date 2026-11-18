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

`federation.institution` refuses by name (`SAMLRefused`) an entity ID over SAML's 1,024
characters, a failed fetch (an entity the MDQ service does not know answers 404), and
metadata that fails its checks. Each refusal is remembered for `refusalCacheSeconds` (60
by default), so a discovery form sending one entity ID again and again fetches it once in
that time; a valid institution is kept until its `validUntil`, at most
`maximumCacheSeconds`.

`scopedIdentifier` refuses an identifier whose scope (the part after `@`) is not one the
federation registered for that institution, so one university cannot sign in another's
people. Only the scoped identifier is checked this way: the NameID, `mail` and other
attributes are whatever the institution says, so never recognise a person by them. Use `pairwiseID` where the institution releases it (a different identifier for each
service, better for privacy), `subjectID` for one identifier across services, and
`eduPersonPrincipalName` where neither is released.

## Every institution at once: the aggregate

To offer "choose your institution" across a whole federation, read its aggregate: one
signed document holding every member. eduGAIN's
(`https://mds.edugain.org/edugain-v2.xml`) is about 95 MB with about 6,600 identity
providers, so it is read as a stream: each entity is built as a small tree, read and
dropped, and the document's canonical form is hashed as it goes by, while it downloads.
Memory follows the largest entity, not the document (about 15 MB traced for eduGAIN's),
and fetching and reading take about a minute.

```python
from carnelian.aggregate import fetchAggregate
from carnelian.fetching import Fetcher, secureContext

fetcher = Fetcher(secureContext(), timeoutSeconds=600)   # the whole download within one deadline
eduGAIN = fetchAggregate("https://mds.edugain.org/edugain-v2.xml", open("mds-v2.cer").read(), fetcher, "eduGAIN")

choices = sorted((institution.displayName("en"), entityID) for entityID, institution in eduGAIN.institutions.items()
                 if not institution.hiddenFromDiscovery)
for entityID, reason in eduGAIN.skipped:
  log.warning("eduGAIN entity %s left out: %s", entityID, reason)

institution = eduGAIN.institution(chosenEntityID)     # refused if absent or past its validUntil
# ... sign in exactly as above, with institution.identityProvider ...
```

eduGAIN's signing certificate is `https://technical.edugain.org/mds-v2.cer`; check its
SHA-256 fingerprint against the one published at `https://technical.edugain.org/metadata`
before trusting it. `readAggregate` takes the document's bytes, or an iterable of chunks,
instead of an address. Refetch on a schedule (eduGAIN asks for every few hours, its
`cacheDuration`) and keep the previous aggregate until the next one verifies.

Nothing is returned until the signature has verified over the whole document. The
aggregate must be an `md:EntitiesDescriptor` whose first child is its signature, with one
reference to its `ID` (or to the whole document), the transforms enveloped-signature then
exclusive canonicalization, and a `validUntil` that has not passed. Refused by name: another
key's signature, any changed byte, a second signature, a nested or wrapping
`EntitiesDescriptor`, any element but `Extensions` and `EntityDescriptor` under it, another
element carrying its `ID`, and a document over `maximumBytes` (256 MB) or with more than
`maximumEntities` (100,000) entities, or an entity over the XML reader's budgets.

Each identity provider is read with the same checks as one from MDQ. One that fails them
(no scope, a scope written as a regular expression, no usable sign-on address), whose own
`validUntil` has passed, or that appears twice is left out and listed in `skipped` with the
reason; log those. Entities with no identity provider (services) are passed over.

## What is refused

Metadata not signed by the federation's key, or whose signature does not cover the whole
entity; metadata past its `validUntil` or without one; an answer for another entity; a scope
written as a regular expression; an institution with no scope; an identifier from another
issuer, out of scope, malformed, or sent more than once.
