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

Configure the provider to sign its responses or its assertions (or both), and to send a
persistent or otherwise stable NameID or an attribute you will use as the identity. Without
keys of your own (below), configure it not to encrypt assertions or require signed requests.

Give the provider your metadata to register, from `serviceProviderMetadata`: the entity ID
and assertion consumer address are enough, and display names, information and privacy
pages, organization and contacts are written when you pass them.

```python
from carnelian.saml import serviceProviderMetadata

metadata = serviceProviderMetadata("https://app.example.org/saml", "https://app.example.org/signin/saml",
                                   technicalContact="it@example.org")  # serve it at an address the provider can fetch
```

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
time window, for another audience, without a bearer confirmation whose Recipient is your
assertion consumer address and whose InResponseTo is this request, without exactly one
AuthnStatement, past its SessionNotOnOrAfter, with any condition other than an audience
restriction (OneTimeUse, ProxyRestriction), or seen before from this issuer; the
signature-wrapping attacks (anything read must be the element the signature covers);
element content where text is expected (an AttributeValue may be one NameID, the form
eduPersonTargetedID takes); a DTD or entity in the XML, a document nested too deep or too
large; an encrypted assertion when no decryption key is configured. The confirmation's Address
is not checked: behind proxies and NAT it rarely matches.

`SAMLIdentity.sessionNotOnOrAfter` is the time the provider wants the session to end, if it
said; honour it in your session.

`ReplayCache` is kept in memory, in one process. Behind several processes, give
`ServiceProvider` a `ReplayStore` of your own: its `admit(issuer, assertionID, until, now)`
must claim the pair atomically (a database table with the pair as its unique key) and raise
`SAMLRefused` when it is already claimed. The same store keeps the provider's LogoutRequest
IDs and, under your own entity ID, the IDs of your logout requests already answered.

## Keys of your own: encryption, signed requests, single logout

Decrypting assertions and signing requests need private keys, and Carnelian does no
private-key cryptography of its own. The module `carnelian.keys` defines the interface: a
`SigningKey` signs bytes, a `DecryptionKey` unwraps a content key by RSA-OAEP and decrypts
content by AES-GCM or AES-CBC. The `keys` extra backs it with pyca/cryptography:

```bash
python -m pip install "carnelian[keys]"
```

```python
from pathlib import Path
from carnelian.keys import LocalDecryptionKey, LocalSigningKey

signingKey = LocalSigningKey(Path("sp-signing.key").read_bytes(), Path("sp-signing.crt").read_bytes())
decryptionKeys = (LocalDecryptionKey(Path("sp-encryption.key").read_bytes(), Path("sp-encryption.crt").read_bytes()),)
serviceProvider = ServiceProvider("https://app.example.org/saml", "https://app.example.org/signin/saml", identityProvider,
                                  signingKey=signingKey, decryptionKeys=decryptionKeys,
                                  singleLogoutURL="https://app.example.org/signout/saml")
```

Nothing else in Carnelian imports `carnelian.keys`, so an application that never builds a
key never loads `cryptography`. To keep keys in a hardware module or a cloud key service,
write classes with the same members (`certificate`, `signatureAlgorithm`, `sign`;
`certificate`, `unwrapKey`, `decryptContent`) over that service; a decryption failure must
raise a `ValueError`, the same for every cause.

The `keys` extra brings pyca/cryptography (Apache-2.0 or BSD) and, in its wheels, OpenSSL 3
(Apache-2.0). The FSF holds Apache-2.0 incompatible with GPLv2-only; a GPLv2-only program
that redistributes itself bundled with the extra should check that combination (CPython's
own `ssl` module already loads an Apache-2.0 OpenSSL).

Use one key pair to sign and another to decrypt (one key under both is refused): XML
Encryption 1.1 asks for this, since an oracle on one use of a key attacks the other. Give
several decryption keys while you roll one over; each is tried. Publish the certificates in
your metadata: `serviceProviderMetadata(..., signingCertificate=signingKey.certificate,
encryptionCertificates=tuple(key.certificate for key in decryptionKeys),
encryptionPolicy=..., singleLogoutURL=...)` writes the signing and encryption
KeyDescriptors, an `md:EncryptionMethod` for every algorithm your policy allows (so a
provider that reads them, Shibboleth among them, picks one of those), `AuthnRequestsSigned`,
and your logout address for the Redirect and POST bindings.

### Encrypted assertions, and which algorithms

`EncryptionPolicy` names the algorithms you accept; the encrypted document never chooses.
The default accepts RSA-OAEP key transport (`xmlenc#rsa-oaep-mgf1p` and `xmlenc11#rsa-oaep`,
with SHA-1 to SHA-512 digests and MGF1 functions) and AES-128-GCM or AES-256-GCM content.
Everything else is refused by name before any key is used:

- **RSA PKCS #1 v1.5 key transport (`xmlenc#rsa-1_5`) is always refused**, and a policy
  that lists it is refused. Bleichenbacher's attack recovers the content key from how a
  service provider reacts to modified key ciphertexts, and it has been shown against XML
  Encryption in particular (Jager, Schinzel and Somorovsky, "Bleichenbacher's Attack Strikes
  Again: Breaking PKCS#1 v1.5 in XML Encryption", ESORICS 2012); its timing variant still
  breaks many libraries (the Marvin attack, 2023). OpenSSL's implicit rejection does not
  help here, because the attacker also chooses the content algorithm the recovered key is
  used with.
- **AES-CBC is off by default.** Its padding lets an attacker decrypt an assertion byte by
  byte from the service provider's errors, about 14 requests a byte (Jager and Somorovsky,
  "How to Break XML Encryption", CCS 2011), and where CBC is accepted beside GCM the same
  oracle reaches GCM ciphertexts too (Jager, Paterson and Somorovsky, "One Bad Apple:
  Backwards Compatibility Attacks on State-of-the-Art Cryptography", NDSS 2013). For a
  provider that can only send CBC (older AD FS), add `aes128CBC` or `aes256CBC` to
  `contentAlgorithms`, and configure the provider to sign the whole Response: CBC is
  decrypted only after the Response's own signature, which covers the ciphertext, has been
  verified. A signature on the assertion is inside the ciphertext and comes too late, so a
  CBC assertion in an unsigned Response is refused.
- One EncryptedData of Type `xmlenc#Element`, and one EncryptedKey, inside its KeyInfo or
  beside it and named there by a RetrievalMethod. A second EncryptedKey, a CipherReference,
  an OAEP label, or an MGF element with `rsa-oaep-mgf1p` is refused by name.

Every failure after that point (a key that does not unwrap, a tag that does not verify,
padding, a plaintext that is not one element) is one refusal, "the encrypted assertion does
not decrypt with this service provider's keys", so the answer says nothing about which step
failed. The work done does not tell either: every configured key unwraps and decrypts the
content, and a key that does not unwrap decrypts with a random content key of the right
length, which fails at the GCM tag as a tampered ciphertext does. A key service of your own
should likewise raise the same error for every failure.

The decrypted assertion is parsed with the same limits as the response, in the namespaces
in scope where it was encrypted, and goes through every check above: its own signature when
the Response is unsigned, audience, conditions, confirmation, replay. Unless it carries its
own signature, it must declare every namespace prefix it uses itself: the Response's
signature (exclusive canonicalization) does not cover a declaration that nothing outside the
ciphertext uses, so such a prefix could be rebound to change what the assertion says, and
an assertion that takes one from outside is refused by name.

saml2int, the federation interoperability profile, asks identity providers to encrypt with
AES-GCM and RSA-OAEP and service providers to decrypt with any of their configured keys;
the default policy is that profile.

### Signed requests

With a `signingKey`, `beginSignIn` signs the AuthnRequest as the Redirect binding does
(SAML bindings 3.4.4.1): the signature is over the exact query string
`SAMLRequest=...&RelayState=...&SigAlg=...`, not an XML signature, and `SigAlg` and
`Signature` are added to the address. A `LocalSigningKey` signs with RSA-SHA256 unless you
name another `signatureAlgorithm`: RSA-SHA384, RSA-SHA512, or ECDSA with SHA-256 to SHA-512
for an EC key on P-256, P-384 or P-521.

### Single logout

Single logout needs a signing key, the provider's SingleLogoutService for the Redirect
binding (read from its metadata), and your own logout address (`singleLogoutURL`). Every
message out is signed by the Redirect binding; every message in must be signed, by the
Redirect binding's query signature or, when posted, by an XML signature, with a key from the
provider's metadata.

```python
@app.get("/signout")
def signOut():
  person = session["saml"]  # nameID, nameIDFormat and sessionIndex, kept at sign-in
  address, pending = serviceProvider.beginSignOut(person["nameID"], person["nameIDFormat"], person["sessionIndex"])
  session.clear()
  key = secrets.token_urlsafe(32)
  waiting[key] = dataclasses.asdict(pending)
  response = redirect(address)
  response.set_cookie("signout", key, max_age=600, httponly=True, secure=True, samesite="None")
  return response

@app.route("/signout/saml", methods=["GET", "POST"])
def signOutReturn():
  raw = request.query_string.decode("ascii")  # the query exactly as sent: the signature covers its encoding
  try:
    if "SAMLRequest" in request.values:  # the provider ends a session that started elsewhere
      asked = (serviceProvider.readSignOutRequest(query=raw) if request.method == "GET"
               else serviceProvider.readSignOutRequest(samlRequest=request.form["SAMLRequest"],
                                                       relayState=request.form.get("RelayState")))
      endSessions(asked.nameID, asked.sessionIndexes)  # yours: this person's sessions from this provider
      return redirect(serviceProvider.answerSignOut(asked))
    stored = waiting.pop(request.cookies.get("signout", ""), None)
    if stored is None:
      abort(400, "no logout is waiting in this browser")
    if request.method == "GET":
      serviceProvider.finishSignOut(Pending(**stored), query=raw)
    else:
      serviceProvider.finishSignOut(Pending(**stored), samlResponse=request.form["SAMLResponse"])
  except SAMLRefused as refusal:
    abort(400, str(refusal))
  return redirect("/")
```

`finishSignOut` checks the LogoutResponse's signature, that it has an ID, that it answers
this request (InResponseTo), that it is for your logout address (Destination), that it was
issued between the request and now, its issuer, and its status: anything but Success is
refused with the provider's status. It accepts one answer per request: the request's ID is
claimed in the `ReplayStore` under your own entity ID, so a second answer is refused, on
every process sharing the store. `readSignOutRequest`
checks the signature, Destination and issuer, that the request was issued within
`pendingSeconds` and is not past its NotOnOrAfter, that its ID has not been seen before (the
`ReplayStore`), and that it names a plain NameID (EncryptedID and BaseID are refused); it
returns the NameID, the SessionIndexes and the RelayState. End the sessions before you
answer: `answerSignOut` always says Success, signed, and is refused by name without a
signing key.

In a Redirect binding query, `SAMLRequest`, `SAMLResponse`, `RelayState`, `SigAlg` and
`Signature` are read by their literal names, as the signature covers them; a parameter that
spells one of them encoded (`Relay%53tate`) or carries it twice is refused. The provider's
single sign-on and logout addresses may carry a query of their own, but not a fragment or
any of these parameters. Names, session indexes and other text you pass are escaped in the
XML Carnelian writes; a character XML cannot carry (a control character, a lone surrogate)
is refused by name.
