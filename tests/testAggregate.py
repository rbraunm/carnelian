# SPDX-License-Identifier: MIT
"""Federation aggregates read as a stream: the streamed canonical form against the tree's and libxml2's,
aggregates signed by signxml and attacked, memory against document size, and eduGAIN's real aggregate."""

import copy
import re
import time
import tracemalloc
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import given, settings
from hypothesis import strategies as st
from lxml import etree
from signxml import XMLSigner

from carnelian.aggregate import fetchAggregate, readAggregate
from carnelian.fetching import Fetcher, secureContext
from carnelian.saml import SAMLRefused
from carnelian.xmlTree import DocumentStream, Text, XMLRefused, canonical, parse

from testFederation import federationCertificate, federationKey, idpCertificate, idpKey, instant, now

vectors = Path(__file__).parent / "vectors"
dsigNamespace = "http://www.w3.org/2000/09/xmldsig#"
mdNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"


# ---- the streamed canonical form ----------------------------------------------

def streamed(data, prefixes=(), leaveOutFirstChild=False, chunkSize=7):
  pieces = []
  holder = {}

  def onRoot(root):
    if not leaveOutFirstChild:
      holder["stream"].canonicalize(pieces.append, prefixes)

  def onChild(child):
    if leaveOutFirstChild and not pieces:
      holder["stream"].canonicalize(pieces.append, prefixes, leaveOut=child)

  stream = holder["stream"] = DocumentStream(onRoot, onChild, len(data))
  for offset in range(0, len(data), chunkSize):
    stream.feed(data[offset:offset + chunkSize])
  stream.close()
  return b"".join(pieces)


def treeCanonical(data, prefixes=(), leaveOutFirstChild=False):
  root = parse(data)
  return canonical(root, prefixes, leaveOut=root.elements()[0] if leaveOutFirstChild else None)


def lxmlCanonical(data, prefixes=()):
  return etree.tostring(etree.fromstring(data), method="c14n", exclusive=True, with_comments=False,
                        inclusive_ns_prefixes=list(prefixes) or None)


documents = {
  "namespaces at several levels": b"""<p:a xmlns:p="urn:p" xmlns:unused="urn:u"><p:b xmlns:q="urn:q" q:x="1"><q:c/></p:b>
  <p:d xmlns:p="urn:other"><p:e xmlns:p="urn:p"/></p:d></p:a>""",
  "default namespaces": b"""<a xmlns="urn:a"><b xmlns=""><c xmlns="urn:c" z="1" y="2"/></b><d/><e xmlns="urn:a"/></a>""",
  "xml:lang and sorted attributes": b"""<r xmlns:p="urn:p" xmlns:q="urn:q" b="x" xml:lang="ar" q:a="2" p:a="1" a="0"><s xml:lang="es"/></r>""",
  "escaping": b"""<r a="&lt;&amp;&quot;&#9;&#10;&#13;'&gt;"><t>&lt;&gt;&amp;&#13;" caf\xc3\xa9 \xe2\x9c\x93</t></r>""",
  "comments, CDATA and instructions": b"""<?xml version="1.0" encoding="UTF-8"?>
<!-- before --><r><!-- one --><a>x<!---->y<![CDATA[<b> & ]]>z</a><?pi some data?><?bare?><b><![CDATA[]]></b></r><!-- after -->""",
  "text at the top level": b"""<r>
  text &amp; more
  <a/>
  between<b>in</b>
</r>""",
}


@pytest.mark.parametrize("name", documents)
@pytest.mark.parametrize("prefixes", [(), ("p", "#default")])
@pytest.mark.parametrize("chunkSize", [1, 7, 1 << 20])
def testTheStreamedCanonicalFormIsTheTreesAndLibxml2s(name, prefixes, chunkSize):
  data = documents[name]
  assert streamed(data, prefixes, chunkSize=chunkSize) == treeCanonical(data, prefixes)
  assert streamed(data, prefixes, leaveOutFirstChild=True, chunkSize=chunkSize) == treeCanonical(data, prefixes, True)
  assert streamed(data, chunkSize=chunkSize) == lxmlCanonical(data)


def escaped(text, attribute=False):
  text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#13;")
  return text.replace('"', "&quot;").replace("\t", "&#9;").replace("\n", "&#10;") if attribute else text


characters = st.text(alphabet="ab &<>\"'\t\r\n\u00e9\u2713]", max_size=6)


@st.composite
def elements(draw, depth=0, inScope=None):
  inScope = inScope or {}
  # libxml2 writes a namespace URI unescaped, unlike C14N, so URIs here need no escaping.
  declared = draw(st.dictionaries(st.sampled_from(["", "p", "q"]), st.sampled_from(["urn:x", "urn:y", "urn:z?a=1"]),
                                  max_size=2))
  if draw(st.booleans()) and "" not in declared:
    declared[""] = draw(st.sampled_from(["", "urn:x"]))
  scope = {**inScope, **declared}
  prefix = draw(st.sampled_from(["", *sorted(prefix for prefix in scope if prefix)]))
  name = f"{prefix}:e" if prefix else "e"
  attributeNames = draw(st.lists(st.sampled_from(["k", "m", "xml:lang", *(f"{p}:k" for p in sorted(scope) if p)]),
                                 unique_by=lambda attributeName: attributeName.rpartition(":")[2], max_size=3))
  attributes = "".join(f' {attributeName}="{escaped(draw(characters), True)}"' for attributeName in attributeNames)
  declarations = "".join(f' xmlns{":" + p if p else ""}="{escaped(uri, True)}"' for p, uri in declared.items())
  children = []
  for kind in draw(st.lists(st.sampled_from(["text", "comment", "cdata", "instruction", "element"]), max_size=4)):
    if kind == "text":
      children.append(escaped(draw(characters)))
    elif kind == "comment":
      children.append(f"<!--{draw(st.sampled_from(['', 'x', ' a b ']))}-->")
    elif kind == "cdata":
      children.append(f"<![CDATA[{draw(characters).replace(']', '')}]]>")
    elif kind == "instruction":
      children.append(f"<?pi{draw(st.sampled_from(['', ' data', ' a b']))}?>")
    elif depth < 3:
      children.append(draw(elements(depth + 1, scope)))
  return f"<{name}{declarations}{attributes}>{''.join(children)}</{name}>"


@settings(max_examples=300, deadline=None)
@given(elements(), st.integers(min_value=1, max_value=40), st.sampled_from([(), ("p",), ("#default", "q")]))
def testAnyDocumentStreamsToItsTreesCanonicalForm(document, chunkSize, prefixes):
  data = document.encode("utf-8")
  assert streamed(data, prefixes, chunkSize=chunkSize) == treeCanonical(data, prefixes)
  if parse(data).elements():
    assert streamed(data, prefixes, True, chunkSize) == treeCanonical(data, prefixes, True)
  assert streamed(data, chunkSize=chunkSize) == lxmlCanonical(data)


def testTheStreamKeepsNoChildrenOnItsDocumentElement():
  seen = []
  stream = DocumentStream(lambda root: None, seen.append, 1000)
  stream.feed(b"<r>x<a><b/>t</a><c/></r>")
  stream.close()
  assert stream.root.children == [] and [child.qualifiedName for child in seen] == ["a", "c"]
  assert [node.qualifiedName for node in seen[0].elements()] == ["b"] and seen[0].children[1] == Text("t")


@pytest.mark.parametrize("data, why", [
  (b"<r/><?late pi?>", "processing instruction outside the document element"),
  (b"<!DOCTYPE r [<!ENTITY e 'x'>]><r>&e;</r>", "DOCTYPE"),
  (b"<r><a>" + b"<b/>" * 10_000 + b"</a></r>", "more than 10000 elements"),
  (b"<r>" + b"<a>" * 70 + b"</a>" * 70 + b"</r>", "nested deeper than 64"),
  (b"<r>" + b" " * 2000 + b"</r>", "larger than 1000 bytes"),
  (b"<r><a></b></r>", "not well-formed"),
])
def testTheStreamRefusesWhatParseRefuses(data, why):
  stream = DocumentStream(lambda root: None, lambda child: None, 1000 if b" " * 2000 in data else 10**7)
  with pytest.raises(XMLRefused, match=why):
    stream.feed(data)
    stream.close()


# ---- signed aggregates ----------------------------------------------------------

namespaces = (f'xmlns:md="{mdNamespace}" xmlns:ds="{dsigNamespace}" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" '
              'xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"')


def identityProvider(number, scopes=None, validUntil=None):
  scopes = f'<shibmd:Scope regexp="false">u{number}.example.edu</shibmd:Scope>' if scopes is None else scopes
  until = f' validUntil="{instant(validUntil)}"' if validUntil is not None else ""
  return (f'<md:EntityDescriptor entityID="https://idp{number}.example.edu/idp"{until}><md:Extensions>'
          '<mdrpi:RegistrationInfo registrationAuthority="https://federation.example.org"/></md:Extensions>'
          '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
          f'<md:Extensions>{scopes}<mdui:UIInfo><mdui:DisplayName xml:lang="en">University {number}</mdui:DisplayName>'
          f'<mdui:DisplayName xml:lang="es">Universidad {number}</mdui:DisplayName></mdui:UIInfo></md:Extensions>'
          '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
          f'{idpCertificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
          '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
          f'Location="https://idp{number}.example.edu/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>')


def serviceProvider(number):
  return (f'<md:EntityDescriptor entityID="https://sp{number}.example.org/sp"><md:SPSSODescriptor '
          'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService '
          'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
          f'Location="https://sp{number}.example.org/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>')


def aggregate(entities, validUntil=86400, identifier="aggregate", signature='<ds:Signature Id="placeholder"/>'):
  until = f' validUntil="{instant(validUntil)}"' if validUntil is not None else ""
  return (f'<md:EntitiesDescriptor {namespaces} Name="https://federation.example.org" ID="{identifier}"{until}>\n'
          f'{signature}\n<md:Extensions><mdrpi:PublicationInfo publisher="https://federation.example.org"/></md:Extensions>\n'
          + "\n".join(entities) + "\n</md:EntitiesDescriptor>")


def signed(text, key=federationKey, reference="#aggregate"):
  root = etree.fromstring(text.encode("utf-8"))
  return etree.tostring(XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                                  c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
    root, key=key, reference_uri=reference, always_add_key_value=False))


def read(document, clock=lambda: now, **options):
  return readAggregate(document, federationCertificate, "Example", clock=clock, **options)


members = [identityProvider(1), serviceProvider(1), identityProvider(2), identityProvider(3, scopes=""),
           identityProvider(4, scopes='<shibmd:Scope regexp="true">^.*$</shibmd:Scope>'),
           identityProvider(5, validUntil=-60), identityProvider(6, validUntil=600), identityProvider(7),
           identityProvider(7), serviceProvider(2)]


def testASignedAggregateGivesItsInstitutionsAndNamesWhatItLeftOut():
  read_ = read(signed(aggregate(members)))
  assert sorted(read_.institutions) == ["https://idp1.example.edu/idp", "https://idp2.example.edu/idp",
                                        "https://idp6.example.edu/idp"]
  institution = read_.institution("https://idp2.example.edu/idp")
  assert institution.scopes == ("u2.example.edu",) and institution.displayName("es") == "Universidad 2"
  assert institution.registrationAuthority == "https://federation.example.org"
  assert institution.identityProvider.singleSignOnURL == "https://idp2.example.edu/sso"
  assert institution.identityProvider.signingKeys[0].modulus == idpKey.public_key().public_numbers().n
  assert institution.validUntil == now + 86400 and read_.institution("https://idp6.example.edu/idp").validUntil == now + 600
  assert [(entityID.split("/")[2], reason) for entityID, reason in read_.skipped] == [
    ("idp3.example.edu", "https://idp3.example.edu/idp has no scope in Example's metadata, so it can vouch for no one"),
    ("idp4.example.edu", "https://idp4.example.edu/idp has a scope written as a regular expression, which is refused"),
    ("idp5.example.edu", f"it expired at {instant(-60)}"),
    ("idp7.example.edu", "it appears more than once in the aggregate"),
  ]


def testAWholeDocumentReferenceIsAccepted():
  assert sorted(read(signed(aggregate(members[:2]), reference=None)).institutions) == ["https://idp1.example.edu/idp"]


def testLookingUpAnInstitution():
  ticks = [now]
  source = read(signed(aggregate(members)), clock=lambda: ticks[0])
  with pytest.raises(SAMLRefused, match="https://sp1.example.org/sp is not an identity provider in Example's aggregate"):
    source.institution("https://sp1.example.org/sp")
  ticks[0] = now + 600
  with pytest.raises(SAMLRefused, match="Example's aggregate expired for https://idp6.example.edu/idp"):
    source.institution("https://idp6.example.edu/idp")
  assert source.institution("https://idp1.example.edu/idp").entityID == "https://idp1.example.edu/idp"


def testAChangedByteAnywhereOutsideTheSignatureIsRefused():
  document = signed(aggregate([identityProvider(1), serviceProvider(1)]))
  start, end = document.index(b"<ds:Signature"), document.index(b"</ds:Signature>") + len(b"</ds:Signature>")
  assert read(document).institutions
  changed = 0
  for offset, byte in enumerate(document):
    if start <= offset < end or not chr(byte).isalnum():
      continue
    altered = document[:offset] + (b"x" if byte != ord("x") else b"y") + document[offset + 1:]
    with pytest.raises(SAMLRefused, match="Example's aggregate is refused"):
      read(altered)
    changed += 1
  assert changed > 1000


def documentWith(change):
  root = etree.fromstring(signed(aggregate(members[:2])))
  change(root)
  return etree.tostring(root)


def signatureOf(root):
  return root.find(f"{{{dsigNamespace}}}Signature")


def secondSignature(root):
  root.insert(2, copy.deepcopy(signatureOf(root)))


def extraTransform(root):
  transforms = root.find(f".//{{{dsigNamespace}}}Transforms")
  transforms.append(copy.deepcopy(transforms[1]))


def otherReference(root):
  root.find(f".//{{{dsigNamespace}}}Reference").set("URI", "#elsewhere")


def wrapped(root):
  wrapper = etree.Element(f"{{{mdNamespace}}}EntitiesDescriptor", nsmap={"md": mdNamespace},
                          validUntil=instant(86400), ID="outer")
  wrapper.append(root)
  return wrapper


def borrowedIdentifier(root):
  root[-1].set("ID", "aggregate")


@pytest.mark.parametrize("document, why", [
  (lambda: signed(aggregate(members[:2]), rsa.generate_private_key(public_exponent=65537, key_size=2048)),
   "the signature does not verify with any trusted key"),
  (lambda: signed(aggregate(members[:2], validUntil=None)), "its validUntil None is not a UTC dateTime"),
  (lambda: signed(aggregate(members[:2], validUntil=-1)), f"it expired at {instant(-1)}"),
  (lambda: documentWith(otherReference), "the reference '#elsewhere' is not to the EntitiesDescriptor's ID 'aggregate'"),
  (lambda: documentWith(extraTransform), "the transforms must be exactly enveloped-signature, then exclusive c14n"),
  (lambda: documentWith(secondSignature), "it has a second ds:Signature"),
  (lambda: etree.tostring(wrapped(etree.fromstring(signed(aggregate(members[:2]))))),
   "it is not signed: its first element is <md:EntitiesDescriptor>, not ds:Signature"),
  (lambda: documentWith(borrowedIdentifier), "<md:EntityDescriptor> also carries the EntitiesDescriptor's ID 'aggregate'"),
  (lambda: aggregate(members[:2], signature="").encode(), "it is not signed: its first element is <md:Extensions>"),
  (lambda: signed(aggregate(members[:2]).replace("<md:Extensions>", "<md:Extensions><md:EntitiesDescriptor/>", 1)
                  .replace("</md:Extensions>\n", "</md:Extensions>\n<md:EntitiesDescriptor/>\n", 1)),
   "a nested EntitiesDescriptor is refused"),
  (lambda: signed(aggregate([*members[:2], f'<md:Organization xmlns:md="{mdNamespace}"/>'])),
   "<md:Organization> is not accepted in an EntitiesDescriptor"),
  (lambda: signed(identityProvider(1).replace("<md:EntityDescriptor ", f'<md:EntityDescriptor {namespaces} ID="aggregate" ', 1)),
   "the document is <md:EntityDescriptor>, not an md:EntitiesDescriptor"),
])
def testAggregatesThatCannotBeTrustedAreRefusedByName(document, why):
  with pytest.raises(SAMLRefused, match=f"^Example's aggregate is refused: {re.escape(why)}"):
    read(document())


def testTheBudgetsAreRefusedByName():
  document = signed(aggregate([serviceProvider(number) for number in range(20)]))
  with pytest.raises(SAMLRefused, match="it has more than 19 entities"):
    read(document, maximumEntities=19)
  with pytest.raises(SAMLRefused, match=f"the XML is larger than {len(document) - 1} bytes"):
    read(document, maximumBytes=len(document) - 1)
  assert read(document, maximumEntities=20, maximumBytes=len(document)).institutions == {}


def testChunksAreReadLikeTheWholeDocument():
  document = signed(aggregate(members))
  chunks = (document[offset:offset + 333] for offset in range(0, len(document), 333))
  assert sorted(read(chunks).institutions) == sorted(read(document).institutions)


class Recorded:
  def __init__(self, answer):
    self.answer, self.asked = answer, []

  def getBytes(self, address, accept):
    self.asked.append((address, accept))
    return self.answer


def testAnAggregateIsFetched():
  fetcher = Recorded(signed(aggregate(members[:2])))
  source = fetchAggregate("https://federation.example.org/aggregate.xml", federationCertificate, fetcher, "Example",
                          clock=lambda: now)
  assert list(source.institutions) == ["https://idp1.example.edu/idp"]
  assert fetcher.asked == [("https://federation.example.org/aggregate.xml", "application/samlmetadata+xml")]


# ---- memory follows the largest entity, not the document ------------------------------

def peakWhileReading(document):
  tracemalloc.start()
  try:
    source = read(document)
    return tracemalloc.get_traced_memory()[1], source
  finally:
    tracemalloc.stop()


def testMemoryFollowsTheLargestEntityNotTheDocument():
  small = signed(aggregate([identityProvider(1)] + [serviceProvider(number) for number in range(1000)]))
  large = signed(aggregate([identityProvider(1)] + [serviceProvider(number) for number in range(8000)]))
  smallPeak, _ = peakWhileReading(small)
  largePeak, source = peakWhileReading(large)
  assert list(source.institutions) == ["https://idp1.example.edu/idp"] and len(large) > 1_900_000
  assert largePeak < len(large) / 3
  assert largePeak < smallPeak * 1.5


# ---- eduGAIN's real aggregate -----------------------------------------------------

eduGAINAggregate = "https://mds.edugain.org/edugain-v2.xml"
# Published at https://technical.edugain.org/metadata under "Signing certificate fingerprints".
eduGAINFingerprint = "BD:21:40:48:9A:9B:D7:40:44:DD:68:05:34:F7:78:88:A9:C1:3B:0A:C1:7C:4F:3A:03:6E:0F:EC:6D:89:99:95"


def testTheEduGAINCertificateIsThePublishedOne():
  certificate = x509.load_pem_x509_certificate((vectors / "eduGAINMetadataSigning.pem").read_bytes())
  assert certificate.fingerprint(hashes.SHA256()).hex(":").upper() == eduGAINFingerprint


@pytest.fixture(scope="module")
def eduGAIN(request):
  if not request.config.getoption("--live"):
    pytest.skip("live test: run with --live to read eduGAIN's published aggregate")
  certificate = (vectors / "eduGAINMetadataSigning.pem").read_text(encoding="ascii")
  assert x509.load_pem_x509_certificate(certificate.encode()).fingerprint(hashes.SHA256()).hex(":").upper() == eduGAINFingerprint
  started = time.perf_counter()
  source = fetchAggregate(eduGAINAggregate, certificate, Fetcher(secureContext(), timeoutSeconds=600,
                                                                 maximumBytes=256 * 1024 * 1024), "eduGAIN")
  fetchedAndRead = time.perf_counter() - started
  document = Fetcher(secureContext(), timeoutSeconds=600, maximumBytes=256 * 1024 * 1024).getBytes(
    eduGAINAggregate, "application/samlmetadata+xml")
  started = time.perf_counter()
  readAggregate(document, certificate, "eduGAIN")
  readOnly = time.perf_counter() - started
  tracemalloc.start()
  try:
    readAggregate(document, certificate, "eduGAIN")
    peak = tracemalloc.get_traced_memory()[1]
  finally:
    tracemalloc.stop()
  print(f"\neduGAIN: {len(document)} bytes, {len(source.institutions)} institutions, {len(source.skipped)} left out; "
        f"fetched and read in {fetchedAndRead:.1f} s, read in {readOnly:.1f} s, peak {peak / 1e6:.1f} MB traced")
  return source, len(document), peak


def testEduGAINsAggregateIsReadInBoundedMemory(eduGAIN):
  source, size, peak = eduGAIN
  assert len(source.institutions) > 5000 and size > 50_000_000 and peak < size / 4


@pytest.mark.parametrize("entityID, scope, authority", [
  ("urn:mace:incommon:arizona.edu", "arizona.edu", "https://incommon.org"),
  ("https://idp.rsu.edu.ng/idp/shibboleth", "rsu.edu.ng", "http://ukfederation.org.uk"),
])
def testEduGAINsMembersAreFound(eduGAIN, entityID, scope, authority):
  institution = eduGAIN[0].institution(entityID)
  assert scope in institution.scopes and institution.registrationAuthority == authority
  assert institution.identityProvider.singleSignOnURL.startswith("https://") and institution.identityProvider.signingKeys
