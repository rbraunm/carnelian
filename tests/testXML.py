# SPDX-License-Identifier: MIT
"""Reading XML safely, and Exclusive XML Canonicalization against libxml2 (through lxml)."""

import tracemalloc

import pytest
from lxml import etree

from carnelian import xmlTree
from carnelian.xmlTree import XMLRefused, canonical, parse

documents = {
  "saml-like": b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1" Version="2.0">
  <saml:Issuer>https://idp.example.org</saml:Issuer>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="a1" IssueInstant="2026-11-17T00:00:00Z">
    <saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">/field/team-a</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>""",
  "default namespaces": b"""<a xmlns="urn:a"><b xmlns=""><c xmlns="urn:c" z="1" y="2"/></b><d/></a>""",
  "attribute order and escaping": b"""<r xmlns:p="urn:p" xmlns:q="urn:q" b="x" a="&lt;&amp;&quot;&#9;&#10;&#13;" q:a="2" p:a="1"><t>&lt;&gt;&amp;&#13; caf\xc3\xa9 \xe2\x9c\x93</t><e></e><?pi data?><!-- gone --></r>""",
  "redeclared prefixes": b"""<p:a xmlns:p="urn:one"><p:b xmlns:p="urn:two"><p:c xmlns:p="urn:one" xml:lang="ar"/></p:b></p:a>""",
  "unused declarations": b"""<a xmlns:unused="urn:u" xmlns:p="urn:p"><b p:x="1"/><c><d xmlns:q="urn:q"/></c></a>""",
}


def lxmlCanonical(data, path, prefixes=()):
  root = etree.fromstring(data)
  node = root if path is None else root.xpath(path)[0]
  return etree.tostring(node, method="c14n", exclusive=True, with_comments=False, inclusive_ns_prefixes=list(prefixes) or None)


def find(root, localName):
  return root if root.localName == localName else next(e for e in root.descendants() if e.localName == localName)


@pytest.mark.parametrize("name", documents)
def testWholeDocumentsMatchLibxml2(name):
  assert canonical(parse(documents[name])) == lxmlCanonical(documents[name], None)


@pytest.mark.parametrize("name, localName", [
  ("saml-like", "Assertion"), ("saml-like", "AttributeValue"), ("default namespaces", "b"),
  ("default namespaces", "c"), ("redeclared prefixes", "c"), ("unused declarations", "d"), ("unused declarations", "b"),
])
def testSubtreesMatchLibxml2(name, localName):
  data = documents[name]
  expected = lxmlCanonical(data, f"//*[local-name()='{localName}']")
  assert canonical(find(parse(data), localName)) == expected


def testInclusivePrefixesMatchLibxml2():
  data = documents["saml-like"]
  expected = lxmlCanonical(data, "//*[local-name()='Assertion']", ["xs"])
  assert canonical(find(parse(data), "Assertion"), ("xs",)) == expected
  assert b'xmlns:xs="http://www.w3.org/2001/XMLSchema"' in expected


def testAnElementCanBeLeftOut():
  root = parse(b'<a xmlns="urn:a"><Signature>x</Signature><b/></a>')
  assert canonical(root, leaveOut=find(root, "Signature")) == b'<a xmlns="urn:a"><b></b></a>'


@pytest.mark.parametrize("data, message", [
  (b'<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>', "DOCTYPE"),
  (b'<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><a>&lol2;</a>', "DOCTYPE"),
  (b'<!DOCTYPE a SYSTEM "file:///etc/passwd"><a/>', "DOCTYPE"),
  (b'<a><p:b/></a>', "prefix 'p' is not declared"),
  (b'<a x="1" x="2"/>', "not well-formed"),
  (b'<a xmlns:p="urn:p" xmlns:q="urn:p" p:x="1" q:x="2"/>', "appears twice"),
  (b'<a/><b/>', "not well-formed"),
])
def testDangerousOrMalformedXMLIsRefused(data, message):
  with pytest.raises(XMLRefused, match=message):
    parse(data)


def testTextRunsThroughComments():
  root = parse(b"<NameID>admin@example.org<!---->.evil.example</NameID>")
  assert root.text == "admin@example.org.evil.example"
  assert canonical(root) == b"<NameID>admin@example.org.evil.example</NameID>"


def peakParseMemory(data):
  tracemalloc.start()
  try:
    parse(data)
    return tracemalloc.get_traced_memory()[1]
  finally:
    tracemalloc.stop()


def testNamespaceDeclarationsAreNotCopiedIntoEveryElement():
  children = b"<b/>" * 9000
  declared = b"<r " + b" ".join(b'xmlns:p%d="urn:p%d"' % (index, index) for index in range(64)) + b">" + children + b"</r>"
  plain = b"<r>" + children + b"</r>"
  assert peakParseMemory(declared) - peakParseMemory(plain) < 1_000_000


def testPrefixesResolveThroughTheAncestors():
  root = parse(b'<p:a xmlns:p="urn:one"><p:b><p:c xmlns:p="urn:two"><p:d q:x="1" xmlns:q="urn:q"/></p:c></p:b></p:a>')
  b = root.elements()[0]
  c = b.elements()[0]
  d = c.elements()[0]
  assert (b.namespaceURI, c.namespaceURI, d.namespaceURI) == ("urn:one", "urn:two", "urn:two")
  assert d.plainAttributes() == [("urn:q", "x", "q:x", "1")]


def nested(depth):
  return b"<a>" * depth + b"</a>" * depth


def testDepthUpToTheBudgetIsRead():
  root = parse(nested(xmlTree.maximumDepth))
  assert len(list(root.descendants())) == xmlTree.maximumDepth - 1
  assert canonical(root) == nested(xmlTree.maximumDepth)


@pytest.mark.parametrize("data, message", [
  (nested(xmlTree.maximumDepth + 1), "nested deeper than 64 elements"),
  (nested(5000), "nested deeper than 64 elements"),
  (b"<r>" + b"<b/>" * xmlTree.maximumElements + b"</r>", "more than 10000 elements"),
  (b"<r " + b" ".join(b'a%d="1"' % index for index in range(xmlTree.maximumAttributes + 1)) + b"/>",
   "more than 64 attributes"),
  (b"<r " + b" ".join(b'xmlns:p%d="urn:p"' % index for index in range(xmlTree.maximumDeclarations + 1)) + b"/>",
   "more than 64 namespace declarations"),
])
def testParseBudgetsAreRefusedByName(data, message):
  with pytest.raises(XMLRefused, match=message):
    parse(data)


def testTheXMLPrefixAlwaysMeansTheXMLNamespace():
  root = parse(b'<xml:a xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:lang="en"/>')
  assert root.isA("http://www.w3.org/XML/1998/namespace", "a")
  assert root.attribute("lang", "http://www.w3.org/XML/1998/namespace") == "en"
  assert parse(b"<xml:a/>").namespaceURI == "http://www.w3.org/XML/1998/namespace"


@pytest.mark.parametrize("data, message", [
  (b'<a xmlns:xml="urn:evil"/>', "the xml prefix cannot be bound to another namespace"),
  (b'<p:a xmlns:p="http://www.w3.org/XML/1998/namespace"/>', "reserved namespace .* cannot be bound to another prefix"),
  (b'<a xmlns="http://www.w3.org/XML/1998/namespace"/>', "reserved namespace .* cannot be bound to another prefix"),
  (b'<a xmlns:p="http://www.w3.org/2000/xmlns/"/>', "reserved namespace .* cannot be bound to another prefix"),
  (b'<a xmlns:xmlns="urn:x"/>', "the xmlns prefix cannot be declared"),
  (b"<xmlns:a/>", "an element cannot use the xmlns prefix"),
  (b'<p:a:b xmlns:p="urn:p"/>', "'p:a:b' is not a well-formed qualified name"),
  (b'<a p:x:y="1" xmlns:p="urn:p"/>', "'p:x:y' is not a well-formed qualified name"),
  (b"<:a/>", "':a' is not a well-formed qualified name"),
  (b'<a: xmlns:a="urn:a"/>', "'a:' is not a well-formed qualified name"),
  (b'<a xmlns:="urn:a"/>', "'xmlns:' is not a well-formed qualified name"),
])
def testReservedPrefixesAndMalformedNamesAreRefused(data, message):
  with pytest.raises(XMLRefused, match=message):
    parse(data)


def testSimpleTextRefusesChildElementsAndInstructions():
  assert parse(b"<NameID>ad<!---->min</NameID>").simpleText == "admin"
  with pytest.raises(XMLRefused, match="<NameID> must hold text only"):
    parse(b"<NameID>ad<b>m</b>in</NameID>").simpleText
  with pytest.raises(XMLRefused, match="<NameID> must hold text only"):
    parse(b"<NameID>ad<?x?>min</NameID>").simpleText
