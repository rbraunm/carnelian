# SPDX-License-Identifier: MIT
"""Reading XML safely, and Exclusive XML Canonicalization against libxml2 (through lxml)."""

import pytest
from lxml import etree

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
