# SPDX-License-Identifier: MIT
"""XML read safely, prefixes kept, and canonicalized by Exclusive XML Canonicalization 1.0.

The reader refuses any DOCTYPE, entity declaration or external entity -- SAML needs none
of them, and they are how XML parsers are attacked (entity expansion, external entities).
It keeps every element's prefix and namespace declarations as written, because
canonicalization needs them; ElementTree throws them away.

A node's text is the concatenation of all its text, comments skipped: a comment splitting
a value ('ad<!---->min') must not shorten it, since canonicalization -- and so the
signature -- sees the whole.

`canonical` implements http://www.w3.org/2001/10/xml-exc-c14n# (without comments), with
an optional InclusiveNamespaces prefix list and an element to leave out (the enveloped
signature).
"""

from __future__ import annotations

import xml.parsers.expat
from dataclasses import dataclass, field

xmlNamespace = "http://www.w3.org/XML/1998/namespace"


class XMLRefused(ValueError):
  """XML that is malformed, or that uses a feature refused here."""


@dataclass
class Text:
  data: str


@dataclass
class Comment:
  data: str


@dataclass
class Instruction:
  target: str
  data: str


@dataclass(eq=False)
class Element:
  qualifiedName: str
  attributes: list[tuple[str, str]]
  parent: Element | None
  children: list = field(default_factory=list)
  scope: dict[str, str] = field(default_factory=dict)

  @property
  def prefix(self) -> str:
    return self.qualifiedName.partition(":")[0] if ":" in self.qualifiedName else ""

  @property
  def localName(self) -> str:
    return self.qualifiedName.rpartition(":")[2]

  @property
  def namespaceURI(self) -> str:
    return self.scope.get(self.prefix, "")

  def isA(self, namespaceURI: str, localName: str) -> bool:
    return self.namespaceURI == namespaceURI and self.localName == localName

  def _resolved(self, qualifiedName: str) -> tuple[str, str]:
    if ":" not in qualifiedName:
      return "", qualifiedName
    prefix, local = qualifiedName.split(":", 1)
    if prefix == "xml":
      return xmlNamespace, local
    return self.scope[prefix], local

  def plainAttributes(self) -> list[tuple[str, str, str, str]]:
    """(namespace URI, local name, qualified name, value) of every attribute but namespace declarations."""
    return [(*self._resolved(name), name, value) for name, value in self.attributes
            if name != "xmlns" and not name.startswith("xmlns:")]

  def attribute(self, localName: str, namespaceURI: str = "") -> str | None:
    found = [value for uri, local, _, value in self.plainAttributes() if uri == namespaceURI and local == localName]
    return found[0] if found else None

  def elements(self) -> list[Element]:
    return [child for child in self.children if isinstance(child, Element)]

  def childrenNamed(self, namespaceURI: str, localName: str) -> list[Element]:
    return [child for child in self.elements() if child.isA(namespaceURI, localName)]

  def only(self, namespaceURI: str, localName: str, required: bool = True) -> Element | None:
    """The one child of this name; none, or more than one, is refused."""
    found = self.childrenNamed(namespaceURI, localName)
    if len(found) > 1 or (required and not found):
      raise XMLRefused(f"<{self.localName}> has {len(found)} <{localName}> children; it needs exactly one")
    return found[0] if found else None

  def descendants(self):
    for child in self.elements():
      yield child
      yield from child.descendants()

  @property
  def text(self) -> str:
    parts = []
    for child in self.children:
      if isinstance(child, Text):
        parts.append(child.data)
      elif isinstance(child, Element):
        parts.append(child.text)
    return "".join(parts)


def parse(data: bytes, maximumBytes: int = 1_000_000) -> Element:
  """The document element of a document with no DTD and well-formed namespaces."""
  if len(data) > maximumBytes:
    raise XMLRefused(f"the XML is larger than {maximumBytes} bytes")
  parser = xml.parsers.expat.ParserCreate()
  parser.ordered_attributes = True
  parser.buffer_text = True
  parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
  stack: list[Element] = []
  roots: list[Element] = []

  def refuse(*_):
    raise XMLRefused("a DOCTYPE, entity or external reference is refused")

  def start(name, attributes):
    pairs = list(zip(attributes[0::2], attributes[1::2]))
    parent = stack[-1] if stack else None
    scope = dict(parent.scope) if parent else {}
    for attributeName, value in pairs:
      if attributeName == "xmlns":
        scope[""] = value
      elif attributeName.startswith("xmlns:"):
        if not value:
          raise XMLRefused(f"prefix '{attributeName[6:]}' is undeclared to the empty name")
        scope[attributeName[6:]] = value
    element = Element(name, pairs, parent, scope=scope)
    for qualifiedName in [name] + [n for n, _ in pairs if n != "xmlns" and not n.startswith("xmlns:")]:
      if ":" in qualifiedName:
        prefix = qualifiedName.split(":", 1)[0]
        if prefix != "xml" and prefix not in scope:
          raise XMLRefused(f"prefix '{prefix}' is not declared")
    seen = set()
    for uri, local, _, _ in element.plainAttributes():
      if (uri, local) in seen:
        raise XMLRefused(f"attribute {local!r} appears twice")
      seen.add((uri, local))
    (parent.children if parent else roots).append(element)
    stack.append(element)

  def end(name):
    stack.pop()

  def characters(data):
    if stack:
      stack[-1].children.append(Text(data))
    elif data.strip():
      raise XMLRefused("text outside the document element")

  def comment(data):
    if stack:
      stack[-1].children.append(Comment(data))

  def instruction(target, data):
    if stack:
      stack[-1].children.append(Instruction(target, data))

  parser.StartDoctypeDeclHandler = refuse
  parser.EntityDeclHandler = refuse
  parser.UnparsedEntityDeclHandler = refuse
  parser.ExternalEntityRefHandler = refuse
  parser.StartElementHandler = start
  parser.EndElementHandler = end
  parser.CharacterDataHandler = characters
  parser.CommentHandler = comment
  parser.ProcessingInstructionHandler = instruction
  try:
    parser.Parse(data, True)
  except xml.parsers.expat.ExpatError as error:
    raise XMLRefused(f"not well-formed XML: {error}") from None
  if len(roots) != 1:
    raise XMLRefused("a document has one document element")
  return roots[0]


def _escapedText(data: str) -> str:
  return data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def _escapedAttribute(data: str) -> str:
  return (data.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
          .replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;"))


def canonical(element: Element, inclusivePrefixes: tuple[str, ...] = (), leaveOut: Element | None = None) -> bytes:
  """Exclusive XML Canonicalization 1.0 of an element's subtree, without comments."""
  output: list[str] = []
  _render(element, {"": ""}, set(inclusivePrefixes), leaveOut, output)
  return "".join(output).encode("utf-8")


def _render(element: Element, rendered: dict[str, str], inclusive: set[str], leaveOut, output: list[str]) -> None:
  used = {element.prefix}
  for _, _, qualifiedName, _ in element.plainAttributes():
    if ":" in qualifiedName:
      used.add(qualifiedName.split(":", 1)[0])
  used |= {prefix for prefix in inclusive if prefix in element.scope or (prefix == "#default")}
  used = {"" if prefix == "#default" else prefix for prefix in used} - {"xml"}
  declarations = []
  nowRendered = dict(rendered)
  for prefix in sorted(used):
    uri = element.scope.get(prefix, "")
    if rendered.get(prefix, "" if prefix == "" else None) == uri:
      continue
    declarations.append(f' xmlns="{_escapedAttribute(uri)}"' if prefix == "" else f' xmlns:{prefix}="{_escapedAttribute(uri)}"')
    nowRendered[prefix] = uri
  attributes = sorted(element.plainAttributes(), key=lambda attribute: (attribute[0], attribute[1]))
  output.append(f"<{element.qualifiedName}")
  output.extend(declarations)
  output.extend(f' {qualifiedName}="{_escapedAttribute(value)}"' for _, _, qualifiedName, value in attributes)
  output.append(">")
  for child in element.children:
    if isinstance(child, Text):
      output.append(_escapedText(child.data))
    elif isinstance(child, Element):
      if child is not leaveOut:
        _render(child, nowRendered, inclusive, leaveOut, output)
    elif isinstance(child, Instruction):
      output.append(f"<?{child.target}{' ' + child.data if child.data else ''}?>")
  output.append(f"</{element.qualifiedName}>")
