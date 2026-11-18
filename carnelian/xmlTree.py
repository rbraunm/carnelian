# SPDX-License-Identifier: MIT
"""XML read safely, prefixes kept, and canonicalized by Exclusive XML Canonicalization 1.0.

The reader refuses any DOCTYPE, entity declaration or external entity -- SAML needs none
of them, and they are how XML parsers are attacked (entity expansion, external entities).
It keeps every element's prefix and own namespace declarations as written, because
canonicalization needs them; ElementTree throws them away. A prefix is resolved through the
element's ancestors. The reserved `xml` prefix always means the XML namespace: binding it
to anything else, binding another prefix to it, or using the `xmlns` prefix or namespace
otherwise than to declare is refused, as is a qualified name with more than one colon or
an empty part.

Parsing has budgets, each refused by name when exceeded: the document's size, its depth
(`maximumDepth`), its number of elements (`maximumElements`), and per element the number
of attributes (`maximumAttributes`) and of namespace declarations (`maximumDeclarations`).
The depth budget keeps every recursive walk of a tree far below Python's recursion limit.

A node's text is the concatenation of all its text, comments skipped: a comment splitting
a value ('ad<!---->min') must not shorten it, since canonicalization -- and so the
signature -- sees the whole. `simpleText` is the text of an element that may hold only
text, refusing child elements and processing instructions.

`canonical` implements http://www.w3.org/2001/10/xml-exc-c14n# (without comments), with
an optional InclusiveNamespaces prefix list and an element to leave out (the enveloped
signature). `DocumentStream` reads a document too large for a tree (a federation's
aggregate) one child of its document element at a time and canonicalizes it as it goes.
"""

from __future__ import annotations

import collections
import xml.parsers.expat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import NoReturn

xmlNamespace = "http://www.w3.org/XML/1998/namespace"
xmlnsNamespace = "http://www.w3.org/2000/xmlns/"

maximumDepth = 64
maximumElements = 10_000
maximumAttributes = 64
maximumDeclarations = 64


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
  children: list[Element | Text | Comment | Instruction] = field(default_factory=list)
  declarations: dict[str, str] = field(default_factory=dict)

  @property
  def prefix(self) -> str:
    return self.qualifiedName.partition(":")[0] if ":" in self.qualifiedName else ""

  @property
  def localName(self) -> str:
    return self.qualifiedName.rpartition(":")[2]

  @property
  def namespaceURI(self) -> str:
    return self.namespaceFor(self.prefix) or ""

  def namespaceFor(self, prefix: str) -> str | None:
    """The namespace a prefix ('' for the default) means here; None for an undeclared prefix."""
    if prefix == "xml":
      return xmlNamespace
    element: Element | None = self
    while element is not None:
      if prefix in element.declarations:
        return element.declarations[prefix]
      element = element.parent
    return "" if prefix == "" else None

  def isA(self, namespaceURI: str, localName: str) -> bool:
    return self.namespaceURI == namespaceURI and self.localName == localName

  def _resolved(self, qualifiedName: str) -> tuple[str, str]:
    if ":" not in qualifiedName:
      return "", qualifiedName
    prefix, local = qualifiedName.split(":", 1)
    uri = self.namespaceFor(prefix)
    if uri is None:
      raise XMLRefused(f"prefix '{prefix}' is not declared")
    return uri, local

  def plainAttributes(self) -> list[tuple[str, str, str, str]]:
    """(namespace URI, local name, qualified name, value) of every attribute but namespace declarations."""
    return [(*self._resolved(name), name, value) for name, value in self.attributes if not _isDeclaration(name)]

  def attribute(self, localName: str, namespaceURI: str = "") -> str | None:
    found = [value for uri, local, _, value in self.plainAttributes() if uri == namespaceURI and local == localName]
    return found[0] if found else None

  def required(self, localName: str, namespaceURI: str = "") -> str:
    """An attribute that must be present."""
    value = self.attribute(localName, namespaceURI)
    if value is None:
      raise XMLRefused(f"<{self.localName}> has no {localName} attribute")
    return value

  def elements(self) -> list[Element]:
    return [child for child in self.children if isinstance(child, Element)]

  def childrenNamed(self, namespaceURI: str, localName: str) -> list[Element]:
    return [child for child in self.elements() if child.isA(namespaceURI, localName)]

  def only(self, namespaceURI: str, localName: str) -> Element:
    """The one child of this name; none, or more than one, is refused."""
    found = self.childrenNamed(namespaceURI, localName)
    if len(found) != 1:
      raise XMLRefused(f"<{self.localName}> has {len(found)} <{localName}> children; it needs exactly one")
    return found[0]

  def optional(self, namespaceURI: str, localName: str) -> Element | None:
    """The child of this name, or None; more than one is refused."""
    found = self.childrenNamed(namespaceURI, localName)
    if len(found) > 1:
      raise XMLRefused(f"<{self.localName}> has {len(found)} <{localName}> children; it may have one")
    return found[0] if found else None

  def descendants(self) -> Iterator[Element]:
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

  @property
  def simpleText(self) -> str:
    if any(isinstance(child, (Element, Instruction)) for child in self.children):
      raise XMLRefused(f"<{self.localName}> must hold text only")
    return "".join(child.data for child in self.children if isinstance(child, Text))


def _isDeclaration(attributeName: str) -> bool:
  return attributeName == "xmlns" or attributeName.startswith("xmlns:")


def _checkedQualifiedName(qualifiedName: str) -> None:
  parts = qualifiedName.split(":")
  if len(parts) > 2 or not all(parts):
    raise XMLRefused(f"{qualifiedName!r} is not a well-formed qualified name")


def _declaration(attributeName: str, value: str) -> tuple[str, str]:
  prefix = "" if attributeName == "xmlns" else attributeName[6:]
  if prefix == "xmlns":
    raise XMLRefused("the xmlns prefix cannot be declared")
  if prefix == "xml":
    if value != xmlNamespace:
      raise XMLRefused("the xml prefix cannot be bound to another namespace")
    return prefix, value
  if value in (xmlNamespace, xmlnsNamespace):
    raise XMLRefused(f"the reserved namespace {value} cannot be bound to another prefix")
  if prefix and not value:
    raise XMLRefused(f"prefix '{prefix}' is undeclared to the empty name")
  return prefix, value


def _expatParser() -> xml.parsers.expat.XMLParserType:
  parser = xml.parsers.expat.ParserCreate()
  parser.ordered_attributes = True
  parser.buffer_text = True
  parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)

  def refuse(*_: object) -> NoReturn:
    raise XMLRefused("a DOCTYPE, entity or external reference is refused")

  parser.StartDoctypeDeclHandler = refuse
  parser.EntityDeclHandler = refuse
  parser.UnparsedEntityDeclHandler = refuse
  parser.ExternalEntityRefHandler = refuse
  return parser


def _element(name: str, attributes: list[str], parent: Element | None) -> Element:
  pairs = list(zip(attributes[0::2], attributes[1::2]))
  declarationNames = [attributeName for attributeName, _ in pairs if _isDeclaration(attributeName)]
  if len(declarationNames) > maximumDeclarations:
    raise XMLRefused(f"an element has more than {maximumDeclarations} namespace declarations")
  if len(pairs) - len(declarationNames) > maximumAttributes:
    raise XMLRefused(f"an element has more than {maximumAttributes} attributes")
  _checkedQualifiedName(name)
  if name.startswith("xmlns:"):
    raise XMLRefused("an element cannot use the xmlns prefix")
  declarations = {}
  for attributeName, value in pairs:
    _checkedQualifiedName(attributeName)
    if _isDeclaration(attributeName):
      prefix, uri = _declaration(attributeName, value)
      declarations[prefix] = uri
  element = Element(name, pairs, parent, declarations=declarations)
  if ":" in name and element.namespaceFor(element.prefix) is None:
    raise XMLRefused(f"prefix '{element.prefix}' is not declared")
  seen = set()
  for uri, local, _, _ in element.plainAttributes():
    if (uri, local) in seen:
      raise XMLRefused(f"attribute {local!r} appears twice")
    seen.add((uri, local))
  return element


def parse(data: bytes, maximumBytes: int = 1_000_000) -> Element:
  """The document element of a document with no DTD, well-formed namespaces and within the budgets."""
  if len(data) > maximumBytes:
    raise XMLRefused(f"the XML is larger than {maximumBytes} bytes")
  parser = _expatParser()
  stack: list[Element] = []
  roots: list[Element] = []
  elementCount = [0]

  def start(name: str, attributes: list[str]) -> None:
    if len(stack) >= maximumDepth:
      raise XMLRefused(f"the XML is nested deeper than {maximumDepth} elements")
    elementCount[0] += 1
    if elementCount[0] > maximumElements:
      raise XMLRefused(f"the XML has more than {maximumElements} elements")
    parent = stack[-1] if stack else None
    element = _element(name, attributes, parent)
    (parent.children if parent else roots).append(element)
    stack.append(element)

  def end(name: str) -> None:
    stack.pop()

  def characters(data: str) -> None:
    if stack:
      stack[-1].children.append(Text(data))
    elif data.strip():
      raise XMLRefused("text outside the document element")

  def comment(data: str) -> None:
    if stack:
      stack[-1].children.append(Comment(data))

  def instruction(target: str, data: str) -> None:
    if stack:
      stack[-1].children.append(Instruction(target, data))

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


class DocumentStream:
  """A document read in chunks that holds one child of its document element at a time.

  The document element keeps no children. Each of its child elements is built as a tree,
  under the budgets of `parse` with `maximumElements` counted per child, handed to `onChild`
  when it closes, and dropped. Once `canonicalize` names a sink, the document element's
  exclusive canonical form goes to it piece by piece (the children that closed before
  included), the same bytes `canonical` gives for the whole tree. A processing instruction
  outside the document element is refused, so that form is also the whole document's.
  """

  def __init__(self, onRoot: Callable[[Element], None], onChild: Callable[[Element], None], maximumBytes: int) -> None:
    self.onRoot, self.onChild, self.maximumBytes = onRoot, onChild, maximumBytes
    self.root: Element | None = None
    self._bytes = 0
    self._stack: list[Element] = []
    self._elementCount = 0
    self._pending: list[Element | Text | Instruction] = []
    self._ended = False
    self._sink: Callable[[bytes], None] | None = None
    self._rendered: collections.ChainMap[str, str] = collections.ChainMap({"": ""})
    self._inclusive: set[str] = set()
    self._leaveOut: Element | None = None
    self._parser = _expatParser()
    self._parser.StartElementHandler = self._start
    self._parser.EndElementHandler = self._end
    self._parser.CharacterDataHandler = self._characters
    self._parser.CommentHandler = self._comment
    self._parser.ProcessingInstructionHandler = self._instruction

  def feed(self, chunk: bytes) -> None:
    self._bytes += len(chunk)
    if self._bytes > self.maximumBytes:
      raise XMLRefused(f"the XML is larger than {self.maximumBytes} bytes")
    self._parse(chunk, False)

  def close(self) -> None:
    self._parse(b"", True)
    if self.root is None:
      raise XMLRefused("a document has one document element")

  def canonicalize(self, sink: Callable[[bytes], None], inclusivePrefixes: tuple[str, ...] = (),
                   leaveOut: Element | None = None) -> None:
    if self.root is None or self._sink is not None:
      raise ValueError("canonicalize is called once, after the document element has started")
    self._inclusive, self._leaveOut = set(inclusivePrefixes), leaveOut
    tag, self._rendered = _openTag(self.root, self._rendered, self._inclusive)
    sink(tag.encode("utf-8"))
    self._sink = sink
    for node in self._pending:
      self._emit(node)
    self._pending.clear()
    if self._ended:
      sink(f"</{self.root.qualifiedName}>".encode("utf-8"))

  def _parse(self, chunk: bytes, final: bool) -> None:
    try:
      self._parser.Parse(chunk, final)
    except xml.parsers.expat.ExpatError as error:
      raise XMLRefused(f"not well-formed XML: {error}") from None

  def _node(self, node: Element | Text | Instruction) -> None:
    if self._sink is None:
      self._pending.append(node)
    else:
      self._emit(node)

  def _emit(self, node: Element | Text | Instruction) -> None:
    assert self._sink is not None
    if isinstance(node, Text):
      self._sink(_escapedText(node.data).encode("utf-8"))
    elif isinstance(node, Instruction):
      self._sink(_instructionText(node).encode("utf-8"))
    elif node is not self._leaveOut:
      output: list[str] = []
      _render(node, self._rendered, self._inclusive, self._leaveOut, output)
      self._sink("".join(output).encode("utf-8"))

  def _start(self, name: str, attributes: list[str]) -> None:
    if len(self._stack) >= maximumDepth:
      raise XMLRefused(f"the XML is nested deeper than {maximumDepth} elements")
    if len(self._stack) == 1:
      self._elementCount = 0
    self._elementCount += 1
    if self._elementCount > maximumElements:
      raise XMLRefused(f"a child of the document element has more than {maximumElements} elements")
    parent = self._stack[-1] if self._stack else None
    element = _element(name, attributes, parent)
    if parent is None:
      self.root = element
      self.onRoot(element)
    elif len(self._stack) > 1:
      parent.children.append(element)
    self._stack.append(element)

  def _end(self, name: str) -> None:
    element = self._stack.pop()
    if not self._stack:
      self._ended = True
      if self._sink is not None:
        self._sink(f"</{element.qualifiedName}>".encode("utf-8"))
    elif len(self._stack) == 1:
      self.onChild(element)
      self._node(element)

  def _characters(self, data: str) -> None:
    if not self._stack:
      if data.strip():
        raise XMLRefused("text outside the document element")
    elif len(self._stack) == 1:
      self._node(Text(data))
    else:
      self._stack[-1].children.append(Text(data))

  def _comment(self, data: str) -> None:
    if len(self._stack) > 1:
      self._stack[-1].children.append(Comment(data))

  def _instruction(self, target: str, data: str) -> None:
    if not self._stack:
      raise XMLRefused("a processing instruction outside the document element is refused")
    if len(self._stack) == 1:
      self._node(Instruction(target, data))
    else:
      self._stack[-1].children.append(Instruction(target, data))


def _escapedText(data: str) -> str:
  return data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def _escapedAttribute(data: str) -> str:
  return (data.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
          .replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;"))


def canonical(element: Element, inclusivePrefixes: tuple[str, ...] = (), leaveOut: Element | None = None) -> bytes:
  """Exclusive XML Canonicalization 1.0 of an element's subtree, without comments."""
  output: list[str] = []
  _render(element, collections.ChainMap({"": ""}), set(inclusivePrefixes), leaveOut, output)
  return "".join(output).encode("utf-8")


def _instructionText(instruction: Instruction) -> str:
  return f"<?{instruction.target}{' ' + instruction.data if instruction.data else ''}?>"


def _openTag(element: Element, rendered: collections.ChainMap[str, str],
             inclusive: set[str]) -> tuple[str, collections.ChainMap[str, str]]:
  used = {element.prefix}
  for _, _, qualifiedName, _ in element.plainAttributes():
    if ":" in qualifiedName:
      used.add(qualifiedName.split(":", 1)[0])
  used |= {prefix for prefix in inclusive if prefix == "#default" or element.namespaceFor(prefix) is not None}
  used = {"" if prefix == "#default" else prefix for prefix in used} - {"xml"}
  declarations = []
  added: dict[str, str] = {}
  for prefix in sorted(used):
    uri = element.namespaceFor(prefix) or ""
    if rendered.get(prefix, "" if prefix == "" else None) == uri:
      continue
    declarations.append(f' xmlns="{_escapedAttribute(uri)}"' if prefix == "" else f' xmlns:{prefix}="{_escapedAttribute(uri)}"')
    added[prefix] = uri
  attributes = sorted(element.plainAttributes(), key=lambda attribute: (attribute[0], attribute[1]))
  tag = "".join([f"<{element.qualifiedName}", *declarations,
                 *(f' {qualifiedName}="{_escapedAttribute(value)}"' for _, _, qualifiedName, value in attributes), ">"])
  return tag, rendered.new_child(added) if added else rendered


def _render(element: Element, rendered: collections.ChainMap[str, str], inclusive: set[str],
            leaveOut: Element | None, output: list[str]) -> None:
  tag, nowRendered = _openTag(element, rendered, inclusive)
  output.append(tag)
  for child in element.children:
    if isinstance(child, Text):
      output.append(_escapedText(child.data))
    elif isinstance(child, Element):
      if child is not leaveOut:
        _render(child, nowRendered, inclusive, leaveOut, output)
    elif isinstance(child, Instruction):
      output.append(_instructionText(child))
  output.append(f"</{element.qualifiedName}>")
