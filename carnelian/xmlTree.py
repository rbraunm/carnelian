# SPDX-License-Identifier: MIT
"""XML read safely, prefixes kept, and canonicalized by Exclusive XML Canonicalization 1.0.

The reader refuses any DOCTYPE, entity declaration or external entity -- SAML needs none
of them, and they are how XML parsers are attacked (entity expansion, external entities).
It keeps every element's prefix and own namespace declarations as written, because
canonicalization needs them; ElementTree throws them away. Each element's namespace and
its attributes' namespaces are resolved once, when the element is built, and kept. The
reserved `xml` prefix always means the XML namespace: binding it to anything else, binding
another prefix to it, or using the `xmlns` prefix or namespace otherwise than to declare is
refused, as is a qualified name with more than one colon or an empty part.

Parsing has budgets, each refused by name when exceeded: the document's size, its depth
(`maximumDepth`), its number of elements (`maximumElements`), attributes
(`maximumTotalAttributes`) and namespace declarations (`maximumTotalDeclarations`), per
element the number of attributes (`maximumAttributes`) and of namespace declarations
(`maximumDeclarations`), and the length of a namespace name (`maximumNamespaceLength`).
The depth budget keeps every recursive walk of a tree far below Python's recursion limit.
Canonicalization has its own: at most `maximumInclusivePrefixes` inclusive prefixes, and
a canonical form of at most `maximumCanonicalBytes` (a stream's is its caller's to set),
written to its sink in segments so that it is never held whole.

A node's text is the concatenation of all its text, comments skipped: a comment splitting
a value ('ad<!---->min') must not shorten it, since canonicalization -- and so the
signature -- sees the whole. `simpleText` is the text of an element that may hold only
text, refusing child elements and processing instructions.

`canonical` implements http://www.w3.org/2001/10/xml-exc-c14n# (without comments), with
an optional InclusiveNamespaces prefix list and an element to leave out (the enveloped
signature); `writeCanonical` writes the same bytes to a sink. `DocumentStream` reads a
document too large for a tree (a federation's aggregate) one child of its document element
at a time and canonicalizes it as it goes.
"""

from __future__ import annotations

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
maximumTotalAttributes = 20_000
maximumTotalDeclarations = 1_000
maximumNamespaceLength = 1_024
maximumInclusivePrefixes = 64
maximumCanonicalBytes = 8_000_000
maximumPendingNodes = 64
maximumPendingCharacters = 65_536
_segmentCharacters = 65_536


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


@dataclass(eq=False, slots=True)
class Element:
  qualifiedName: str
  namespaceURI: str
  parent: Element | None
  declarations: dict[str, str]
  scope: dict[str, str]
  resolvedAttributes: tuple[tuple[str, str, str, str], ...]
  children: list[Element | Text | Comment | Instruction] = field(default_factory=list)

  @property
  def prefix(self) -> str:
    return self.qualifiedName.partition(":")[0] if ":" in self.qualifiedName else ""

  @property
  def localName(self) -> str:
    return self.qualifiedName.rpartition(":")[2]

  def namespaceFor(self, prefix: str) -> str | None:
    """The namespace a prefix ('' for the default) means here; None for an undeclared prefix."""
    return _lookup(self.scope, prefix)

  def isA(self, namespaceURI: str, localName: str) -> bool:
    return self.namespaceURI == namespaceURI and self.localName == localName

  def plainAttributes(self) -> tuple[tuple[str, str, str, str], ...]:
    """(namespace URI, local name, qualified name, value) of every attribute but namespace declarations."""
    return self.resolvedAttributes

  def attribute(self, localName: str, namespaceURI: str = "") -> str | None:
    for uri, local, _, value in self.resolvedAttributes:
      if uri == namespaceURI and local == localName:
        return value
    return None

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
    pending = [iter(self.elements())]
    while pending:
      child = next(pending[-1], None)
      if child is None:
        pending.pop()
      else:
        yield child
        pending.append(iter(child.elements()))

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


def _lookup(scope: dict[str, str], prefix: str) -> str | None:
  if prefix == "xml":
    return xmlNamespace
  return scope.get(prefix, "" if prefix == "" else None)


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
  if len(value) > maximumNamespaceLength:
    raise XMLRefused(f"a namespace name is longer than {maximumNamespaceLength} characters")
  if prefix == "xml":
    if value != xmlNamespace:
      raise XMLRefused("the xml prefix cannot be bound to another namespace")
    return prefix, value
  if value in (xmlNamespace, xmlnsNamespace):
    raise XMLRefused(f"the reserved namespace {value} cannot be bound to another prefix")
  if prefix and not value:
    raise XMLRefused(f"prefix '{prefix}' is undeclared to the empty name")
  return prefix, value


def _resolved(scope: dict[str, str], attributeName: str) -> tuple[str, str]:
  if ":" not in attributeName:
    return "", attributeName
  prefix, local = attributeName.split(":", 1)
  uri = _lookup(scope, prefix)
  if uri is None:
    raise XMLRefused(f"prefix '{prefix}' is not declared")
  return uri, local


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


class _Budget:
  def __init__(self, whole: str) -> None:
    self.whole = whole
    self.elements = self.attributes = self.declarations = 0

  def add(self, attributes: int, declarations: int) -> None:
    self.elements += 1
    self.attributes += attributes
    self.declarations += declarations
    if self.elements > maximumElements:
      raise XMLRefused(f"{self.whole} has more than {maximumElements} elements")
    if self.attributes > maximumTotalAttributes:
      raise XMLRefused(f"{self.whole} has more than {maximumTotalAttributes} attributes")
    if self.declarations > maximumTotalDeclarations:
      raise XMLRefused(f"{self.whole} has more than {maximumTotalDeclarations} namespace declarations")


def _element(name: str, attributes: list[str], parent: Element | None, budget: _Budget) -> Element:
  pairs = list(zip(attributes[0::2], attributes[1::2]))
  declarationCount = sum(1 for attributeName, _ in pairs if _isDeclaration(attributeName))
  if declarationCount > maximumDeclarations:
    raise XMLRefused(f"an element has more than {maximumDeclarations} namespace declarations")
  if len(pairs) - declarationCount > maximumAttributes:
    raise XMLRefused(f"an element has more than {maximumAttributes} attributes")
  budget.add(len(pairs) - declarationCount, declarationCount)
  _checkedQualifiedName(name)
  if name.startswith("xmlns:"):
    raise XMLRefused("an element cannot use the xmlns prefix")
  declarations: dict[str, str] = {}
  plain = []
  for attributeName, value in pairs:
    _checkedQualifiedName(attributeName)
    if _isDeclaration(attributeName):
      prefix, uri = _declaration(attributeName, value)
      declarations[prefix] = uri
    else:
      plain.append((attributeName, value))
  if parent is None:
    scope = declarations
  else:
    scope = {**parent.scope, **declarations} if declarations else parent.scope
  prefix = name.partition(":")[0] if ":" in name else ""
  namespaceURI = _lookup(scope, prefix)
  if namespaceURI is None:
    raise XMLRefused(f"prefix '{prefix}' is not declared")
  resolvedAttributes = tuple((*_resolved(scope, attributeName), attributeName, value) for attributeName, value in plain)
  seen = set()
  for uri, local, _, _ in resolvedAttributes:
    if (uri, local) in seen:
      raise XMLRefused(f"attribute {local!r} appears twice")
    seen.add((uri, local))
  return Element(name, namespaceURI, parent, declarations, scope, resolvedAttributes)


def parse(data: bytes, maximumBytes: int = 1_000_000) -> Element:
  """The document element of a document with no DTD, well-formed namespaces and within the budgets."""
  if len(data) > maximumBytes:
    raise XMLRefused(f"the XML is larger than {maximumBytes} bytes")
  parser = _expatParser()
  stack: list[Element] = []
  roots: list[Element] = []
  budget = _Budget("the XML")

  def start(name: str, attributes: list[str]) -> None:
    if len(stack) >= maximumDepth:
      raise XMLRefused(f"the XML is nested deeper than {maximumDepth} elements")
    parent = stack[-1] if stack else None
    element = _element(name, attributes, parent, budget)
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
  under the budgets of `parse` with the element, attribute and declaration counts taken per
  child, handed to `onChild` when it closes, and dropped: once it is in the canonical form
  its tree is taken apart, so `onChild` keeps what it reads, never the element. Once `canonicalize` names a sink,
  the document element's exclusive canonical form goes to it in segments (the children that
  closed before included), the same bytes `canonical` gives for the whole tree, and at most
  `maximumCanonicalBytes` of them. Before then at most `maximumPendingNodes` children and
  `maximumPendingCharacters` of text are kept for it. A processing instruction outside the
  document element is refused, so that form is also the whole document's.
  """

  def __init__(self, onRoot: Callable[[Element], None], onChild: Callable[[Element], None], maximumBytes: int,
               maximumCanonicalBytes: int) -> None:
    self.onRoot, self.onChild = onRoot, onChild
    self.maximumBytes, self.maximumCanonicalBytes = maximumBytes, maximumCanonicalBytes
    self.root: Element | None = None
    self._bytes = 0
    self._stack: list[Element] = []
    self._budget = _Budget("the document element")
    self._pending: list[Element | Text | Instruction] = []
    self._pendingCharacters = 0
    self._ended = False
    self._writer: _CanonicalWriter | None = None
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
    if self.root is None or self._writer is not None:
      raise ValueError("canonicalize is called once, after the document element has started")
    writer = _CanonicalWriter(sink, inclusivePrefixes, leaveOut, self.maximumCanonicalBytes)
    writer.open(self.root)
    self._writer = writer
    for node in self._pending:
      writer.node(node)
      if isinstance(node, Element):
        _takenApart(node)
    self._pending.clear()
    if self._ended:
      writer.write(f"</{self.root.qualifiedName}>")
    writer.flush()

  def _parse(self, chunk: bytes, final: bool) -> None:
    try:
      self._parser.Parse(chunk, final)
    except xml.parsers.expat.ExpatError as error:
      raise XMLRefused(f"not well-formed XML: {error}") from None

  def _node(self, node: Element | Text | Instruction) -> None:
    if self._writer is not None:
      self._writer.node(node)
      return
    self._pending.append(node)
    if isinstance(node, Text):
      self._pendingCharacters += len(node.data)
    elif isinstance(node, Instruction):
      self._pendingCharacters += len(node.target) + len(node.data)
    if len(self._pending) > maximumPendingNodes:
      raise XMLRefused(f"more than {maximumPendingNodes} nodes come before the canonical form starts")
    if self._pendingCharacters > maximumPendingCharacters:
      raise XMLRefused(f"more than {maximumPendingCharacters} characters come before the canonical form starts")

  def _start(self, name: str, attributes: list[str]) -> None:
    if len(self._stack) >= maximumDepth:
      raise XMLRefused(f"the XML is nested deeper than {maximumDepth} elements")
    if len(self._stack) == 1:
      self._budget = _Budget("a child of the document element")
    parent = self._stack[-1] if self._stack else None
    element = _element(name, attributes, parent, self._budget)
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
      if self._writer is not None:
        self._writer.write(f"</{element.qualifiedName}>")
        self._writer.flush()
    elif len(self._stack) == 1:
      self.onChild(element)
      self._node(element)
      if self._writer is not None:
        _takenApart(element)

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


def _takenApart(element: Element) -> None:
  """Empties every children list of a subtree, so that the parent links leave no cycles to wait for the collector."""
  pending = [element]
  while pending:
    current = pending.pop()
    pending.extend(current.elements())
    current.children.clear()


def _escapedText(data: str) -> str:
  return data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def _escapedAttribute(data: str) -> str:
  return (data.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
          .replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;"))


def _instructionText(instruction: Instruction) -> str:
  return f"<?{instruction.target}{' ' + instruction.data if instruction.data else ''}?>"


class _CanonicalWriter:
  def __init__(self, sink: Callable[[bytes], None], inclusivePrefixes: tuple[str, ...], leaveOut: Element | None,
               maximumBytes: int) -> None:
    if len(inclusivePrefixes) > maximumInclusivePrefixes:
      raise XMLRefused(f"the inclusive prefix list has more than {maximumInclusivePrefixes} prefixes")
    self.sink, self.leaveOut, self.maximumBytes = sink, leaveOut, maximumBytes
    self.inclusive = set(inclusivePrefixes)
    self.rendered: dict[str, str] = {"": ""}
    self.parts: list[str] = []
    self.pendingCharacters = 0
    self.written = 0

  def write(self, text: str) -> None:
    self.parts.append(text)
    self.pendingCharacters += len(text)
    if self.written + self.pendingCharacters > self.maximumBytes:
      raise XMLRefused(f"the canonical form is longer than {self.maximumBytes} bytes")
    if self.pendingCharacters >= _segmentCharacters:
      self.flush()

  def flush(self) -> None:
    segment = "".join(self.parts).encode("utf-8")
    self.parts.clear()
    self.pendingCharacters = 0
    self.written += len(segment)
    if self.written > self.maximumBytes:
      raise XMLRefused(f"the canonical form is longer than {self.maximumBytes} bytes")
    if segment:
      self.sink(segment)

  def open(self, element: Element) -> list[tuple[str, str | None]]:
    """Writes the open tag; returns the rendered prefixes it replaced, for `restore` once the element closes."""
    used = {element.prefix}
    for _, _, qualifiedName, _ in element.resolvedAttributes:
      if ":" in qualifiedName:
        used.add(qualifiedName.split(":", 1)[0])
    used |= {prefix for prefix in self.inclusive if prefix == "#default" or element.namespaceFor(prefix) is not None}
    used = {"" if prefix == "#default" else prefix for prefix in used} - {"xml"}
    declarations = []
    replaced: list[tuple[str, str | None]] = []
    for prefix in sorted(used):
      uri = element.namespaceFor(prefix) or ""
      if self.rendered.get(prefix) == uri:
        continue
      declarations.append(f' xmlns="{_escapedAttribute(uri)}"' if prefix == "" else f' xmlns:{prefix}="{_escapedAttribute(uri)}"')
      replaced.append((prefix, self.rendered.get(prefix)))
    for prefix, _ in replaced:
      self.rendered[prefix] = element.namespaceFor(prefix) or ""
    attributes = sorted(element.resolvedAttributes, key=lambda attribute: (attribute[0], attribute[1]))
    self.write("".join([f"<{element.qualifiedName}", *declarations,
                        *(f' {qualifiedName}="{_escapedAttribute(value)}"' for _, _, qualifiedName, value in attributes),
                        ">"]))
    return replaced

  def restore(self, replaced: list[tuple[str, str | None]]) -> None:
    for prefix, previous in replaced:
      if previous is None:
        del self.rendered[prefix]
      else:
        self.rendered[prefix] = previous

  def node(self, node: Element | Text | Comment | Instruction) -> None:
    if isinstance(node, Text):
      self.write(_escapedText(node.data))
    elif isinstance(node, Instruction):
      self.write(_instructionText(node))
    elif isinstance(node, Element) and node is not self.leaveOut:
      replaced = self.open(node)
      for child in node.children:
        self.node(child)
      self.write(f"</{node.qualifiedName}>")
      self.restore(replaced)


def writeCanonical(element: Element, sink: Callable[[bytes], None], inclusivePrefixes: tuple[str, ...] = (),
                   leaveOut: Element | None = None) -> None:
  """Exclusive XML Canonicalization 1.0 of an element's subtree, without comments, written to `sink` in segments."""
  writer = _CanonicalWriter(sink, inclusivePrefixes, leaveOut, maximumCanonicalBytes)
  writer.node(element)
  writer.flush()


def canonical(element: Element, inclusivePrefixes: tuple[str, ...] = (), leaveOut: Element | None = None) -> bytes:
  """Exclusive XML Canonicalization 1.0 of an element's subtree, without comments."""
  segments: list[bytes] = []
  writeCanonical(element, segments.append, inclusivePrefixes, leaveOut)
  return b"".join(segments)
