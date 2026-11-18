# SPDX-License-Identifier: MIT
"""A SCIM 2.0 service provider (RFC 7643 and RFC 7644): users and groups an identity provider pushes.

The application keeps the resources in its own Store and passes each HTTP request below its
SCIM base URL to SCIMService.handle, which authorizes, parses, checks and answers it. Users
(with the enterprise extension) and groups; filters with the whole RFC 7644 grammar; paging;
attribute selection; POST, GET, PUT, PATCH and DELETE; the discovery endpoints. Not offered:
bulk, sorting, ETags, /Me and passwords (a request carrying one is refused by name).

Strict by default: an unknown attribute, a value of the wrong type (the string "False" for a
boolean, say), a second primary value, a duplicate key and an unknown query parameter are
refused with the reason. Read-only attributes in a POST or PUT are ignored, as RFC 7644
section 3.3 requires; in a PATCH they are refused. Group display names are unique, because
Microsoft Entra ID matches groups by them. Two Entra forms are taken as Entra sends them:
PATCH op names in any case, and "remove" of members listed in "value" rather than in a filter.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol
from urllib.parse import parse_qsl, unquote

coreUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
coreGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
enterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
entraGroupSchema = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
listResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
patchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
mediaType = "application/scim+json"


class SCIMRefused(ValueError):
  """A request refused, with its HTTP status, the RFC 7644 scimType when one fits, and why."""

  def __init__(self, status: int, detail: str, scimType: str | None = None):
    super().__init__(detail)
    self.status, self.detail, self.scimType = status, detail, scimType


def _invalid(detail: str, scimType: str = "invalidValue") -> SCIMRefused:
  return SCIMRefused(400, detail, scimType)


# ---- schemas ----------------------------------------------------------------

@dataclass(frozen=True)
class Attribute:
  name: str
  type: str = "string"
  multiValued: bool = False
  required: bool = False
  caseExact: bool = False
  mutability: str = "readWrite"
  returned: str = "default"
  uniqueness: str = "none"
  subAttributes: tuple[Attribute, ...] = ()
  canonicalValues: tuple[str, ...] = ()
  referenceTypes: tuple[str, ...] = ()
  stored: bool = True

  def sub(self, name: str) -> Attribute | None:
    return _named(self.subAttributes, name)

  def definition(self) -> dict:
    described = {"name": self.name, "type": self.type, "multiValued": self.multiValued, "required": self.required,
                 "caseExact": self.caseExact, "mutability": self.mutability, "returned": self.returned,
                 "uniqueness": self.uniqueness}
    if self.subAttributes:
      described["subAttributes"] = [sub.definition() for sub in self.subAttributes]
    if self.canonicalValues:
      described["canonicalValues"] = list(self.canonicalValues)
    if self.referenceTypes:
      described["referenceTypes"] = list(self.referenceTypes)
    return described


def _named(attributes, name: str):
  lowered = name.lower()
  for attribute in attributes:
    if attribute.name.lower() == lowered:
      return attribute
  return None


@dataclass(frozen=True)
class Schema:
  id: str
  name: str
  description: str
  attributes: tuple[Attribute, ...]


def _plural(name: str, valueType: str = "string", types: tuple[str, ...] = (), referenceTypes: tuple[str, ...] = ()):
  return Attribute(name, "complex", multiValued=True, subAttributes=(
    Attribute("value", valueType, referenceTypes=referenceTypes), Attribute("display"),
    Attribute("type", canonicalValues=types), Attribute("primary", "boolean")))


commonAttributes = (
  Attribute("id", caseExact=True, mutability="readOnly", returned="always", uniqueness="server"),
  Attribute("externalId", caseExact=True),
  Attribute("meta", "complex", mutability="readOnly", subAttributes=(
    Attribute("resourceType", caseExact=True, mutability="readOnly"),
    Attribute("created", "dateTime", mutability="readOnly"),
    Attribute("lastModified", "dateTime", mutability="readOnly"),
    Attribute("location", "reference", caseExact=True, mutability="readOnly", referenceTypes=("uri",)),
    Attribute("version", caseExact=True, mutability="readOnly"))),
)
schemasAttribute = Attribute("schemas", "reference", multiValued=True, referenceTypes=("uri",))

userSchema = Schema(coreUserSchema, "User", "User Account", (
  Attribute("userName", required=True, uniqueness="server"),
  Attribute("name", "complex", subAttributes=tuple(Attribute(part) for part in (
    "formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"))),
  Attribute("displayName"),
  Attribute("nickName"),
  Attribute("profileUrl", "reference", referenceTypes=("external",)),
  Attribute("title"),
  Attribute("userType"),
  Attribute("preferredLanguage"),
  Attribute("locale"),
  Attribute("timezone"),
  Attribute("active", "boolean"),
  _plural("emails", types=("work", "home", "other")),
  _plural("phoneNumbers", types=("work", "home", "mobile", "fax", "pager", "other")),
  _plural("ims", types=("aim", "gtalk", "icq", "xmpp", "msn", "skype", "qq", "yahoo")),
  _plural("photos", "reference", ("photo", "thumbnail"), ("external",)),
  Attribute("addresses", "complex", multiValued=True, subAttributes=tuple(Attribute(part) for part in (
    "formatted", "streetAddress", "locality", "region", "postalCode", "country")) + (
    Attribute("type", canonicalValues=("work", "home", "other")), Attribute("primary", "boolean"))),
  Attribute("groups", "complex", multiValued=True, mutability="readOnly", subAttributes=(
    Attribute("value", mutability="readOnly"),
    Attribute("$ref", "reference", mutability="readOnly", referenceTypes=("User", "Group")),
    Attribute("display", mutability="readOnly"),
    Attribute("type", mutability="readOnly", canonicalValues=("direct", "indirect")))),
  _plural("entitlements"),
  _plural("roles"),
  _plural("x509Certificates", "binary"),
))

enterpriseSchema = Schema(enterpriseUserSchema, "EnterpriseUser", "Enterprise User", tuple(
  Attribute(part) for part in ("employeeNumber", "costCenter", "organization", "division", "department")) + (
  Attribute("manager", "complex", subAttributes=(
    Attribute("value", required=True),
    Attribute("$ref", "reference", referenceTypes=("User",), stored=False),
    Attribute("displayName", mutability="readOnly"))),
))

groupSchema = Schema(coreGroupSchema, "Group", "Group", (
  Attribute("displayName", required=True, uniqueness="server"),
  Attribute("members", "complex", multiValued=True, subAttributes=(
    Attribute("value", required=True, caseExact=True, mutability="immutable"),
    Attribute("$ref", "reference", mutability="immutable", referenceTypes=("User", "Group"), stored=False),
    Attribute("display"),
    Attribute("type", mutability="immutable", canonicalValues=("User", "Group")))),
))


@dataclass(frozen=True)
class ResourceType:
  name: str
  endpoint: str
  description: str
  schema: Schema
  extensions: tuple[Schema, ...]
  ignoredSchemas: tuple[str, ...]
  uniqueAttribute: str

  def schemaNamed(self, uri: str) -> Schema | None:
    lowered = uri.lower()
    for schema in (self.schema,) + self.extensions:
      if schema.id.lower() == lowered:
        return schema
    return None


userType = ResourceType("User", "/Users", "User Account", userSchema, (enterpriseSchema,), (), "userName")
# Entra names its own group schema in every group it creates; it carries no attributes.
groupType = ResourceType("Group", "/Groups", "Group", groupSchema, (), (entraGroupSchema,), "displayName")
resourceTypes = {"User": userType, "Group": groupType}


@dataclass(frozen=True)
class _Target:
  schema: Schema
  attribute: Attribute
  sub: Attribute | None


def _resolve(resourceType: ResourceType, text: str, scimType: str) -> _Target:
  """An attribute path, short or with its schema URI in front (RFC 7644 section 3.10)."""
  lowered = text.lower()
  schema, rest = resourceType.schema, text
  for candidate in (resourceType.schema,) + resourceType.extensions:
    prefix = candidate.id.lower() + ":"
    if lowered.startswith(prefix):
      schema, rest = candidate, text[len(prefix):]
      break
  else:
    if lowered.startswith("urn:"):
      raise _invalid(f"{text}: no such schema on {resourceType.name}", scimType)
  name, dot, subName = rest.partition(".")
  pool = schema.attributes + (commonAttributes if schema is resourceType.schema else ())
  attribute = _named(pool, name)
  if attribute is None:
    raise _invalid(f"{text}: no such attribute on {resourceType.name}", scimType)
  sub = None
  if dot:
    sub = attribute.sub(subName)
    if sub is None:
      raise _invalid(f"{text}: {attribute.name} has no sub-attribute {subName}", scimType)
  return _Target(schema, attribute, sub)


def _container(resource: dict, schema: Schema, resourceType: ResourceType, create: bool = False) -> dict | None:
  if schema is resourceType.schema:
    return resource
  if create:
    return resource.setdefault(schema.id, {})
  return resource.get(schema.id)


# ---- values -----------------------------------------------------------------

class _Absent:
  pass


_absent = _Absent()


def _parseTime(text: str, where: str, scimType: str = "invalidValue") -> datetime:
  try:
    moment = datetime.fromisoformat(text)
  except ValueError:
    raise _invalid(f"{where} is not a dateTime", scimType) from None
  if moment.tzinfo is None:
    raise _invalid(f"{where} is a dateTime without a time zone", scimType)
  return moment


def _readSingle(attribute: Attribute, value, where: str, patching: bool):
  if value is None:
    return _absent
  if attribute.type == "complex":
    if not isinstance(value, dict):
      raise _invalid(f"{where} must be an object", "invalidSyntax")
    result, seen = {}, set()
    for key, item in value.items():
      sub = attribute.sub(key)
      if sub is None:
        raise _invalid(f"{where}.{key}: no such attribute", "invalidSyntax")
      if sub.name in seen:
        raise _invalid(f"{where}.{sub.name} appears twice", "invalidSyntax")
      seen.add(sub.name)
      if sub.mutability == "readOnly":
        if patching and item is not None:
          raise _invalid(f"{where}.{sub.name} is read-only", "mutability")
        continue
      read = _readSingle(sub, item, f"{where}.{sub.name}", patching)
      if read is not _absent and sub.stored:
        result[sub.name] = read
    if not result:
      return _absent
    for sub in attribute.subAttributes:
      if sub.required and sub.name not in result:
        raise _invalid(f"{where}.{sub.name} is required")
    return result
  kind = attribute.type
  if kind in ("string", "reference"):
    if not isinstance(value, str):
      raise _invalid(f"{where} must be a string")
  elif kind == "boolean":
    if type(value) is not bool:
      raise _invalid(f"{where} must be true or false")
  elif kind == "integer":
    if type(value) is not int:
      raise _invalid(f"{where} must be an integer")
  elif kind == "decimal":
    if type(value) not in (int, float):
      raise _invalid(f"{where} must be a number")
  elif kind == "dateTime":
    if not isinstance(value, str):
      raise _invalid(f"{where} must be a dateTime string")
    _parseTime(value, where)
  elif kind == "binary":
    if not isinstance(value, str):
      raise _invalid(f"{where} must be base64 text")
    try:
      base64.b64decode(value, validate=True)
    except binascii.Error:
      raise _invalid(f"{where} must be base64 text") from None
  return value


def _readValue(attribute: Attribute, value, where: str, patching: bool):
  if value is None:
    return _absent
  if not attribute.multiValued:
    return _readSingle(attribute, value, where, patching)
  if not isinstance(value, list):
    raise _invalid(f"{where} must be a list", "invalidSyntax")
  items = [_readSingle(attribute, item, f"{where}[{index}]", patching) for index, item in enumerate(value)]
  items = [item for item in items if item is not _absent]
  _checkPrimary(attribute, items, where)
  return items or _absent


def _checkPrimary(attribute: Attribute, items: list, where: str) -> None:
  if attribute.type == "complex" and sum(1 for item in items if item.get("primary") is True) > 1:
    raise _invalid(f"{where} has more than one primary value")


def _readResource(resourceType: ResourceType, document) -> dict:
  if not isinstance(document, dict):
    raise _invalid("the resource must be a JSON object", "invalidSyntax")
  declared = _declaredSchemas(resourceType, document)
  resource, seen = {}, set()
  for key, value in document.items():
    if key.lower() == "schemas":
      continue
    if key.lower() == "password":
      raise _invalid("password is refused: Carnelian takes no passwords over SCIM")
    extension = resourceType.schemaNamed(key)
    if extension is not None and extension is not resourceType.schema:
      if extension.id not in declared:
        raise _invalid(f"{extension.id} is used but not named in schemas", "invalidSyntax")
      if value is None:
        continue
      if not isinstance(value, dict):
        raise _invalid(f"{key} must be an object", "invalidSyntax")
      for innerKey, innerValue in value.items():
        attribute = _named(extension.attributes, innerKey)
        if attribute is None:
          raise _invalid(f"{key}:{innerKey}: no such attribute", "invalidSyntax")
        _putRead(resource, resourceType, _Target(extension, attribute, None), innerValue, seen)
      continue
    target = _resolve(resourceType, key, "invalidSyntax")
    if target.sub is not None:
      raise _invalid(f"{key}: a resource names whole attributes", "invalidSyntax")
    if target.schema is not resourceType.schema and target.schema.id not in declared:
      raise _invalid(f"{target.schema.id} is used but not named in schemas", "invalidSyntax")
    _putRead(resource, resourceType, target, value, seen)
  return resource


def _declaredSchemas(resourceType: ResourceType, document: dict) -> set[str]:
  schemas = [value for key, value in document.items() if key.lower() == "schemas"]
  if len(schemas) != 1 or not isinstance(schemas[0], list) or not all(isinstance(uri, str) for uri in schemas[0]):
    raise _invalid("schemas must be a list of schema URIs", "invalidSyntax")
  declared = set()
  for uri in schemas[0]:
    schema = resourceType.schemaNamed(uri)
    if schema is not None:
      declared.add(schema.id)
    elif uri.lower() not in (ignored.lower() for ignored in resourceType.ignoredSchemas):
      raise _invalid(f"schema {uri} is not offered for {resourceType.name}", "invalidSyntax")
  if resourceType.schema.id not in declared:
    raise _invalid(f"schemas must name {resourceType.schema.id}", "invalidSyntax")
  return declared


def _putRead(resource: dict, resourceType: ResourceType, target: _Target, value, seen: set) -> None:
  key = (target.schema.id, target.attribute.name)
  if key in seen:
    raise _invalid(f"{target.attribute.name} appears twice", "invalidSyntax")
  seen.add(key)
  if target.attribute.mutability == "readOnly":
    return
  read = _readValue(target.attribute, value, target.attribute.name, patching=False)
  if read is not _absent:
    _container(resource, target.schema, resourceType, create=True)[target.attribute.name] = read


def _checkRequired(resourceType: ResourceType, resource: dict) -> None:
  for schema in (resourceType.schema,) + resourceType.extensions:
    container = _container(resource, schema, resourceType)
    if container is None:
      continue
    for attribute in schema.attributes:
      if attribute.required and attribute.name not in container:
        raise _invalid(f"{attribute.name} is required")
      if attribute.multiValued and attribute.name in container:
        _checkPrimary(attribute, container[attribute.name], attribute.name)


# ---- filters (RFC 7644 section 3.4.2.2) -------------------------------------

@dataclass(frozen=True)
class Compare:
  path: str
  operator: str
  value: object


@dataclass(frozen=True)
class Present:
  path: str


@dataclass(frozen=True)
class And:
  left: object
  right: object


@dataclass(frozen=True)
class Or:
  left: object
  right: object


@dataclass(frozen=True)
class Not:
  inner: object


@dataclass(frozen=True)
class ValuePath:
  """attribute[filter]: some value of a multi-valued complex attribute matches the inner filter."""

  path: str
  inner: object


comparisonOperators = ("eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le")
_tokenPattern = re.compile(r'\s*(?:(?P<mark>[()\[\]])|(?P<string>"(?:[^"\\]|\\.)*")|(?P<word>[^\s()\[\]"]+))', re.DOTALL)
_numberPattern = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
maximumFilterLength = 4096
maximumFilterDepth = 32


class _FilterParser:
  def __init__(self, text: str):
    if len(text) > maximumFilterLength:
      raise _invalid(f"a filter longer than {maximumFilterLength} characters", "invalidFilter")
    self.tokens, position = [], 0
    while position < len(text):
      if not text[position:].strip():
        break
      found = _tokenPattern.match(text, position)
      if found is None:
        raise _invalid(f"the filter cannot be read at character {position}", "invalidFilter")
      kind = found.lastgroup
      self.tokens.append((kind, found.group(kind), found.start(kind), found.end(kind)))
      position = found.end()
    self.index, self.depth, self.inValuePath = 0, 0, False

  def fail(self, why: str):
    raise _invalid(f"the filter {why}", "invalidFilter")

  def peek(self):
    return self.tokens[self.index] if self.index < len(self.tokens) else (None, None, None, None)

  def take(self):
    token = self.peek()
    if token[0] is None:
      self.fail("ends too early")
    self.index += 1
    return token

  def isWord(self, word: str) -> bool:
    kind, text, _, _ = self.peek()
    return kind == "word" and text.lower() == word

  def expectMark(self, mark: str) -> None:
    kind, text, _, _ = self.take()
    if kind != "mark" or text != mark:
      self.fail(f"needs {mark!r} where it has {text!r}")

  def parse(self):
    node = self.orExpression()
    if self.index != len(self.tokens):
      self.fail(f"has {self.peek()[1]!r} left over")
    return node

  def orExpression(self):
    self.depth += 1
    if self.depth > maximumFilterDepth:
      self.fail(f"nests deeper than {maximumFilterDepth}")
    node = self.andExpression()
    while self.isWord("or"):
      self.take()
      node = Or(node, self.andExpression())
    self.depth -= 1
    return node

  def andExpression(self):
    node = self.notExpression()
    while self.isWord("and"):
      self.take()
      node = And(node, self.notExpression())
    return node

  def notExpression(self):
    if self.isWord("not"):
      self.take()
      self.expectMark("(")
      inner = self.orExpression()
      self.expectMark(")")
      return Not(inner)
    return self.primary()

  def primary(self):
    kind, text, _, _ = self.peek()
    if kind == "mark" and text == "(":
      self.take()
      inner = self.orExpression()
      self.expectMark(")")
      return inner
    kind, path, _, _ = self.take()
    if kind != "word" or path.lower() in ("and", "or", "not") or path.startswith("."):
      self.fail(f"needs an attribute where it has {path!r}")
    if self.peek()[:2] == ("mark", "["):
      if self.inValuePath:
        self.fail("puts one [] filter inside another")
      self.take()
      self.inValuePath = True
      inner = self.orExpression()
      self.inValuePath = False
      kind, text, _, closed = self.take()
      if (kind, text) != ("mark", "]"):
        self.fail(f"needs ']' where it has {text!r}")
      nextKind, nextText, nextStart, _ = self.peek()
      if nextKind == "word" and nextText.startswith(".") and nextStart == closed:
        self.take()
        inner = And(inner, self.comparison(nextText[1:]))
      return ValuePath(path, inner)
    return self.comparison(path)

  def comparison(self, path: str):
    kind, operator, _, _ = self.take()
    operator = (operator or "").lower()
    if kind != "word":
      self.fail(f"needs an operator after {path}")
    if operator == "pr":
      return Present(path)
    if operator not in comparisonOperators:
      self.fail(f"has an unknown operator {operator!r}")
    kind, text, _, _ = self.take()
    if kind == "string":
      try:
        value = json.loads(text)
      except json.JSONDecodeError:
        self.fail(f"has a string it cannot read: {text}")
    elif kind == "word" and text in ("true", "false", "null"):
      value = {"true": True, "false": False, "null": None}[text]
    elif kind == "word" and _numberPattern.fullmatch(text):
      value = json.loads(text)
    else:
      self.fail(f"needs a value after {path} {operator} where it has {text!r}")
    return Compare(path, operator, value)


def parseFilter(text: str):
  return _FilterParser(text).parse()


class _ResourceScope:
  def __init__(self, resourceType: ResourceType, resource: dict):
    self.resourceType, self.resource = resourceType, resource

  def target(self, path: str) -> _Target:
    target = _resolve(self.resourceType, path, "invalidFilter")
    if self.resourceType is userType and target.attribute.name == "groups":
      raise _invalid("filter memberships through the members of /Groups, not a user's groups", "invalidFilter")
    return target

  def values(self, path: str):
    if path.lower() == "schemas":
      return schemasAttribute, _schemasOf(self.resourceType, self.resource)
    target = self.target(path)
    container = _container(self.resource, target.schema, self.resourceType) or {}
    return _collect(target.attribute, target.sub, container.get(target.attribute.name))

  def elements(self, path: str):
    target = self.target(path)
    if target.attribute.type != "complex" or target.sub is not None:
      raise _invalid(f"{path}[...] needs a complex attribute", "invalidFilter")
    container = _container(self.resource, target.schema, self.resourceType) or {}
    raw = container.get(target.attribute.name)
    return target.attribute, (raw if isinstance(raw, list) else [] if raw is None else [raw])


class _ElementScope:
  def __init__(self, attribute: Attribute, element: dict):
    self.attribute, self.element = attribute, element

  def values(self, path: str):
    sub = self.attribute.sub(path)
    if sub is None:
      raise _invalid(f"{self.attribute.name} has no sub-attribute {path}", "invalidFilter")
    return sub, ([self.element[sub.name]] if sub.name in self.element else [])

  def elements(self, path: str):
    raise _invalid("a [] filter cannot hold another", "invalidFilter")


def _collect(attribute: Attribute, sub: Attribute | None, raw):
  items = raw if isinstance(raw, list) else [] if raw is None else [raw]
  if attribute.type != "complex":
    return attribute, items
  if sub is None:
    sub = attribute.sub("value") if attribute.multiValued else None
    if sub is None:
      raise _invalid(f"{attribute.name} is complex: name one of its sub-attributes", "invalidFilter")
  return sub, [item[sub.name] for item in items if sub.name in item]


def _evaluate(node, scope) -> bool:
  if isinstance(node, And):
    return _evaluate(node.left, scope) and _evaluate(node.right, scope)
  if isinstance(node, Or):
    return _evaluate(node.left, scope) or _evaluate(node.right, scope)
  if isinstance(node, Not):
    return not _evaluate(node.inner, scope)
  if isinstance(node, Present):
    _, values = scope.values(node.path)
    return any(value not in ("", None) for value in values)
  if isinstance(node, Compare):
    attribute, values = scope.values(node.path)
    return _compare(attribute, values, node.operator, node.value, node.path)
  if isinstance(node, ValuePath):
    attribute, elements = scope.elements(node.path)
    return any(_evaluate(node.inner, _ElementScope(attribute, element)) for element in elements)
  raise TypeError(f"not a filter: {node!r}")


def _compare(attribute: Attribute, values: list, operator: str, operand, path: str) -> bool:
  if operand is None:
    if operator == "eq":
      return not values
    if operator == "ne":
      return bool(values)
    raise _invalid(f"{path} {operator} null: only eq and ne take null", "invalidFilter")
  kind = attribute.type
  if kind == "complex":
    raise _invalid(f"{path} is complex: name one of its sub-attributes", "invalidFilter")
  if kind == "boolean":
    if type(operand) is not bool or operator not in ("eq", "ne"):
      raise _invalid(f"{path} is a boolean: compare it with eq or ne and true or false", "invalidFilter")
    key = lambda value: value
  elif kind in ("integer", "decimal"):
    if type(operand) not in (int, float) or operator in ("co", "sw", "ew"):
      raise _invalid(f"{path} is a number: compare it with a number", "invalidFilter")
    key = lambda value: value
  elif kind == "dateTime":
    if not isinstance(operand, str) or operator in ("co", "sw", "ew"):
      raise _invalid(f"{path} is a dateTime: compare it with a dateTime string", "invalidFilter")
    operand = _parseTime(operand, path, "invalidFilter")
    key = lambda value: _parseTime(value, path)
  else:
    if not isinstance(operand, str):
      raise _invalid(f"{path} is a string: compare it with a string", "invalidFilter")
    if kind == "binary" and operator not in ("eq", "ne"):
      raise _invalid(f"{path} is binary: compare it with eq or ne", "invalidFilter")
    if not attribute.caseExact:
      operand = operand.casefold()
      key = lambda value: value.casefold()
    else:
      key = lambda value: value
  keys = [key(value) for value in values]
  if operator == "eq":
    return operand in keys
  if operator == "ne":
    return operand not in keys
  tests = {"co": lambda value: operand in value, "sw": lambda value: value.startswith(operand),
           "ew": lambda value: value.endswith(operand), "gt": lambda value: value > operand,
           "ge": lambda value: value >= operand, "lt": lambda value: value < operand, "le": lambda value: value <= operand}
  return any(tests[operator](value) for value in keys)


def matches(resourceType: ResourceType, query, resource: dict) -> bool:
  """Whether a stored resource matches a parsed filter; for stores that filter in memory."""
  return _evaluate(query, _ResourceScope(resourceType, resource))


def _walk(node, scope) -> None:
  """Every attribute a filter names exists and every value fits its type, before any store sees it."""
  if isinstance(node, (And, Or)):
    _walk(node.left, scope)
    _walk(node.right, scope)
  elif isinstance(node, Not):
    _walk(node.inner, scope)
  elif isinstance(node, Present):
    scope.values(node.path)
  elif isinstance(node, Compare):
    attribute, _ = scope.values(node.path)
    _compare(attribute, [], node.operator, node.value, node.path)
  elif isinstance(node, ValuePath):
    attribute, _ = scope.elements(node.path)
    _walk(node.inner, _ElementScope(attribute, {}))
  else:
    raise TypeError(f"not a filter: {node!r}")


def _checkFilter(resourceType: ResourceType, query) -> None:
  _walk(query, _ResourceScope(resourceType, {}))


def _checkElementFilter(attribute: Attribute, query) -> None:
  _walk(query, _ElementScope(attribute, {}))


def _schemasOf(resourceType: ResourceType, resource: dict) -> list[str]:
  return [resourceType.schema.id] + [schema.id for schema in resourceType.extensions if schema.id in resource]


# ---- PATCH (RFC 7644 section 3.5.2) -----------------------------------------

_patchPathPattern = re.compile(r"([^\[\]]+)(?:\[(.*)\](?:\.([A-Za-z0-9_$-]+))?)?", re.DOTALL)


def _patchPath(resourceType: ResourceType, text: str):
  found = _patchPathPattern.fullmatch(text)
  if found is None:
    raise _invalid(f"the path {text!r} cannot be read", "invalidPath")
  head, inner, after = found.groups()
  target = _resolve(resourceType, head, "invalidPath")
  if inner is None:
    return target, None
  if target.sub is not None or target.attribute.type != "complex" or not target.attribute.multiValued:
    raise _invalid(f"the path {text!r} filters an attribute that is not multi-valued and complex", "invalidPath")
  query = parseFilter(inner)
  _checkElementFilter(target.attribute, query)
  sub = None
  if after is not None:
    sub = target.attribute.sub(after)
    if sub is None:
      raise _invalid(f"{target.attribute.name} has no sub-attribute {after}", "invalidPath")
  return _Target(target.schema, target.attribute, sub), query


def _field(document: dict, name: str, where: str):
  found = [value for key, value in document.items() if key.lower() == name.lower()]
  if len(found) > 1:
    raise _invalid(f"{where} names {name} twice", "invalidSyntax")
  return found[0] if found else _absent


def _applyPatch(resourceType: ResourceType, resource: dict, document) -> dict:
  if not isinstance(document, dict):
    raise _invalid("a PATCH body must be a JSON object", "invalidSyntax")
  schemas = _field(document, "schemas", "the PATCH body")
  if not isinstance(schemas, list) or [uri.lower() for uri in schemas if isinstance(uri, str)] != [patchOpSchema.lower()]:
    raise _invalid(f"a PATCH body names exactly the schema {patchOpSchema}", "invalidSyntax")
  operations = _field(document, "Operations", "the PATCH body")
  if not isinstance(operations, list) or not operations:
    raise _invalid("a PATCH body needs a list of Operations", "invalidSyntax")
  unknown = [key for key in document if key.lower() not in ("schemas", "operations")]
  if unknown:
    raise _invalid(f"a PATCH body has unknown members {unknown}", "invalidSyntax")
  work = copy.deepcopy(resource)
  for index, operation in enumerate(operations):
    where = f"Operations[{index}]"
    if not isinstance(operation, dict):
      raise _invalid(f"{where} must be an object", "invalidSyntax")
    unknown = [key for key in operation if key.lower() not in ("op", "path", "value")]
    if unknown:
      raise _invalid(f"{where} has unknown members {unknown}", "invalidSyntax")
    op = _field(operation, "op", where)
    if not isinstance(op, str) or op.lower() not in ("add", "replace", "remove"):
      raise _invalid(f"{where}.op must be add, replace or remove", "invalidSyntax")
    op = op.lower()
    path = _field(operation, "path", where)
    value = _field(operation, "value", where)
    if path is _absent or path is None:
      if op == "remove":
        raise _invalid(f"{where}: remove needs a path", "noTarget")
      if not isinstance(value, dict):
        raise _invalid(f"{where}: {op} without a path needs an object of attributes", "invalidSyntax")
      for key, item in value.items():
        extension = resourceType.schemaNamed(key)
        if extension is not None and extension is not resourceType.schema:
          if not isinstance(item, dict):
            raise _invalid(f"{where}.value.{key} must be an object", "invalidSyntax")
          for innerKey, innerItem in item.items():
            attribute = _named(extension.attributes, innerKey)
            if attribute is None:
              raise _invalid(f"{key}:{innerKey}: no such attribute", "invalidPath")
            _apply(work, resourceType, op, _Target(extension, attribute, None), None, innerItem, f"{where}.value.{key}:{attribute.name}")
          continue
        if key.lower() == "password":
          raise _invalid("password is refused: Carnelian takes no passwords over SCIM")
        _apply(work, resourceType, op, _resolve(resourceType, key, "invalidPath"), None, item, f"{where}.value.{key}")
      continue
    if not isinstance(path, str):
      raise _invalid(f"{where}.path must be a string", "invalidSyntax")
    if path.lower() == "password":
      raise _invalid("password is refused: Carnelian takes no passwords over SCIM")
    target, query = _patchPath(resourceType, path)
    _apply(work, resourceType, op, target, query, value, f"{where} {path}")
  for schema in resourceType.extensions:
    if work.get(schema.id) == {}:
      del work[schema.id]
  _checkRequired(resourceType, work)
  return work


def _apply(work: dict, resourceType: ResourceType, op: str, target: _Target, query, value, where: str) -> None:
  attribute, sub = target.attribute, target.sub
  if attribute.mutability == "readOnly" or (sub is not None and sub.mutability == "readOnly"):
    raise _invalid(f"{attribute.name} is read-only", "mutability")
  container = _container(work, target.schema, resourceType, create=op != "remove")
  if container is None:
    return
  name = attribute.name
  current = container.get(name)
  if op == "remove":
    _remove(container, attribute, sub, query, value, where)
  elif value is _absent:
    raise _invalid(f"{where}: {op} needs a value", "invalidSyntax")
  elif query is not None:
    found = [element for element in current or [] if _evaluate(query, _ElementScope(attribute, element))]
    if not found:
      raise _invalid(f"{where}: the filter matches no value of {name}", "noTarget")
    if sub is None:
      if op == "add":
        raise _invalid(f"{where}: add to a filtered value needs a sub-attribute", "invalidPath")
      replacement = _readSingle(attribute, value, where, True)
      rebuilt = []
      for element in current:
        if not any(element is match for match in found):
          rebuilt.append(element)
        elif replacement is not _absent:
          rebuilt.append(copy.deepcopy(replacement))
      container[name] = rebuilt
    else:
      read = _readSingle(sub, value, where, True)
      if read is not _absent and sub.name == "primary" and read is True:
        for element in current:
          element.pop("primary", None)
      for element in found:
        if read is _absent:
          element.pop(sub.name, None)
        elif sub.stored:
          element[sub.name] = read
  elif sub is not None:
    if attribute.multiValued:
      raise _invalid(f"{where}: name which {name} value with a filter, as {name}[...].{sub.name}", "invalidPath")
    read = _readSingle(sub, value, where, True)
    complexValue = container.setdefault(name, {})
    if read is _absent:
      complexValue.pop(sub.name, None)
    elif sub.stored:
      complexValue[sub.name] = read
  else:
    read = _readValue(attribute, value, where, True)
    if read is _absent:
      if op == "replace":
        container.pop(name, None)
    elif attribute.multiValued and op == "add":
      kept = list(current or [])
      if attribute.type == "complex" and any(item.get("primary") is True for item in read):
        for element in kept:
          element.pop("primary", None)
      for item in read:
        same = [index for index, element in enumerate(kept) if _sameValue(attribute, element, item)]
        if same:
          kept[same[0]] = item
        else:
          kept.append(item)
      container[name] = kept
    elif attribute.type == "complex" and not attribute.multiValued:
      container[name] = {**(current or {}), **read}
    else:
      container[name] = read
  if container.get(name) in ([], {}):
    del container[name]
  if name in container and attribute.multiValued:
    _checkPrimary(attribute, container[name], name)


def _sameValue(attribute: Attribute, left, right) -> bool:
  if attribute.type == "complex" and "value" in left and "value" in right:
    valueAttribute = attribute.sub("value")
    if valueAttribute.caseExact or not isinstance(left["value"], str):
      return left["value"] == right["value"]
    return left["value"].casefold() == right["value"].casefold()
  return left == right


def _remove(container: dict, attribute: Attribute, sub, query, value, where: str) -> None:
  name = attribute.name
  current = container.get(name)
  if value is not _absent and not (attribute.multiValued and query is None and sub is None):
    raise _invalid(f"{where}: remove takes a value only to list values of a multi-valued attribute", "invalidSyntax")
  if current is None:
    return
  if query is None and sub is None:
    if value is _absent:
      del container[name]
      return
    listed = _readValue(attribute, value, where, True)
    if listed is _absent:
      raise _invalid(f"{where}: remove lists no values", "invalidValue")
    if attribute.type == "complex" and any("value" not in item for item in listed):
      raise _invalid(f"{where}: each value to remove needs its value", "invalidValue")
    container[name] = [element for element in current
                       if not any(_sameValue(attribute, element, item) for item in listed)]
  elif query is None:
    if attribute.multiValued:
      raise _invalid(f"{where}: name which {name} value with a filter, as {name}[...].{sub.name}", "invalidPath")
    current.pop(sub.name, None)
  else:
    found = [element for element in current if _evaluate(query, _ElementScope(attribute, element))]
    if sub is None:
      container[name] = [element for element in current if not any(element is match for match in found)]
    else:
      for element in found:
        element.pop(sub.name, None)
      container[name] = [element for element in current if element]


# ---- the store the application keeps -----------------------------------------

class Store(Protocol):
  """The application's resources. Each is a dict as SCIMService builds it: id, meta (resourceType,
  created, lastModified), the core attributes, and each extension under its schema URI.
  search gets a filter already checked against the schema (None for every resource), and
  `matches` evaluates one in memory. create and replace raise SCIMRefused(409, ..., "uniqueness")
  when the store's own unique constraints refuse the resource."""

  def create(self, resourceType: str, resource: dict) -> None: ...

  def get(self, resourceType: str, resourceID: str) -> dict | None: ...

  def replace(self, resourceType: str, resource: dict) -> None: ...

  def delete(self, resourceType: str, resourceID: str) -> None: ...

  def search(self, resourceType: str, query) -> list[dict]: ...


# ---- the service ------------------------------------------------------------

@dataclass(frozen=True)
class SCIMResponse:
  status: int
  headers: dict[str, str]
  body: bytes


def _stamp(moment: datetime) -> str:
  if moment.tzinfo is None:
    raise ValueError("the clock must give times with a time zone")
  moment = moment.astimezone(timezone.utc)
  return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


def _refuseDuplicates(pairs):
  result = {}
  for key, value in pairs:
    if key in result:
      raise _invalid(f"the body names {key} twice", "invalidSyntax")
    result[key] = value
  return result


def _refuseConstant(name):
  raise _invalid(f"the body holds {name}, which is not JSON", "invalidSyntax")


class SCIMService:
  """Answers SCIM requests below baseURL (https) from the store, once isAuthorized accepts the bearer token."""

  def __init__(self, store: Store, baseURL: str, isAuthorized: Callable[[str], bool], pageSize: int = 100,
               maximumResults: int = 200, maximumBytes: int = 1_000_000,
               clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
    if not baseURL.startswith("https://") or baseURL.endswith("/"):
      raise ValueError("baseURL must be an https URL without a trailing slash")
    if not 0 < pageSize <= maximumResults:
      raise ValueError("pageSize must be positive and at most maximumResults")
    self.store, self.baseURL, self.isAuthorized = store, baseURL, isAuthorized
    self.pageSize, self.maximumResults, self.maximumBytes, self.clock = pageSize, maximumResults, maximumBytes, clock

  def handle(self, method: str, path: str, query: str, headers: Mapping[str, str], body: bytes) -> SCIMResponse:
    try:
      lowered = {key.lower(): value for key, value in headers.items()}
      self._authorize(lowered.get("authorization"))
      return self._route(method.upper(), path, query, lowered, body)
    except SCIMRefused as refused:
      document = {"schemas": [errorSchema], "status": str(refused.status), "detail": refused.detail}
      if refused.scimType is not None:
        document["scimType"] = refused.scimType
      extra = {"WWW-Authenticate": 'Bearer realm="SCIM"'} if refused.status == 401 else {}
      return self._answer(refused.status, document, extra)

  def _authorize(self, header: str | None) -> None:
    if header is None:
      raise SCIMRefused(401, "a bearer token is required")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip() or not self.isAuthorized(token.strip()):
      raise SCIMRefused(401, "the bearer token is not accepted")

  def _answer(self, status: int, document: dict | None, extra: dict | None = None) -> SCIMResponse:
    headers = dict(extra or {})
    if document is None:
      return SCIMResponse(status, headers, b"")
    headers["Content-Type"] = mediaType
    return SCIMResponse(status, headers, json.dumps(document, ensure_ascii=False).encode("utf-8"))

  def _route(self, method: str, path: str, query: str, headers: dict, body: bytes) -> SCIMResponse:
    if not path.startswith("/"):
      raise SCIMRefused(404, f"no endpoint {path}")
    segments = [unquote(segment) for segment in path[1:].split("/")]
    parameters = self._parameters(query)
    head = segments[0]
    if head in ("Bulk", "Me") or segments[-1] == ".search":
      raise SCIMRefused(501, f"/{'/'.join(segments)} is not offered")
    if head in ("ServiceProviderConfig", "ResourceTypes", "Schemas"):
      if method != "GET":
        raise SCIMRefused(405, f"{method} is not allowed on /{head}")
      self._allow(parameters, ())
      return self._discovery(segments)
    resourceType = next((candidate for candidate in resourceTypes.values() if candidate.endpoint == "/" + head), None)
    if resourceType is None or len(segments) > 2 or (len(segments) == 2 and not segments[1]):
      raise SCIMRefused(404, f"no endpoint {path}")
    if len(segments) == 1:
      if method == "GET":
        return self._list(resourceType, parameters)
      if method == "POST":
        return self._create(resourceType, parameters, headers, body)
      raise SCIMRefused(405, f"{method} is not allowed on {resourceType.endpoint}")
    resourceID = segments[1]
    if method == "GET":
      self._allow(parameters, ("attributes", "excludedAttributes"))
      resource = self._existing(resourceType, resourceID)
      return self._answer(200, self._render(resourceType, resource, parameters))
    if method == "PUT":
      return self._replace(resourceType, resourceID, parameters, headers, body)
    if method == "PATCH":
      return self._patch(resourceType, resourceID, parameters, headers, body)
    if method == "DELETE":
      self._allow(parameters, ())
      return self._delete(resourceType, resourceID)
    raise SCIMRefused(405, f"{method} is not allowed on {resourceType.endpoint}/{{id}}")

  # -- requests

  def _parameters(self, query: str) -> dict[str, str]:
    if not query:
      return {}
    try:
      pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
      raise _invalid("the query string cannot be read") from None
    parameters = {}
    for key, value in pairs:
      if key in parameters:
        raise _invalid(f"the query names {key} twice")
      parameters[key] = value
    return parameters

  def _allow(self, parameters: dict, allowed: tuple[str, ...]) -> None:
    unknown = sorted(set(parameters) - set(allowed))
    if unknown:
      why = " (sorting is not offered)" if {"sortBy", "sortOrder"} & set(unknown) else ""
      raise _invalid(f"unknown query parameters {unknown}{why}")

  def _document(self, headers: dict, body: bytes):
    contentType = headers.get("content-type", "").split(";")[0].strip().lower()
    if contentType not in (mediaType, "application/json"):
      raise SCIMRefused(415, f"the body must be {mediaType}")
    if len(body) > self.maximumBytes:
      raise SCIMRefused(413, f"the body is larger than {self.maximumBytes} bytes")
    try:
      return json.loads(body.decode("utf-8"), object_pairs_hook=_refuseDuplicates, parse_constant=_refuseConstant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
      raise _invalid(f"the body is not JSON: {error}", "invalidSyntax") from None

  def _existing(self, resourceType: ResourceType, resourceID: str) -> dict:
    resource = self.store.get(resourceType.name, resourceID)
    if resource is None:
      raise SCIMRefused(404, f"no {resourceType.name} {resourceID}")
    return copy.deepcopy(resource)

  # -- checks shared by create, replace and patch

  def _checkResource(self, resourceType: ResourceType, resource: dict, resourceID: str | None) -> None:
    _checkRequired(resourceType, resource)
    unique = resourceType.uniqueAttribute
    others = [found for found in self.store.search(resourceType.name, Compare(unique, "eq", resource[unique]))
              if found["id"] != resourceID]
    if others:
      raise SCIMRefused(409, f"another {resourceType.name} has the {unique} {resource[unique]!r}", "uniqueness")
    if resourceType is groupType:
      for member in resource.get("members", []):
        if member["value"] == resourceID:
          raise _invalid("a group cannot be its own member")
        found = [name for name in ("User", "Group") if self.store.get(name, member["value"]) is not None]
        if not found:
          raise _invalid(f"member {member['value']} is neither a user nor a group here")
        if member.get("type", found[0]) != found[0]:
          raise _invalid(f"member {member['value']} is a {found[0]}, not a {member['type']}")
        member["type"] = found[0]

  def _create(self, resourceType: ResourceType, parameters: dict, headers: dict, body: bytes) -> SCIMResponse:
    self._allow(parameters, ("attributes", "excludedAttributes"))
    resource = _readResource(resourceType, self._document(headers, body))
    resourceID = str(uuid.uuid4())
    self._checkResource(resourceType, resource, resourceID)
    stamp = _stamp(self.clock())
    resource = {"id": resourceID, "meta": {"resourceType": resourceType.name, "created": stamp, "lastModified": stamp},
                **resource}
    self.store.create(resourceType.name, resource)
    rendered = self._render(resourceType, resource, parameters)
    return self._answer(201, rendered, {"Location": self._location(resourceType, resourceID)})

  def _replace(self, resourceType: ResourceType, resourceID: str, parameters: dict, headers: dict, body: bytes):
    self._allow(parameters, ("attributes", "excludedAttributes"))
    existing = self._existing(resourceType, resourceID)
    resource = _readResource(resourceType, self._document(headers, body))
    self._checkResource(resourceType, resource, resourceID)
    resource = {"id": resourceID, "meta": {**existing["meta"], "lastModified": _stamp(self.clock())}, **resource}
    self.store.replace(resourceType.name, resource)
    return self._answer(200, self._render(resourceType, resource, parameters))

  def _patch(self, resourceType: ResourceType, resourceID: str, parameters: dict, headers: dict, body: bytes):
    self._allow(parameters, ("attributes", "excludedAttributes"))
    existing = self._existing(resourceType, resourceID)
    resource = _applyPatch(resourceType, existing, self._document(headers, body))
    self._checkResource(resourceType, resource, resourceID)
    resource["meta"] = {**resource["meta"], "lastModified": _stamp(self.clock())}
    self.store.replace(resourceType.name, resource)
    # A group's member list can be long, so its PATCH answers without a body, as Entra asks.
    if resourceType is groupType and not parameters:
      return self._answer(204, None)
    return self._answer(200, self._render(resourceType, resource, parameters))

  def _delete(self, resourceType: ResourceType, resourceID: str) -> SCIMResponse:
    self._existing(resourceType, resourceID)
    self.store.delete(resourceType.name, resourceID)
    stamp = _stamp(self.clock())
    for group in self.store.search("Group", ValuePath("members", Compare("value", "eq", resourceID))):
      group = copy.deepcopy(group)
      group["members"] = [member for member in group["members"] if member["value"] != resourceID]
      if not group["members"]:
        del group["members"]
      group["meta"] = {**group["meta"], "lastModified": stamp}
      self.store.replace("Group", group)
    return self._answer(204, None)

  def _list(self, resourceType: ResourceType, parameters: dict) -> SCIMResponse:
    self._allow(parameters, ("filter", "startIndex", "count", "attributes", "excludedAttributes"))
    self._projection(resourceType, parameters)
    query = None
    if "filter" in parameters:
      query = parseFilter(parameters["filter"])
      _checkFilter(resourceType, query)
    startIndex = self._whole(parameters, "startIndex", 1)
    count = self._whole(parameters, "count", self.pageSize)
    if startIndex < 1:
      raise _invalid("startIndex counts from 1")
    if count > self.maximumResults:
      raise _invalid(f"count may be at most {self.maximumResults}", "tooMany")
    found = sorted(self.store.search(resourceType.name, query), key=lambda item: (item["meta"]["created"], item["id"]))
    page = found[startIndex - 1:startIndex - 1 + count]
    return self._answer(200, {
      "schemas": [listResponseSchema], "totalResults": len(found), "itemsPerPage": len(page), "startIndex": startIndex,
      "Resources": [self._render(resourceType, resource, parameters) for resource in page]})

  @staticmethod
  def _whole(parameters: dict, name: str, default: int) -> int:
    if name not in parameters:
      return default
    text = parameters[name]
    if not re.fullmatch(r"[0-9]{1,9}", text):
      raise _invalid(f"{name} must be a whole number")
    return int(text)

  # -- answers

  def _location(self, resourceType: ResourceType, resourceID: str) -> str:
    return f"{self.baseURL}{resourceType.endpoint}/{resourceID}"

  def _projection(self, resourceType: ResourceType, parameters: dict):
    if "attributes" in parameters and "excludedAttributes" in parameters:
      raise _invalid("give attributes or excludedAttributes, not both")
    def keys(text):
      found = set()
      for path in text.split(","):
        target = _resolve(resourceType, path.strip(), "invalidValue")
        found.add((target.schema.id, target.attribute.name, target.sub.name if target.sub else None))
      return found
    if "attributes" in parameters:
      return keys(parameters["attributes"]), set()
    if "excludedAttributes" in parameters:
      return None, keys(parameters["excludedAttributes"])
    return None, set()

  def _render(self, resourceType: ResourceType, resource: dict, parameters: dict) -> dict:
    include, exclude = self._projection(resourceType, parameters)

    def wanted(schema: Schema, attribute: Attribute, sub: Attribute | None = None) -> bool:
      if attribute.returned == "always":
        return True
      key = (schema.id, attribute.name)
      if include is not None:
        if key + (None,) in include:
          return True
        if sub is None:
          return any(entry[:2] == key for entry in include)
        return key + (sub.name,) in include
      return key + (None,) not in exclude and (sub is None or key + (sub.name,) not in exclude)

    rendered = {"schemas": _schemasOf(resourceType, resource), "id": resource["id"]}
    core = resourceType.schema
    stored = dict(resource)
    stored["meta"] = {**resource["meta"], "location": self._location(resourceType, resource["id"])}
    if resourceType is userType and wanted(core, _named(core.attributes, "groups")):
      groups = self.store.search("Group", ValuePath("members", Compare("value", "eq", resource["id"])))
      if groups:
        stored["groups"] = [{"value": group["id"], "display": group["displayName"], "type": "direct"}
                            for group in sorted(groups, key=lambda item: item["id"])]
    for schema in (core,) + resourceType.extensions:
      container = stored if schema is core else stored.get(schema.id)
      if container is None:
        continue
      pool = (commonAttributes[1:] + schema.attributes) if schema is core else schema.attributes
      output = rendered if schema is core else {}
      for attribute in pool:
        if attribute.name not in container or not wanted(schema, attribute):
          continue
        output[attribute.name] = self._renderValue(schema, attribute, container[attribute.name], wanted)
      if schema is not core and output:
        rendered[schema.id] = output
    return rendered

  def _renderValue(self, schema: Schema, attribute: Attribute, value, wanted):
    if attribute.type != "complex":
      return value
    def one(item: dict) -> dict:
      item = dict(item)
      if attribute.sub("$ref") is not None and "value" in item:
        endpoint = "/Groups" if item.get("type") == "Group" or attribute.name == "groups" else "/Users"
        item["$ref"] = f"{self.baseURL}{endpoint}/{item['value']}"
      return {sub.name: item[sub.name] for sub in attribute.subAttributes
              if sub.name in item and wanted(schema, attribute, sub)}
    return [one(item) for item in value] if attribute.multiValued else one(value)

  def _discovery(self, segments: list[str]) -> SCIMResponse:
    head = segments[0]
    if head == "ServiceProviderConfig":
      if len(segments) != 1:
        raise SCIMRefused(404, "no such endpoint")
      return self._answer(200, {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": self.maximumResults}, "changePassword": {"supported": False},
        "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "OAuth Bearer Token",
                                   "description": "A bearer token in the Authorization header", "primary": True}],
        "meta": {"resourceType": "ServiceProviderConfig", "location": f"{self.baseURL}/ServiceProviderConfig"}})
    if head == "ResourceTypes":
      documents = {resourceType.name: {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": resourceType.name,
        "name": resourceType.name, "endpoint": resourceType.endpoint, "description": resourceType.description,
        "schema": resourceType.schema.id,
        "schemaExtensions": [{"schema": schema.id, "required": False} for schema in resourceType.extensions],
        "meta": {"resourceType": "ResourceType", "location": f"{self.baseURL}/ResourceTypes/{resourceType.name}"},
      } for resourceType in resourceTypes.values()}
    else:
      schemas = [userSchema, enterpriseSchema, groupSchema]
      documents = {schema.id: {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"], "id": schema.id, "name": schema.name,
        "description": schema.description, "attributes": [attribute.definition() for attribute in schema.attributes],
        "meta": {"resourceType": "Schema", "location": f"{self.baseURL}/Schemas/{schema.id}"},
      } for schema in schemas}
    if len(segments) == 2:
      if segments[1] not in documents:
        raise SCIMRefused(404, f"no {head} {segments[1]}")
      return self._answer(200, documents[segments[1]])
    if len(segments) != 1:
      raise SCIMRefused(404, "no such endpoint")
    return self._answer(200, {"schemas": [listResponseSchema], "totalResults": len(documents),
                              "itemsPerPage": len(documents), "startIndex": 1, "Resources": list(documents.values())})
