# SPDX-License-Identifier: MIT
"""A SCIM 2.0 service provider (RFC 7643 and RFC 7644): users and groups an identity provider pushes.

The application keeps the resources in its own Store and passes each HTTP request below its
SCIM base URL to SCIMService.handle, which authorizes, parses, checks and answers it. Users
(with the enterprise extension) and groups; filters with the whole RFC 7644 grammar; paging and
sorting; attribute selection; POST, GET, PUT, PATCH and DELETE; version tags (ETags, with
If-Match and If-None-Match); bulk requests; the discovery endpoints. Not offered: /Me, /.search
and passwords (a request carrying one is refused by name, or with discardPasswords dropped).

Strict by default: an unknown attribute, a value of the wrong type (the string "False" for a
boolean, say), a second primary value, a duplicate key and an unknown query parameter are
refused with the reason. Read-only attributes in a POST or PUT are ignored, as RFC 7644
section 3.3 requires; in a PATCH they are refused. Group display names are unique, because
Microsoft Entra ID matches groups by them. Two Entra forms are taken as Entra sends them:
PATCH op names in any case, and "remove" of members listed in "value" rather than in a filter.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Iterable
from typing import Any, Callable, Mapping, NoReturn, Protocol, cast
from urllib.parse import parse_qsl, unquote

from carnelian.fetching import checkNesting

__all__ = ["SCIMRefused", "SCIMService", "SCIMResponse", "Store", "Filter", "ResourceType", "userType", "groupType",
           "resourceTypes", "parseFilter", "matches", "Compare", "Present", "And", "Or", "Not", "ValuePath",
           "coreUserSchema", "coreGroupSchema", "enterpriseUserSchema"]

coreUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
coreGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
enterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
entraGroupSchema = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
listResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
patchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
mediaType = "application/scim+json"

JSON = dict[str, Any]


class SCIMRefused(ValueError):
  """A request refused, with its HTTP status, the RFC 7644 scimType when one fits, and why."""

  def __init__(self, status: int, detail: str, scimType: str | None = None) -> None:
    super().__init__(detail)
    self.status, self.detail, self.scimType = status, detail, scimType


def _invalid(detail: str, scimType: str = "invalidValue") -> SCIMRefused:
  return SCIMRefused(400, detail, scimType)


_surrogatePattern = re.compile(r"[\ud800-\udfff]")


def _refuseSurrogates(text: str, where: str, scimType: str = "invalidValue") -> None:
  if _surrogatePattern.search(text):
    raise _invalid(f"{where} holds a lone surrogate (half of a UTF-16 pair), which UTF-8 cannot carry", scimType)


def _isResourceID(text: str) -> bool:
  """Carnelian makes every resource ID itself as a UUID in its canonical form."""
  try:
    return str(uuid.UUID(text)) == text
  except ValueError:
    return False


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

  def definition(self) -> dict[str, object]:
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


def _named(attributes: Iterable[Attribute], name: str) -> Attribute | None:
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


def _plural(name: str, valueType: str = "string", types: tuple[str, ...] = (),
            referenceTypes: tuple[str, ...] = ()) -> Attribute:
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


def _container(resource: JSON, schema: Schema, resourceType: ResourceType) -> JSON | None:
  """Where a schema's attributes are kept: the resource itself for the core schema, else its extension's object."""
  return resource if schema is resourceType.schema else resource.get(schema.id)


def _writableContainer(resource: JSON, schema: Schema, resourceType: ResourceType) -> JSON:
  return resource if schema is resourceType.schema else resource.setdefault(schema.id, {})


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


def _readSingle(attribute: Attribute, value: object, where: str, patching: bool) -> Any:
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
    except ValueError:
      raise _invalid(f"{where} must be base64 text") from None
  return value


def _readValue(attribute: Attribute, value: object, where: str, patching: bool) -> Any:
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


def _checkPrimary(attribute: Attribute, items: list[Any], where: str) -> None:
  if attribute.type == "complex" and sum(1 for item in items if item.get("primary") is True) > 1:
    raise _invalid(f"{where} has more than one primary value")


def _readResource(resourceType: ResourceType, document: object) -> JSON:
  if not isinstance(document, dict):
    raise _invalid("the resource must be a JSON object", "invalidSyntax")
  declared = _declaredSchemas(resourceType, document)
  resource: JSON = {}
  seen: set[tuple[str, str]] = set()
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


def _declaredSchemas(resourceType: ResourceType, document: JSON) -> set[str]:
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


def _putRead(resource: JSON, resourceType: ResourceType, target: _Target, value: object,
             seen: set[tuple[str, str]]) -> None:
  key = (target.schema.id, target.attribute.name)
  if key in seen:
    raise _invalid(f"{target.attribute.name} appears twice", "invalidSyntax")
  seen.add(key)
  if target.attribute.mutability == "readOnly":
    return
  read = _readValue(target.attribute, value, target.attribute.name, patching=False)
  if read is not _absent:
    _writableContainer(resource, target.schema, resourceType)[target.attribute.name] = read


def _checkRequired(resourceType: ResourceType, resource: JSON) -> None:
  for schema in (resourceType.schema,) + resourceType.extensions:
    container = _container(resource, schema, resourceType)
    if container is None:
      continue
    for attribute in schema.attributes:
      if attribute.required and attribute.name not in container:
        raise _invalid(f"{attribute.name} is required")
      if attribute.multiValued and attribute.name in container:
        _checkPrimary(attribute, container[attribute.name], attribute.name)


def _checkWhole(resourceType: ResourceType, resource: JSON) -> None:
  """A changed resource read again as a whole: every value, required sub-attributes included."""
  document = {key: value for key, value in resource.items() if key not in ("id", "meta")}
  _checkRequired(resourceType, _readResource(resourceType, {"schemas": _schemasOf(resourceType, resource), **document}))


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
  left: Filter
  right: Filter


@dataclass(frozen=True)
class Or:
  left: Filter
  right: Filter


@dataclass(frozen=True)
class Not:
  inner: Filter


@dataclass(frozen=True)
class ValuePath:
  """attribute[filter]: some value of a multi-valued complex attribute matches the inner filter."""

  path: str
  inner: Filter


Filter = Compare | Present | And | Or | Not | ValuePath
_token = tuple[str, str, int, int]


comparisonOperators = ("eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le")
_tokenPattern = re.compile(r'\s*(?:(?P<mark>[()\[\]])|(?P<string>"(?:[^"\\]|\\.)*")|(?P<word>[^\s()\[\]"]+))', re.DOTALL)
_numberPattern = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_integerPattern = re.compile(r"-?[0-9]+")
maximumFilterLength = 4096
maximumFilterDepth = 32
maximumFilterTerms = 100
maximumNumberLength = 64


class _FilterParser:
  def __init__(self, text: str) -> None:
    if len(text) > maximumFilterLength:
      raise _invalid(f"a filter longer than {maximumFilterLength} characters", "invalidFilter")
    self.tokens: list[_token] = []
    position = 0
    while position < len(text):
      if not text[position:].strip():
        break
      found = _tokenPattern.match(text, position)
      if found is None:
        raise _invalid(f"the filter cannot be read at character {position}", "invalidFilter")
      kind = found.lastgroup
      if kind is None:
        raise _invalid(f"the filter cannot be read at character {position}", "invalidFilter")
      self.tokens.append((kind, found.group(kind), found.start(kind), found.end(kind)))
      position = found.end()
    self.index, self.depth, self.terms, self.inValuePath = 0, 0, 0, False

  def fail(self, why: str) -> NoReturn:
    raise _invalid(f"the filter {why}", "invalidFilter")

  def peek(self) -> _token | tuple[None, None, None, None]:
    return self.tokens[self.index] if self.index < len(self.tokens) else (None, None, None, None)

  def take(self) -> _token:
    token = self.peek()
    if token[0] is None:
      self.fail("ends too early")
    self.index += 1
    return token

  def isWord(self, word: str) -> bool:
    kind, text, _, _ = self.peek()
    return kind == "word" and cast(str, text).lower() == word

  def expectMark(self, mark: str) -> None:
    kind, text, _, _ = self.take()
    if kind != "mark" or text != mark:
      self.fail(f"needs {mark!r} where it has {text!r}")

  def parse(self) -> Filter:
    node = self.orExpression()
    if self.index != len(self.tokens):
      self.fail(f"has {self.peek()[1]!r} left over")
    return node

  def orExpression(self) -> Filter:
    self.depth += 1
    if self.depth > maximumFilterDepth:
      self.fail(f"nests deeper than {maximumFilterDepth}")
    node = self.andExpression()
    while self.isWord("or"):
      self.take()
      node = Or(node, self.andExpression())
    self.depth -= 1
    return node

  def andExpression(self) -> Filter:
    node = self.notExpression()
    while self.isWord("and"):
      self.take()
      node = And(node, self.notExpression())
    return node

  def notExpression(self) -> Filter:
    if self.isWord("not"):
      self.take()
      self.expectMark("(")
      inner = self.orExpression()
      self.expectMark(")")
      return Not(inner)
    return self.primary()

  def primary(self) -> Filter:
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
      if nextKind == "word" and cast(str, nextText).startswith(".") and nextStart == closed:
        self.take()
        inner = And(inner, self.comparison(cast(str, nextText)[1:]))
      return ValuePath(path, inner)
    return self.comparison(path)

  def comparison(self, path: str) -> Compare | Present:
    self.terms += 1
    if self.terms > maximumFilterTerms:
      self.fail(f"has more than {maximumFilterTerms} comparisons")
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
      _refuseSurrogates(value, "the filter")
    elif kind == "word" and text in ("true", "false", "null"):
      value = {"true": True, "false": False, "null": None}[text]
    elif kind == "word" and _numberPattern.fullmatch(text):
      value = _readNumber(text, "the filter", "invalidFilter")
    else:
      self.fail(f"needs a value after {path} {operator} where it has {text!r}")
    return Compare(path, operator, value)


def _readNumber(text: str, where: str, scimType: str) -> int | float:
  if len(text) > maximumNumberLength:
    raise _invalid(f"{where} has a number longer than {maximumNumberLength} characters", scimType)
  number: int | float = int(text) if _integerPattern.fullmatch(text) else float(text)
  if not math.isfinite(number):
    raise _invalid(f"{where} has a number beyond the range of a double: {text}", scimType)
  return number


def parseFilter(text: str) -> Filter:
  return _FilterParser(text).parse()


class _ResourceScope:
  def __init__(self, resourceType: ResourceType, resource: JSON) -> None:
    self.resourceType, self.resource = resourceType, resource

  def target(self, path: str) -> _Target:
    target = _resolve(self.resourceType, path, "invalidFilter")
    if self.resourceType is userType and target.attribute.name == "groups":
      raise _invalid("filter memberships through the members of /Groups, not a user's groups", "invalidFilter")
    return target

  def values(self, path: str) -> tuple[Attribute, list[Any]]:
    if path.lower() == "schemas":
      return schemasAttribute, _schemasOf(self.resourceType, self.resource)
    target = self.target(path)
    container = _container(self.resource, target.schema, self.resourceType) or {}
    return _collect(target.attribute, target.sub, container.get(target.attribute.name))

  def elements(self, path: str) -> tuple[Attribute, list[Any]]:
    target = self.target(path)
    if target.attribute.type != "complex" or target.sub is not None:
      raise _invalid(f"{path}[...] needs a complex attribute", "invalidFilter")
    container = _container(self.resource, target.schema, self.resourceType) or {}
    raw = container.get(target.attribute.name)
    return target.attribute, (raw if isinstance(raw, list) else [] if raw is None else [raw])


class _ElementScope:
  def __init__(self, attribute: Attribute, element: JSON) -> None:
    self.attribute, self.element = attribute, element

  def values(self, path: str) -> tuple[Attribute, list[Any]]:
    sub = self.attribute.sub(path)
    if sub is None:
      raise _invalid(f"{self.attribute.name} has no sub-attribute {path}", "invalidFilter")
    return sub, ([self.element[sub.name]] if sub.name in self.element else [])

  def elements(self, path: str) -> NoReturn:
    raise _invalid("a [] filter cannot hold another", "invalidFilter")


def _collect(attribute: Attribute, sub: Attribute | None, raw: Any) -> tuple[Attribute, list[Any]]:
  items = raw if isinstance(raw, list) else [] if raw is None else [raw]
  if attribute.type != "complex":
    return attribute, items
  if sub is None:
    sub = attribute.sub("value") if attribute.multiValued else None
    if sub is None:
      raise _invalid(f"{attribute.name} is complex: name one of its sub-attributes", "invalidFilter")
  return sub, [item[sub.name] for item in items if sub.name in item]


def _evaluate(node: Filter, scope: _ResourceScope | _ElementScope) -> bool:
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


def _compare(attribute: Attribute, values: list[Any], operator: str, operand: object, path: str) -> bool:
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
    key: Callable[[Any], Any] = lambda value: value
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
  tests: dict[str, Callable[[Any], bool]] = {
    "co": lambda value: operand in value, "sw": lambda value: value.startswith(operand),
    "ew": lambda value: value.endswith(operand), "gt": lambda value: value > operand,
    "ge": lambda value: value >= operand, "lt": lambda value: value < operand, "le": lambda value: value <= operand}
  return any(tests[operator](value) for value in keys)


def matches(resourceType: ResourceType, query: Filter, resource: JSON) -> bool:
  """Whether a stored resource matches a parsed filter; for stores that filter in memory."""
  return _evaluate(query, _ResourceScope(resourceType, resource))


def _walk(node: Filter, scope: _ResourceScope | _ElementScope) -> None:
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


def _checkFilter(resourceType: ResourceType, query: Filter) -> None:
  _walk(query, _ResourceScope(resourceType, {}))


def _checkElementFilter(attribute: Attribute, query: Filter) -> None:
  _walk(query, _ElementScope(attribute, {}))


def _schemasOf(resourceType: ResourceType, resource: JSON) -> list[str]:
  return [resourceType.schema.id] + [schema.id for schema in resourceType.extensions if schema.id in resource]


# ---- PATCH (RFC 7644 section 3.5.2) -----------------------------------------

_patchPathPattern = re.compile(r"([^\[\]]+)(?:\[(.*)\](?:\.([A-Za-z0-9_$-]+))?)?", re.DOTALL)


def _patchPath(resourceType: ResourceType, text: str) -> tuple[_Target, Filter | None]:
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


def _field(document: JSON, name: str, where: str) -> Any:
  found = [value for key, value in document.items() if key.lower() == name.lower()]
  if len(found) > 1:
    raise _invalid(f"{where} names {name} twice", "invalidSyntax")
  return found[0] if found else _absent


def _applyPatch(resourceType: ResourceType, resource: JSON, document: object, discardPasswords: bool) -> JSON | None:
  """The resource with the PATCH applied; None when discardPasswords leaves no operation to apply."""
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
  applied = 0
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
      if discardPasswords:
        if value and all(key.lower() == "password" for key in value):
          continue
        value = {key: item for key, item in value.items() if key.lower() != "password"}
      applied += 1
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
        target = _resolve(resourceType, key, "invalidPath")
        if target.attribute.mutability == "readOnly" and target.sub is None and op != "remove" \
            and (_container(work, target.schema, resourceType) or {}).get(target.attribute.name) == item:
          continue
        _apply(work, resourceType, op, target, None, item, f"{where}.value.{key}")
      continue
    if not isinstance(path, str):
      raise _invalid(f"{where}.path must be a string", "invalidSyntax")
    if path.lower() == "password":
      if discardPasswords:
        continue
      raise _invalid("password is refused: Carnelian takes no passwords over SCIM")
    applied += 1
    target, query = _patchPath(resourceType, path)
    _apply(work, resourceType, op, target, query, value, f"{where} {path}")
  if not applied:
    return None
  for schema in resourceType.extensions:
    if work.get(schema.id) == {}:
      del work[schema.id]
  _checkWhole(resourceType, work)
  return work


def _apply(work: JSON, resourceType: ResourceType, op: str, target: _Target, query: Filter | None, value: object,
           where: str) -> None:
  attribute, sub = target.attribute, target.sub
  if attribute.mutability == "readOnly" or (sub is not None and sub.mutability == "readOnly"):
    raise _invalid(f"{attribute.name} is read-only", "mutability")
  container = (_container(work, target.schema, resourceType) if op == "remove"
               else _writableContainer(work, target.schema, resourceType))
  if container is None:
    return
  name = attribute.name
  current = container.get(name)
  if op == "remove":
    _remove(container, attribute, sub, query, value, where)
  elif value is _absent:
    raise _invalid(f"{where}: {op} needs a value", "invalidSyntax")
  elif query is not None:
    values = current or []
    found = [element for element in values if _evaluate(query, _ElementScope(attribute, element))]
    if not found:
      raise _invalid(f"{where}: the filter matches no value of {name}", "noTarget")
    if sub is None:
      if op == "add":
        raise _invalid(f"{where}: add to a filtered value needs a sub-attribute", "invalidPath")
      replacement = _readSingle(attribute, value, where, True)
      if replacement is not _absent:
        for element in found:
          for part in attribute.subAttributes:
            if (part.mutability == "immutable" and part.name in element and part.name in replacement
                and element[part.name] != replacement[part.name]):
              raise _invalid(f"{where}: {name}.{part.name} is immutable: remove the value and add another",
                             "mutability")
      rebuilt = []
      for element in values:
        if not any(element is match for match in found):
          rebuilt.append(element)
        elif replacement is not _absent:
          rebuilt.append(copy.deepcopy(replacement))
      container[name] = rebuilt
    else:
      read = _readSingle(sub, value, where, True)
      if read is _absent:
        _refuseRemovingSub(attribute, sub, where)
      if sub.mutability == "immutable" and any(not sub.stored or element.get(sub.name) != read for element in found):
        raise _invalid(f"{where}: {name}.{sub.name} is immutable: remove the value and add another", "mutability")
      if read is not _absent and sub.name == "primary" and read is True:
        for element in values:
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
      _refuseRemovingSub(attribute, sub, where)
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


def _refuseRemovingSub(attribute: Attribute, sub: Attribute, where: str) -> None:
  if sub.required:
    raise _invalid(f"{where}: {attribute.name}.{sub.name} is required: remove the whole {attribute.name} value instead")
  if sub.mutability == "immutable":
    raise _invalid(f"{where}: {attribute.name}.{sub.name} is immutable: remove the value and add another",
                   "mutability")


def _sameValue(attribute: Attribute, left: Any, right: Any) -> bool:
  if attribute.type == "complex" and "value" in left and "value" in right:
    valueAttribute = attribute.sub("value")
    if valueAttribute is None:
      raise TypeError(f"{attribute.name} has no value sub-attribute")
    if valueAttribute.caseExact or not isinstance(left["value"], str):
      return cast(bool, left["value"] == right["value"])
    return cast(bool, left["value"].casefold() == right["value"].casefold())
  return cast(bool, left == right)


def _remove(container: JSON, attribute: Attribute, sub: Attribute | None, query: Filter | None, value: object,
            where: str) -> None:
  name = attribute.name
  current = container.get(name)
  if value is not _absent and not (attribute.multiValued and query is None and sub is None):
    raise _invalid(f"{where}: remove takes a value only to list values of a multi-valued attribute", "invalidSyntax")
  if sub is not None:
    _refuseRemovingSub(attribute, sub, where)
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
      raise _invalid(f"{where}: name which {name} value with a filter, as {name}[...].{cast(Attribute, sub).name}",
                     "invalidPath")
    current.pop(cast(Attribute, sub).name, None)
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
  created, lastModified, and revision, a count every write raises, which version tags are made
  from), the core attributes, and each extension under its schema URI. search gets a filter
  already checked against the schema (None for every resource), and `matches` evaluates one in
  memory. create and replace raise SCIMRefused(409, ..., "uniqueness") when the store's own
  unique constraints refuse the resource.

  A request is checked against the store first (If-Match and If-None-Match included) and then
  written in several calls; every request, and every operation of a bulk request, belongs in
  one transaction (a savepoint per bulk operation), so a check and the writes it allows hold
  together under concurrent requests. A refusal from the service comes before the first write,
  and a resource's own create or replace is its first write, so an operation refused for
  uniqueness has written nothing. Writes that follow: a group's write gives each user whose
  groups it changes a new revision; a DELETE first takes the resource out of every group that
  holds it, then (for a group) gives its users a new revision, and deletes it last, so a store
  failing midway leaves no group holding a member that is gone."""

  def create(self, resourceType: str, resource: JSON) -> None: ...

  def get(self, resourceType: str, resourceID: str) -> JSON | None: ...

  def replace(self, resourceType: str, resource: JSON) -> None: ...

  def delete(self, resourceType: str, resourceID: str) -> None: ...

  def search(self, resourceType: str, query: Filter | None) -> list[JSON]: ...


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


def _refuseDuplicates(pairs: list[tuple[str, Any]]) -> JSON:
  result = {}
  for key, value in pairs:
    if key in result:
      raise _invalid(f"the body names {key} twice", "invalidSyntax")
    result[key] = value
  return result


def _refuseConstant(name: str) -> NoReturn:
  raise _invalid(f"the body holds {name}, which is not JSON", "invalidSyntax")


def _readBodyNumber(text: str) -> int | float:
  return _readNumber(text, "the body", "invalidValue")


maximumQueryLength = 16384
maximumBulkOperations = 1000
bulkRequestSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
bulkResponseSchema = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"


maximumBulkIDLength = 64
_bulkIDPattern = re.compile(rf"[A-Za-z0-9._~-]{{1,{maximumBulkIDLength}}}")
_entityTag = r'(?:W/)?"[\x21\x23-\x7e\x80-\xff]*"'
_entityTagListPattern = re.compile(rf"\s*{_entityTag}\s*(?:,\s*{_entityTag}\s*)*")


def _bulkResource(reference: str, created: dict[str, str | None], where: str) -> str:
  """The ID an earlier POST of the request made for "bulkId:name"; any other name is refused."""
  name = reference.removeprefix("bulkId:")
  if not _bulkIDPattern.fullmatch(name):
    raise _invalid(f"{where} refers to {reference!r}, whose name is not a bulkId", "invalidValue")
  if name not in created:
    raise SCIMRefused(409, f"{where} refers to bulkId {name}, which no earlier operation of this request made",
                      "invalidValue")
  resourceID = created[name]
  if resourceID is None:
    raise SCIMRefused(409, f"{where} refers to bulkId {name}, whose POST failed", "invalidValue")
  return resourceID


def _isReference(resourceType: ResourceType, target: _Target) -> bool:
  """The attributes whose value may be "bulkId:name" (RFC 7644 section 3.7.2): a group's members, a user's manager."""
  return ((resourceType is groupType and target.attribute.name == "members")
          or (target.schema is enterpriseSchema and target.attribute.name == "manager"))


def _referenceTarget(resourceType: ResourceType, text: str, patchPath: bool) -> _Target | None:
  """The reference attribute a key or PATCH path names; any other, the route reads (and refuses) as it is."""
  try:
    target = _patchPath(resourceType, text)[0] if patchPath else _resolve(resourceType, text, "invalidPath")
  except SCIMRefused:
    return None
  return target if _isReference(resourceType, target) else None


def _resolveReference(value: object, created: dict[str, str | None], where: str) -> object:
  if isinstance(value, str) and value.startswith("bulkId:"):
    return _bulkResource(value, created, where)
  return value


def _resolveHolders(value: object, created: dict[str, str | None], where: str) -> object:
  """Member or manager objects as sent, each one's value resolved."""
  def one(item: object) -> object:
    if not isinstance(item, dict):
      return item
    return {key: _resolveReference(inner, created, where) if key.lower() == "value" else inner
            for key, inner in item.items()}
  return [one(item) for item in value] if isinstance(value, list) else one(value)


def _resolveAttributes(resourceType: ResourceType, document: object, created: dict[str, str | None],
                       where: str) -> object:
  """A resource body, or a PATCH value without a path, with "bulkId:name" resolved where it names a reference."""
  if not isinstance(document, dict):
    return document
  resolved: JSON = {}
  for key, value in document.items():
    extension = resourceType.schemaNamed(key)
    if extension is not None and extension is not resourceType.schema and isinstance(value, dict):
      inner: JSON = {}
      for innerKey, item in value.items():
        attribute = _named(extension.attributes, innerKey)
        reference = attribute is not None and _isReference(resourceType, _Target(extension, attribute, None))
        inner[innerKey] = _resolveHolders(item, created, where) if reference else item
      resolved[key] = inner
    elif _referenceTarget(resourceType, key, patchPath=False) is not None:
      resolved[key] = _resolveHolders(value, created, where)
    else:
      resolved[key] = value
  return resolved


def _resolvePatch(resourceType: ResourceType, document: object, created: dict[str, str | None], where: str) -> object:
  if not isinstance(document, dict):
    return document
  resolved = dict(document)
  for key, operations in document.items():
    if key.lower() == "operations" and isinstance(operations, list):
      resolved[key] = [_resolveOperation(resourceType, operation, created, where) for operation in operations]
  return resolved


def _resolveOperation(resourceType: ResourceType, operation: object, created: dict[str, str | None],
                      where: str) -> object:
  if not isinstance(operation, dict):
    return operation
  paths = [value for key, value in operation.items() if key.lower() == "path"]
  values = [key for key in operation if key.lower() == "value"]
  if len(paths) > 1 or len(values) != 1:
    return operation
  value = operation[values[0]]
  if not paths or paths[0] is None:
    return {**operation, values[0]: _resolveAttributes(resourceType, value, created, where)}
  if not isinstance(paths[0], str):
    return operation
  target = _referenceTarget(resourceType, paths[0], patchPath=True)
  if target is None:
    return operation
  if target.sub is None:
    return {**operation, values[0]: _resolveHolders(value, created, where)}
  if target.sub.name == "value":
    return {**operation, values[0]: _resolveReference(value, created, where)}
  return operation


def _version(resource: JSON) -> str:
  """A resource's weak entity tag, from what it holds and its revision, so a write never brings back an earlier tag."""
  content = {key: value for key, value in resource.items() if key != "meta"}
  revision = resource["meta"]["revision"]
  digest = hashlib.sha256(json.dumps([revision, content], sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
  return f'W/"{digest[:32]}"'


def _entityTags(header: str, name: str) -> list[str]:
  if header.strip() == "*":
    return ["*"]
  if not _entityTagListPattern.fullmatch(header):
    raise _invalid(f"{name} is not * or a list of entity tags", "invalidSyntax")
  return re.findall(_entityTag, header)


def _ifMatch(header: str, version: str) -> bool:
  """If-Match compares the tag exactly as this service gave it: weak, as RFC 7644 section 3.14 sends it, and
  changed by every write (see _version), so RFC 7232's strong comparison, which never matches a weak tag, is not used."""
  tags = _entityTags(header, "If-Match")
  return tags == ["*"] or version in tags


def _ifNoneMatch(header: str, version: str) -> bool:
  """If-None-Match compares weakly (RFC 7232 section 2.3.2): the tags' opaque parts, W/ or not."""
  tags = _entityTags(header, "If-None-Match")
  return tags == ["*"] or version.removeprefix("W/") in (tag.removeprefix("W/") for tag in tags)


def _touched(meta: JSON, stamp: str) -> JSON:
  return {**meta, "lastModified": stamp, "revision": meta["revision"] + 1}


def _sortKey(resourceType: ResourceType, path: str, resource: JSON) -> tuple[Any, ...] | None:
  """The value a resource sorts by: a multi-valued attribute's primary value, else its first; None when it has none."""
  target = _resolve(resourceType, path, "invalidValue")
  if target.attribute.type == "complex" and target.sub is None and not target.attribute.multiValued:
    raise _invalid(f"sortBy {path} is complex: name one of its sub-attributes")
  attribute, values = _ResourceScope(resourceType, resource).values(path)
  if target.attribute.multiValued and target.attribute.type == "complex" and values:
    container = _container(resource, target.schema, resourceType) or {}
    elements = container.get(target.attribute.name, [])
    primary = [element for element in elements if element.get("primary") is True]
    sub = target.sub.name if target.sub is not None else "value"
    chosen = (primary or elements)[0]
    values = [chosen[sub]] if sub in chosen else values
  if not values:
    return None
  value = values[0]
  if attribute.type == "dateTime":
    return (_parseTime(value, path).timestamp(),)
  if isinstance(value, str) and not attribute.caseExact:
    return (value.casefold(), value)
  return (value,)
maximumQueryParameters = 8


def _checkNesting(text: str) -> None:
  try:
    checkNesting(text)
  except ValueError as error:
    raise _invalid(f"the body {error}", "invalidSyntax") from None


class SCIMService:
  """Answers SCIM requests below baseURL (https) from the store, once isAuthorized accepts the bearer token.

  An accepted token authorizes everything the service does on the store: it creates, changes
  and deletes every user and group, active, roles, entitlements and memberships included.
  isAuthorized answers only yes or no, so a token meant for one tenant or for narrower rights
  gets no narrower treatment here; such grants are the application's to enforce, in the store
  it passes (one per tenant, say) and in its token check."""

  def __init__(self, store: Store, baseURL: str, isAuthorized: Callable[[str], bool], pageSize: int = 100,
               maximumResults: int = 200, maximumBytes: int = 1_000_000,
               clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc), discardPasswords: bool = False) -> None:
    if not baseURL.startswith("https://") or baseURL.endswith("/"):
      raise ValueError("baseURL must be an https URL without a trailing slash")
    if not 0 < pageSize <= maximumResults:
      raise ValueError("pageSize must be positive and at most maximumResults")
    self.store, self.baseURL, self.isAuthorized = store, baseURL, isAuthorized
    self.pageSize, self.maximumResults, self.maximumBytes, self.clock = pageSize, maximumResults, maximumBytes, clock
    self.discardPasswords = discardPasswords

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

  def _answer(self, status: int, document: JSON | None, extra: dict[str, str] | None = None) -> SCIMResponse:
    headers = dict(extra or {})
    if document is None:
      return SCIMResponse(status, headers, b"")
    headers["Content-Type"] = mediaType
    return SCIMResponse(status, headers, json.dumps(document, ensure_ascii=False).encode("utf-8"))

  def _route(self, method: str, path: str, query: str, headers: dict[str, str], body: bytes) -> SCIMResponse:
    _refuseSurrogates(path, "the path")
    if not path.startswith("/"):
      raise SCIMRefused(404, f"no endpoint {path}")
    segments = [unquote(segment) for segment in path[1:].split("/")]
    parameters = self._parameters(query)
    head = segments[0]
    if head == "Bulk" and len(segments) == 1:
      if method != "POST":
        raise SCIMRefused(405, f"{method} is not allowed on /Bulk")
      self._allow(parameters, ())
      return self._bulk(headers, body)
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
      self._allowProjection(resourceType, parameters)
      resource = self._existing(resourceType, resourceID)
      version = _version(resource)
      if self._preconditions(resourceType, headers, version, reading=True):
        return self._answer(304, None, {"ETag": version})
      return self._answer(200, self._render(resourceType, resource, parameters), {"ETag": version})
    if method in ("PUT", "PATCH", "DELETE") and ("if-match" in headers or "if-none-match" in headers):
      self._preconditions(resourceType, headers, _version(self._existing(resourceType, resourceID)), reading=False)
    if method == "PUT":
      return self._replace(resourceType, resourceID, parameters, headers, body)
    if method == "PATCH":
      return self._patch(resourceType, resourceID, parameters, headers, body)
    if method == "DELETE":
      self._allow(parameters, ())
      return self._delete(resourceType, resourceID)
    raise SCIMRefused(405, f"{method} is not allowed on {resourceType.endpoint}/{{id}}")

  @staticmethod
  def _preconditions(resourceType: ResourceType, headers: dict[str, str], version: str, reading: bool) -> bool:
    """RFC 7232 section 6: If-Match, then If-None-Match; True when a read is to be answered 304."""
    if "if-match" in headers and not _ifMatch(headers["if-match"], version):
      raise SCIMRefused(412, f"the {resourceType.name} has changed since the version given in If-Match")
    if "if-none-match" in headers and _ifNoneMatch(headers["if-none-match"], version):
      if reading:
        return True
      raise SCIMRefused(412, f"the {resourceType.name} has the version given in If-None-Match")
    return False

  # -- requests

  def _parameters(self, query: str) -> dict[str, str]:
    if not query:
      return {}
    if len(query) > maximumQueryLength:
      raise _invalid(f"the query string is longer than {maximumQueryLength} characters")
    if query.count("&") >= maximumQueryParameters:
      raise _invalid(f"the query string has more than {maximumQueryParameters} parameters")
    _refuseSurrogates(query, "the query string")
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

  def _allow(self, parameters: dict[str, str], allowed: tuple[str, ...]) -> None:
    unknown = sorted(set(parameters) - set(allowed))
    if unknown:
      raise _invalid(f"unknown query parameters {unknown}")

  def _allowProjection(self, resourceType: ResourceType, parameters: dict[str, str]) -> None:
    """Checked before any write, so a request refused for its projection has changed nothing."""
    self._allow(parameters, ("attributes", "excludedAttributes"))
    self._projection(resourceType, parameters)

  def _document(self, headers: dict[str, str], body: bytes) -> object:
    contentType = headers.get("content-type", "").split(";")[0].strip().lower()
    if contentType not in (mediaType, "application/json"):
      raise SCIMRefused(415, f"the body must be {mediaType}")
    if len(body) > self.maximumBytes:
      raise SCIMRefused(413, f"the body is larger than {self.maximumBytes} bytes")
    try:
      text = body.decode("utf-8")
      _checkNesting(text)
      document = json.loads(text, object_pairs_hook=_refuseDuplicates, parse_constant=_refuseConstant,
                            parse_int=_readBodyNumber, parse_float=_readBodyNumber)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
      raise _invalid(f"the body is not JSON: {error}", "invalidSyntax") from None
    _refuseSurrogates(json.dumps(document, ensure_ascii=False), "the body")
    return document

  def _existing(self, resourceType: ResourceType, resourceID: str) -> JSON:
    if not _isResourceID(resourceID):
      raise SCIMRefused(404, f"no {resourceType.name} {resourceID}")
    resource = self.store.get(resourceType.name, resourceID)
    if resource is None:
      raise SCIMRefused(404, f"no {resourceType.name} {resourceID}")
    return copy.deepcopy(resource)

  # -- checks shared by create, replace and patch

  def _checkResource(self, resourceType: ResourceType, resource: JSON, resourceID: str) -> None:
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
        found = [name for name in ("User", "Group")
                 if _isResourceID(member["value"]) and self.store.get(name, member["value"]) is not None]
        if not found:
          raise _invalid(f"member {member['value']} is neither a user nor a group here")
        if member.get("type", found[0]) != found[0]:
          raise _invalid(f"member {member['value']} is a {found[0]}, not a {member['type']}")
        member["type"] = found[0]
        if found[0] == "Group" and self._holds(member["value"], resourceID):
          raise _invalid(f"member {member['value']} holds this group already, so the group would contain itself")

  def _holds(self, outerID: str, innerID: str) -> bool:
    """Whether the group outerID holds innerID, directly or through groups it holds."""
    pending, seen = [outerID], set()
    while pending:
      groupID = pending.pop()
      if groupID == innerID:
        return True
      if groupID in seen:
        continue
      seen.add(groupID)
      group = self.store.get("Group", groupID)
      if group is not None:
        pending.extend(member["value"] for member in group.get("members", []) if member.get("type") == "Group")
    return False

  def _create(self, resourceType: ResourceType, parameters: dict[str, str], headers: dict[str, str],
              body: bytes) -> SCIMResponse:
    self._allowProjection(resourceType, parameters)
    resource = _readResource(resourceType, self._withoutPasswords(self._document(headers, body)))
    resourceID = str(uuid.uuid4())
    self._checkResource(resourceType, resource, resourceID)
    stamp = _stamp(self.clock())
    resource = {"id": resourceID, "meta": {"resourceType": resourceType.name, "created": stamp, "lastModified": stamp,
                                           "revision": 1}, **resource}
    self.store.create(resourceType.name, resource)
    if resourceType is groupType:
      self._touchMembers(None, resource, stamp)
    rendered = self._render(resourceType, resource, parameters)
    return self._answer(201, rendered, {"Location": self._location(resourceType, resourceID), "ETag": _version(resource)})

  def _replace(self, resourceType: ResourceType, resourceID: str, parameters: dict[str, str], headers: dict[str, str],
               body: bytes) -> SCIMResponse:
    self._allowProjection(resourceType, parameters)
    existing = self._existing(resourceType, resourceID)
    resource = _readResource(resourceType, self._withoutPasswords(self._document(headers, body)))
    self._checkResource(resourceType, resource, resourceID)
    stamp = _stamp(self.clock())
    resource = {"id": resourceID, "meta": _touched(existing["meta"], stamp), **resource}
    self.store.replace(resourceType.name, resource)
    if resourceType is groupType:
      self._touchMembers(existing, resource, stamp)
    return self._answer(200, self._render(resourceType, resource, parameters), {"ETag": _version(resource)})

  def _bulk(self, headers: dict[str, str], body: bytes) -> SCIMResponse:
    document = self._document(headers, body)
    if not isinstance(document, dict) or document.get("schemas") != [bulkRequestSchema]:
      raise _invalid(f"a bulk request names exactly the schema {bulkRequestSchema}", "invalidSyntax")
    unknown = sorted(set(document) - {"schemas", "Operations", "failOnErrors"})
    if unknown:
      raise _invalid(f"a bulk request has unknown members {unknown}", "invalidSyntax")
    operations = document.get("Operations")
    if not isinstance(operations, list) or not operations:
      raise _invalid("a bulk request needs a list of Operations", "invalidSyntax")
    if len(operations) > maximumBulkOperations:
      raise SCIMRefused(413, f"a bulk request may hold at most {maximumBulkOperations} operations")
    failOnErrors = document.get("failOnErrors")
    if failOnErrors is not None and (type(failOnErrors) is not int or failOnErrors < 1):
      raise _invalid("failOnErrors is a whole number of at least 1", "invalidSyntax")
    created: dict[str, str | None] = {}
    answers: list[JSON] = []
    errors = 0
    for index, operation in enumerate(operations):
      if failOnErrors is not None and errors >= failOnErrors:
        break
      answers.append(self._bulkOperation(index, operation, created))
      errors += int(answers[-1]["status"]) >= 400
    return self._answer(200, {"schemas": [bulkResponseSchema], "Operations": answers})

  def _bulkOperation(self, index: int, operation: object, created: dict[str, str | None]) -> JSON:
    """One operation, answered on its own: a malformed one too, so it counts toward failOnErrors."""
    where = f"Operations[{index}]"
    answer: JSON = {}
    if isinstance(operation, dict):
      answer.update((key, operation[key]) for key in ("method", "bulkId") if isinstance(operation.get(key), str))
    try:
      method, path, body, headers = self._readBulkOperation(where, operation, created)
      response = self._route(method, path, "", headers, body)
    except SCIMRefused as refused:
      error: JSON = {"schemas": [errorSchema], "status": str(refused.status), "detail": refused.detail}
      if refused.scimType is not None:
        error["scimType"] = refused.scimType
      answer.update(status=str(refused.status), response=error)
      return answer
    answer["status"] = str(response.status)
    if "ETag" in response.headers:
      answer["version"] = response.headers["ETag"]
    if method == "POST":
      created[answer["bulkId"]] = cast(str, json.loads(response.body)["id"])
      answer["location"] = response.headers["Location"]
    elif method != "DELETE":
      answer["location"] = f"{self.baseURL}{path}"
    return answer

  def _readBulkOperation(self, where: str, operation: object, created: dict[str, str | None]
                         ) -> tuple[str, str, bytes, dict[str, str]]:
    """The method, path (bulkId resolved), body (bulkId references resolved) and headers of one bulk operation."""
    if not isinstance(operation, dict):
      raise _invalid(f"{where} must be an object", "invalidSyntax")
    unknown = sorted(set(operation) - {"method", "bulkId", "version", "path", "data"})
    if unknown:
      raise _invalid(f"{where} has unknown members {unknown}", "invalidSyntax")
    method, path, bulkId = operation.get("method"), operation.get("path"), operation.get("bulkId")
    if method not in ("POST", "PUT", "PATCH", "DELETE") or not isinstance(path, str):
      raise _invalid(f"{where} needs a method (POST, PUT, PATCH or DELETE) and a path", "invalidSyntax")
    if not re.fullmatch(r"/(Users|Groups)(/[^/]+)?", path) or (method == "POST") != ("/" not in path[1:]):
      raise _invalid(f"{where}: {method} {path} is not a resource operation", "invalidPath")
    if "bulkId" in operation and (not isinstance(bulkId, str) or not _bulkIDPattern.fullmatch(bulkId)):
      raise _invalid(f"{where}: a bulkId is 1 to {maximumBulkIDLength} letters, digits and . _ ~ -", "invalidSyntax")
    if method == "POST" and bulkId is None:
      raise _invalid(f"{where}: a POST needs a bulkId", "invalidSyntax")
    if bulkId is not None and bulkId in created:
      raise _invalid(f"{where}: bulkId {bulkId} is used by an earlier operation", "invalidSyntax")
    headers = {"content-type": mediaType}
    if "version" in operation:
      version = operation["version"]
      if method == "POST":
        raise _invalid(f"{where}: a POST takes no version", "invalidSyntax")
      if not isinstance(version, str) or not re.fullmatch(_entityTag, version):
        raise _invalid(f"{where}: version must be an entity tag", "invalidSyntax")
      headers["if-match"] = version
    if method == "DELETE" and "data" in operation:
      raise _invalid(f"{where}: a DELETE takes no data", "invalidSyntax")
    if method == "POST":
      created[cast(str, bulkId)] = None
    endpoint, _, segment = path[1:].partition("/")
    if segment.startswith("bulkId:"):
      path = f"/{endpoint}/{_bulkResource(segment, created, where)}"
    if method == "DELETE":
      return method, path, b"", headers
    resourceType = userType if endpoint == "Users" else groupType
    data = operation.get("data")
    resolved = (_resolvePatch(resourceType, data, created, where) if method == "PATCH"
                else _resolveAttributes(resourceType, data, created, where))
    return method, path, json.dumps(resolved, ensure_ascii=False).encode("utf-8"), headers

  def _withoutPasswords(self, document: object) -> object:
    """With discardPasswords, a POST or PUT body without its password (Okta sends one even when it syncs none)."""
    if not self.discardPasswords or not isinstance(document, dict):
      return document
    return {key: value for key, value in document.items() if key.lower() != "password"}

  def _patch(self, resourceType: ResourceType, resourceID: str, parameters: dict[str, str], headers: dict[str, str],
             body: bytes) -> SCIMResponse:
    self._allowProjection(resourceType, parameters)
    existing = self._existing(resourceType, resourceID)
    resource = _applyPatch(resourceType, existing, self._document(headers, body), self.discardPasswords)
    if resource is None:
      return self._patched(resourceType, existing, parameters)
    self._checkResource(resourceType, resource, resourceID)
    stamp = _stamp(self.clock())
    resource["meta"] = _touched(resource["meta"], stamp)
    self.store.replace(resourceType.name, resource)
    if resourceType is groupType:
      self._touchMembers(existing, resource, stamp)
    return self._patched(resourceType, resource, parameters)

  def _patched(self, resourceType: ResourceType, resource: JSON, parameters: dict[str, str]) -> SCIMResponse:
    # A group's member list can be long, so its PATCH answers without a body, as Entra asks.
    if resourceType is groupType and not parameters:
      return self._answer(204, None, {"ETag": _version(resource)})
    return self._answer(200, self._render(resourceType, resource, parameters), {"ETag": _version(resource)})

  def _delete(self, resourceType: ResourceType, resourceID: str) -> SCIMResponse:
    existing = self._existing(resourceType, resourceID)
    stamp = _stamp(self.clock())
    for group in self.store.search("Group", ValuePath("members", Compare("value", "eq", resourceID))):
      group = copy.deepcopy(group)
      group["members"] = [member for member in group["members"] if member["value"] != resourceID]
      if not group["members"]:
        del group["members"]
      group["meta"] = _touched(group["meta"], stamp)
      self.store.replace("Group", group)
    if resourceType is groupType:
      self._touchMembers(existing, None, stamp)
    self.store.delete(resourceType.name, resourceID)
    return self._answer(204, None)

  def _touchMembers(self, before: JSON | None, after: JSON | None, stamp: str) -> None:
    """A new revision for each user whose rendered groups a group's write changes, so its version changes too."""
    def users(group: JSON | None) -> set[str]:
      return {member["value"] for member in (group or {}).get("members", []) if member["type"] == "User"}
    renamed = before is not None and after is not None and before["displayName"] != after["displayName"]
    changed = users(before) | users(after) if renamed else users(before) ^ users(after)
    for userID in sorted(changed):
      user = self.store.get("User", userID)
      if user is None:
        raise LookupError(f"a group holds the user {userID}, which the store does not have")
      user["meta"] = _touched(user["meta"], stamp)
      self.store.replace("User", user)

  def _list(self, resourceType: ResourceType, parameters: dict[str, str]) -> SCIMResponse:
    self._allow(parameters, ("filter", "startIndex", "count", "attributes", "excludedAttributes", "sortBy", "sortOrder"))
    self._projection(resourceType, parameters)
    order = parameters.get("sortOrder", "ascending")
    if order not in ("ascending", "descending") or ("sortOrder" in parameters and "sortBy" not in parameters):
      raise _invalid("sortOrder is ascending or descending, and only with sortBy")
    if "sortBy" in parameters:
      _sortKey(resourceType, parameters["sortBy"], {"id": "", "meta": {}})
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
    if "sortBy" in parameters:
      present = [item for item in found if _sortKey(resourceType, parameters["sortBy"], item) is not None]
      absent = [item for item in found if _sortKey(resourceType, parameters["sortBy"], item) is None]
      present.sort(key=lambda item: cast(tuple[Any, ...], _sortKey(resourceType, parameters["sortBy"], item)),
                   reverse=order == "descending")
      found = present + absent
    page = found[startIndex - 1:startIndex - 1 + count]
    return self._answer(200, {
      "schemas": [listResponseSchema], "totalResults": len(found), "itemsPerPage": len(page), "startIndex": startIndex,
      "Resources": [self._render(resourceType, resource, parameters) for resource in page]})

  @staticmethod
  def _whole(parameters: dict[str, str], name: str, default: int) -> int:
    if name not in parameters:
      return default
    text = parameters[name]
    if not re.fullmatch(r"[0-9]{1,9}", text):
      raise _invalid(f"{name} must be a whole number")
    return int(text)

  # -- answers

  def _location(self, resourceType: ResourceType, resourceID: str) -> str:
    return f"{self.baseURL}{resourceType.endpoint}/{resourceID}"

  def _projection(self, resourceType: ResourceType, parameters: dict[str, str]
                  ) -> tuple[set[tuple[str, str, str | None]] | None, set[tuple[str, str, str | None]]]:
    if "attributes" in parameters and "excludedAttributes" in parameters:
      raise _invalid("give attributes or excludedAttributes, not both")
    def keys(text: str) -> set[tuple[str, str, str | None]]:
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

  def _render(self, resourceType: ResourceType, resource: JSON, parameters: dict[str, str]) -> JSON:
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
    stored["meta"] = {**resource["meta"], "location": self._location(resourceType, resource["id"]), "version": _version(resource)}
    if resourceType is userType and wanted(core, cast(Attribute, _named(core.attributes, "groups"))):
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

  def _renderValue(self, schema: Schema, attribute: Attribute, value: Any,
                   wanted: Callable[[Schema, Attribute, Attribute | None], bool]) -> object:
    if attribute.type != "complex":
      return value
    def one(item: JSON) -> JSON:
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
        "patch": {"supported": True},
        "bulk": {"supported": True, "maxOperations": maximumBulkOperations, "maxPayloadSize": self.maximumBytes},
        "filter": {"supported": True, "maxResults": self.maximumResults}, "changePassword": {"supported": False},
        "sort": {"supported": True}, "etag": {"supported": True},
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
