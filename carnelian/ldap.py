# SPDX-License-Identifier: MIT
"""An LDAPv3 client for signing in against Active Directory (RFC 4511).

Only what sign-in needs: simple bind, search, StartTLS, unbind, always over TLS (LDAPS, or
StartTLS before anything else is said), with certificate and hostname checks; a TLS context
that does not require them is refused. Filters are built as values, never parsed from text,
so a user name cannot inject filter syntax. A bind with an empty password or an empty name
is refused before it is sent: LDAP treats it as an anonymous bind that succeeds (RFC 4513
section 5.1), the classic way past a directory check.

Every answer is read strictly: an LDAPResult must carry its ENUMERATED result code and its
two OCTET STRINGs, and search entries their DN and attribute list, or the answer is refused.
Each operation has a deadline (maximumOperationSeconds), a byte budget
(maximumOperationBytes) and, for a search, a maximum number of entries (maximumEntries),
all enforced here whatever the directory does with the limits it is sent. A search
reference (a pointer to another server) is refused: sign-in does not follow referrals, and
ignoring one would let a partial answer stand for the whole.

Sign-in: the service account finds the one person (objectCategory person, objectClass user;
computer accounts never match) with the user name, the account must carry
userAccountControl and not be disabled, the person's password is checked by binding as that
entry on a fresh connection, and the groups are those the entry belongs to, nested ones
included (Active Directory's LDAP_MATCHING_RULE_IN_CHAIN), named by sAMAccountName, which
Active Directory keeps unique in the domain (a cn is unique only within its container).
OpenLDAP groups are groupOfNames in one container, each named by the cn its DN begins with
(a group whose first RDN is not cn=<its cn> is refused, since its cn need not be unique
there), told apart by entryUUID, and walked within maximumGroupNesting levels,
maximumGroupSearches searches, maximumGroups groups and maximumGroupWalkSeconds.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from enum import Enum

__all__ = ["DirectoryRefused", "Directory", "DirectoryKind", "DirectoryIdentity"]

maximumMessageBytes = 4_000_000
maximumOperationBytes = 16_000_000
maximumOperationSeconds = 30.0
maximumEntries = 1000
# Active Directory's LDAP_SERVER_DOMAIN_SCOPE control: answer from this domain only, without references to other
# partitions, so a reference that still arrives is refused rather than ignored. Other servers ignore it (not critical).
domainScopeControl = "1.2.840.113556.1.4.1339"


class DirectoryRefused(ValueError):
  """A sign-in, connection or answer refused, with why."""


# ---- BER (X.690), as LDAP uses it ------------------------------------------

def _length(length: int) -> bytes:
  if length < 0x80:
    return bytes([length])
  body = length.to_bytes((length.bit_length() + 7) // 8, "big")
  return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
  return bytes([tag]) + _length(len(content)) + content


def integer(value: int, tag: int = 0x02) -> bytes:
  return tlv(tag, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


def octets(value: bytes | str, tag: int = 0x04) -> bytes:
  return tlv(tag, value.encode("utf-8") if isinstance(value, str) else value)


def boolean(value: bool, tag: int = 0x01) -> bytes:
  return tlv(tag, b"\xff" if value else b"\x00")


def sequence(*parts: bytes, tag: int = 0x30) -> bytes:
  return tlv(tag, b"".join(parts))


def readTLV(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
  """(tag, content, next offset); long-form lengths of up to four bytes, definite only."""
  if offset + 2 > len(data):
    raise DirectoryRefused("a truncated LDAP message")
  tag = data[offset]
  first = data[offset + 1]
  position = offset + 2
  if first < 0x80:
    length = first
  else:
    count = first & 0x7F
    if count == 0 or count > 4 or position + count > len(data):
      raise DirectoryRefused("an LDAP length that is indefinite or out of range")
    length = int.from_bytes(data[position:position + count], "big")
    position += count
  if position + length > len(data):
    raise DirectoryRefused("a truncated LDAP message")
  return tag, data[position:position + length], position + length


def readAll(data: bytes) -> list[tuple[int, bytes]]:
  parts, offset = [], 0
  while offset < len(data):
    tag, content, offset = readTLV(data, offset)
    parts.append((tag, content))
  return parts


def readInteger(content: bytes) -> int:
  if not content:
    raise DirectoryRefused("an LDAP integer without content")
  return int.from_bytes(content, "big", signed=True)


def _text(content: bytes, what: str) -> str:
  try:
    return content.decode("utf-8")
  except UnicodeDecodeError:
    raise DirectoryRefused(f"{what} that is not UTF-8") from None


def _tags(parts: list[tuple[int, bytes]]) -> list[int]:
  return [tag for tag, _ in parts]


# ---- filters, as values -----------------------------------------------------

@dataclass(frozen=True)
class Equal:
  attribute: str
  value: str

  def encoded(self) -> bytes:
    return sequence(octets(self.attribute), octets(self.value), tag=0xA3)


@dataclass(frozen=True)
class Present:
  attribute: str

  def encoded(self) -> bytes:
    return octets(self.attribute, tag=0x87)


@dataclass(frozen=True)
class InChain:
  """Active Directory: entries whose `attribute` reaches `value` through any number of links."""

  attribute: str
  value: str

  def encoded(self) -> bytes:
    return sequence(octets("1.2.840.113556.1.4.1941", 0x81), octets(self.attribute, 0x82),
                    octets(self.value, 0x83), tag=0xA9)


@dataclass(frozen=True)
class All:
  filters: tuple[Filter, ...]

  def encoded(self) -> bytes:
    return sequence(*(part.encoded() for part in self.filters), tag=0xA0)


type Filter = Equal | Present | InChain | All


# ---- answers ----------------------------------------------------------------

resultNames = {0: "success", 3: "timeLimitExceeded", 4: "sizeLimitExceeded", 10: "referral",
               11: "adminLimitExceeded", 14: "saslBindInProgress", 32: "noSuchObject", 34: "invalidDNSyntax",
               48: "inappropriateAuthentication", 49: "invalidCredentials", 50: "insufficientAccessRights",
               53: "unwillingToPerform"}


def checkResult(result: bytes, what: str, extraTags: frozenset[int] = frozenset()) -> None:
  """Refuse an LDAPResult that is malformed or not success; `extraTags` are the operation's own trailing parts."""
  parts = readAll(result)
  if _tags(parts[:3]) != [0x0A, 0x04, 0x04]:
    raise DirectoryRefused(f"{what}: an LDAPResult without its result code, matched DN and diagnostic message")
  code = readInteger(parts[0][1])
  trailing = _tags(parts[3:])
  if len(set(trailing)) != len(trailing) or not set(trailing) <= extraTags | {0xA3}:
    raise DirectoryRefused(f"{what}: an LDAPResult with unexpected parts {[f'0x{tag:02x}' for tag in trailing]}")
  if code != 0:
    message = parts[2][1].decode("utf-8", "replace")
    raise DirectoryRefused(f"{what}: {resultNames.get(code, code)} {message}".rstrip())
  if 0xA3 in trailing:
    raise DirectoryRefused(f"{what}: a success that carries a referral")


@dataclass(frozen=True)
class Entry:
  """A search entry; attribute names are in lower case, as LDAP compares them without case."""

  dn: str
  attributes: dict[str, tuple[str, ...]]

  def values(self, name: str) -> tuple[str, ...] | None:
    return self.attributes.get(name.lower())


def readEntry(content: bytes) -> Entry:
  """A SearchResultEntry's content: the DN, then attributes that each hold a name and a set of values."""
  parts = readAll(content)
  if _tags(parts) != [0x04, 0x30]:
    raise DirectoryRefused("a search entry that is not a DN and an attribute list")
  attributes: dict[str, tuple[str, ...]] = {}
  for tag, attribute in readAll(parts[1][1]):
    pieces = readAll(attribute)
    if tag != 0x30 or _tags(pieces) != [0x04, 0x31]:
      raise DirectoryRefused("a search entry attribute that is not a name and a set of values")
    name = _text(pieces[0][1], "an attribute name").lower()
    if not name or name in attributes:
      raise DirectoryRefused(f"a search entry with the attribute name {name!r} empty or twice")
    values = readAll(pieces[1][1])
    if any(valueTag != 0x04 for valueTag in _tags(values)):
      raise DirectoryRefused(f"a search entry whose {name} holds something other than OCTET STRINGs")
    attributes[name] = tuple(_text(value, f"a value of {name}") for _, value in values)
  return Entry(dn=_text(parts[0][1], "a DN"), attributes=attributes)


def _requireVerification(context: ssl.SSLContext) -> None:
  if (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname
      or context.minimum_version < ssl.TLSVersion.TLSv1_2):
    raise DirectoryRefused("a TLS context that does not require a verified certificate, the host name and TLS 1.2 "
                           "or newer is refused")


# ---- the connection ---------------------------------------------------------

class Connection:
  """One LDAP connection over a socket; Connection.open makes it TLS-protected. Use it as a context manager."""

  def __init__(self, transport: socket.socket):
    self._socket = transport
    self._idleSeconds = transport.gettimeout()
    self._nextID = 1
    self._deadline = 0.0
    self._bytesLeft = 0

  @classmethod
  def open(cls, host: str, port: int, context: ssl.SSLContext, startTLS: bool, timeoutSeconds: float) -> Connection:
    """LDAPS, or StartTLS before anything else; the certificate and host name are checked."""
    _requireVerification(context)
    try:
      raw = socket.create_connection((host, port), timeout=timeoutSeconds)
    except OSError as error:
      raise DirectoryRefused(f"cannot reach the directory at {host}:{port}: {error}") from None
    try:
      connection = cls(raw)
      if startTLS:
        tag, result = connection._request(sequence(octets("1.3.6.1.4.1.1466.20037", 0x80), tag=0x77))
        if tag != 0x78:
          raise DirectoryRefused("the directory did not answer StartTLS")
        checkResult(result, "StartTLS", frozenset({0x8A, 0x8B}))
      try:
        connection._socket = context.wrap_socket(raw, server_hostname=host)
      except OSError as error:
        raise DirectoryRefused(f"no TLS with the directory at {host}:{port}: {error}") from None
    except BaseException:
      raw.close()
      raise
    return connection

  def __enter__(self) -> Connection:
    return self

  def __exit__(self, *exception: object) -> None:
    try:
      self._begin()
      self._send(self._message(tlv(0x42, b"")))
    except DirectoryRefused:
      pass
    self._socket.close()

  def _begin(self) -> None:
    self._deadline = time.monotonic() + maximumOperationSeconds
    self._bytesLeft = maximumOperationBytes

  def _timeout(self) -> float:
    remaining = self._deadline - time.monotonic()
    if remaining <= 0:
      raise DirectoryRefused(f"the directory did not finish within {maximumOperationSeconds} seconds")
    return remaining if self._idleSeconds is None else min(self._idleSeconds, remaining)

  def _timedOut(self, seconds: float) -> DirectoryRefused:
    if self._idleSeconds is not None and seconds >= self._idleSeconds:
      return DirectoryRefused(f"the directory was silent for {self._idleSeconds} seconds")
    return DirectoryRefused(f"the directory did not finish within {maximumOperationSeconds} seconds")

  def _message(self, operation: bytes, controls: bytes = b"") -> bytes:
    message = sequence(integer(self._nextID), operation, controls)
    self._nextID += 1
    return message

  def _send(self, data: bytes) -> None:
    seconds = self._timeout()
    self._socket.settimeout(seconds)
    try:
      self._socket.sendall(data)
    except TimeoutError:
      raise self._timedOut(seconds) from None
    except OSError as error:
      raise DirectoryRefused(f"the connection to the directory failed: {error}") from None

  def _exactly(self, count: int) -> bytes:
    if count > self._bytesLeft:
      raise DirectoryRefused(f"the directory sent more than {maximumOperationBytes} bytes for one operation")
    self._bytesLeft -= count
    buffer = bytearray(count)
    view = memoryview(buffer)
    received = 0
    while received < count:
      seconds = self._timeout()
      self._socket.settimeout(seconds)
      try:
        size = self._socket.recv_into(view[received:])
      except TimeoutError:
        raise self._timedOut(seconds) from None
      except OSError as error:
        raise DirectoryRefused(f"the connection to the directory failed: {error}") from None
      if size == 0:
        raise DirectoryRefused("the directory closed the connection")
      received += size
    return bytes(buffer)

  def _receive(self) -> tuple[int, tuple[int, bytes]]:
    """One LDAPMessage: its message ID and the protocol operation's (tag, content) inside."""
    head = self._exactly(2)
    if head[0] != 0x30:
      raise DirectoryRefused("the directory sent something that is not an LDAP message")
    if head[1] < 0x80:
      length = head[1]
    else:
      count = head[1] & 0x7F
      if count == 0 or count > 4:
        raise DirectoryRefused("an LDAP length that is indefinite or out of range")
      length = int.from_bytes(self._exactly(count), "big")
    if length > maximumMessageBytes:
      raise DirectoryRefused(f"the directory sent a message of more than {maximumMessageBytes} bytes")
    parts = readAll(self._exactly(length))
    if len(parts) not in (2, 3) or parts[0][0] != 0x02 or (len(parts) == 3 and parts[2][0] != 0xA0):
      raise DirectoryRefused("an LDAP message that is not an ID, an operation and optional controls")
    return readInteger(parts[0][1]), parts[1]

  def _request(self, operation: bytes) -> tuple[int, bytes]:
    self._begin()
    messageID = self._nextID
    self._send(self._message(operation))
    answerID, answer = self._receive()
    if answerID != messageID:
      raise DirectoryRefused(f"the directory answered message {answerID}, not {messageID}")
    return answer

  def bind(self, name: str, password: str) -> None:
    if not name:
      raise DirectoryRefused("an empty name is refused: LDAP would take it for an anonymous bind")
    if not password:
      raise DirectoryRefused("an empty password is refused: LDAP would take it for an anonymous bind")
    tag, result = self._request(sequence(integer(3), octets(name), octets(password, 0x80), tag=0x60))
    if tag != 0x61:
      raise DirectoryRefused("the directory did not answer the bind")
    checkResult(result, "bind", frozenset({0x87}))

  def search(self, base: str, query: Filter, attributes: tuple[str, ...], oneLevel: bool = False) -> list[Entry]:
    """Subtree search; refused past maximumEntries entries, at a search reference, or past the budgets."""
    self._begin()
    messageID = self._nextID
    self._send(self._message(sequence(
      octets(base), integer(1 if oneLevel else 2, 0x0A), integer(0, 0x0A), integer(maximumEntries), integer(int(maximumOperationSeconds)),
      boolean(False), query.encoded(), sequence(*(octets(attribute) for attribute in attributes)), tag=0x63),
      sequence(sequence(octets(domainScopeControl)), tag=0xA0)))
    entries: list[Entry] = []
    while True:
      answerID, (tag, content) = self._receive()
      if answerID != messageID:
        raise DirectoryRefused(f"the directory answered message {answerID}, not {messageID}")
      if tag == 0x64:
        if len(entries) == maximumEntries:
          raise DirectoryRefused(f"the directory answered a search with more than {maximumEntries} entries")
        entries.append(readEntry(content))
      elif tag == 0x73:
        raise DirectoryRefused("the directory answered a search with a reference to another server, "
                               "which sign-in does not follow")
      elif tag == 0x65:
        checkResult(content, "search")
        return entries
      else:
        raise DirectoryRefused(f"the directory answered a search with operation 0x{tag:02x}")


@dataclass(frozen=True)
class DirectoryIdentity:
  """The person signed in; `groups` are sAMAccountNames, unique in the domain, of every group, nested included."""

  dn: str
  userName: str
  displayName: str | None
  email: str | None
  groups: tuple[str, ...]


def _single(entry: Entry, name: str) -> str | None:
  values = entry.values(name)
  if values is None:
    return None
  if len(values) != 1:
    raise DirectoryRefused(f"the directory sent {len(values)} values of {name}, not one")
  return values[0]


def _required(entry: Entry, name: str, owner: str) -> str:
  value = _single(entry, name)
  if value is None:
    raise DirectoryRefused(f"the directory did not send {name} for {owner}")
  return value


class DirectoryKind(Enum):
  """How a directory keeps people and groups."""

  activeDirectory = "activeDirectory"  # user objects, userAccountControl, in-chain groups named by sAMAccountName
  openLDAP = "openLDAP"                # inetOrgPerson, groupOfNames in one container named by cn RDNs, password policy


maximumGroupNesting = 16
maximumGroupSearches = 200
maximumGroups = 500
maximumGroupWalkSeconds = 30.0
_dnSpecials = frozenset(' "#+,;<=>\\')
_hexDigits = frozenset("0123456789abcdefABCDEF")


def _firstRDN(dn: str) -> tuple[str, str]:
  """A DN's first RDN (RFC 4514) as its attribute type and unescaped value; a multi-valued or BER-encoded one is refused."""
  attributeType, equals, rest = dn.partition("=")
  if not equals or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", attributeType):
    raise DirectoryRefused(f"the group DN {dn!r} does not begin with an attribute type and =")
  if rest.startswith("#"):
    raise DirectoryRefused(f"the group DN {dn!r} names its first RDN by a BER value")
  value = bytearray()
  index = 0
  while index < len(rest):
    character = rest[index]
    if character == "\\":
      pair = rest[index + 1:index + 3]
      if len(pair) == 2 and set(pair) <= _hexDigits:
        value.append(int(pair, 16))
        index += 3
        continue
      if pair[:1] and pair[0] in _dnSpecials:
        value.extend(pair[0].encode("utf-8"))
        index += 2
        continue
      raise DirectoryRefused(f"the group DN {dn!r} holds an escape RFC 4514 does not define")
    if character == "+":
      raise DirectoryRefused(f"the group DN {dn!r} has a first RDN of more than one attribute")
    if character == ",":
      break
    value.extend(character.encode("utf-8"))
    index += 1
  try:
    return attributeType.lower(), value.decode("utf-8")
  except UnicodeDecodeError:
    raise DirectoryRefused(f"the group DN {dn!r} escapes bytes that are not UTF-8") from None


def _groupName(group: Entry) -> str:
  """A group's cn, which is unique in its container only because it is the RDN its DN begins with."""
  name = _required(group, "cn", "a group")
  attributeType, value = _firstRDN(group.dn)
  if attributeType != "cn" or value.casefold() != name.casefold():
    raise DirectoryRefused(f"the group {group.dn!r} is not named by cn={name} as its first RDN, "
                           "so its cn need not be unique in the container")
  return name


def _entryUUID(group: Entry) -> str:
  text = _required(group, "entryUUID", "a group")
  try:
    return str(uuid.UUID(text))
  except ValueError:
    raise DirectoryRefused(f"the directory sent an entryUUID that is not a UUID for {group.dn!r}") from None


class Directory:
  """Sign-in against Active Directory (the default) or OpenLDAP."""

  def __init__(self, host: str, context: ssl.SSLContext, baseDN: str, serviceName: str, servicePassword: str,
               port: int = 636, startTLS: bool = False, userAttribute: str | None = None, timeoutSeconds: float = 10.0,
               kind: DirectoryKind = DirectoryKind.activeDirectory, groupsBaseDN: str | None = None):
    _requireVerification(context)
    if (kind is DirectoryKind.openLDAP) != (groupsBaseDN is not None):
      raise ValueError("an OpenLDAP directory needs groupsBaseDN, the one container its groups are in; "
                       "Active Directory takes none")
    self.host, self.port, self.context, self.startTLS = host, port, context, startTLS
    self.kind, self.baseDN, self.groupsBaseDN, self.timeoutSeconds = kind, baseDN, groupsBaseDN, timeoutSeconds
    self.userAttribute = userAttribute or ("sAMAccountName" if kind is DirectoryKind.activeDirectory else "uid")
    self._serviceName, self._servicePassword = serviceName, servicePassword

  def _connect(self) -> Connection:
    return Connection.open(self.host, self.port, self.context, self.startTLS, self.timeoutSeconds)

  def signIn(self, userName: str, password: str) -> DirectoryIdentity:
    if not password:
      raise DirectoryRefused("an empty password is refused: LDAP would take it for an anonymous bind")
    if self.groupsBaseDN is not None:
      return self._openLDAPSignIn(userName, password, self.groupsBaseDN)
    with self._connect() as service:
      service.bind(self._serviceName, self._servicePassword)
      found = service.search(
        self.baseDN,
        All((Equal("objectCategory", "person"), Equal("objectClass", "user"), Equal(self.userAttribute, userName))),
        ("displayName", "mail", "userAccountControl", self.userAttribute))
      if len(found) != 1:
        raise DirectoryRefused("the user name or the password is wrong")
      entry = found[0]
      if not entry.dn:
        raise DirectoryRefused("the directory found the user under an empty DN")
      control = _required(entry, "userAccountControl", "the user")
      if not re.fullmatch(r"-?[0-9]{1,10}", control):
        raise DirectoryRefused("the directory sent a userAccountControl that is not a number")
      if int(control) & 0x2:
        raise DirectoryRefused("the user name or the password is wrong")
      with self._connect() as person:
        try:
          person.bind(entry.dn, password)
        except DirectoryRefused:
          raise DirectoryRefused("the user name or the password is wrong") from None
      groups = service.search(self.baseDN, All((Equal("objectClass", "group"), InChain("member", entry.dn))),
                              ("sAMAccountName",))
    return DirectoryIdentity(
      dn=entry.dn, userName=_required(entry, self.userAttribute, "the user"),
      displayName=_single(entry, "displayName"), email=_single(entry, "mail"),
      groups=tuple(sorted(_required(group, "sAMAccountName", "a group") for group in groups)),
    )

  def _openLDAPSignIn(self, userName: str, password: str, groupsBaseDN: str) -> DirectoryIdentity:
    with self._connect() as service:
      service.bind(self._serviceName, self._servicePassword)
      found = service.search(self.baseDN, All((Equal("objectClass", "inetOrgPerson"), Equal(self.userAttribute, userName))),
                             ("displayName", "mail", self.userAttribute))
      if len(found) != 1:
        raise DirectoryRefused("the user name or the password is wrong")
      entry = found[0]
      if not entry.dn:
        raise DirectoryRefused("the directory found the user under an empty DN")
      # A disabled account is the password policy's to refuse: it locks the account, and the bind fails.
      with self._connect() as person:
        try:
          person.bind(entry.dn, password)
        except DirectoryRefused:
          raise DirectoryRefused("the user name or the password is wrong") from None
      names = self._openLDAPGroups(service, entry.dn, groupsBaseDN)
    return DirectoryIdentity(dn=entry.dn, userName=_required(entry, self.userAttribute, "the user"),
                             displayName=_single(entry, "displayName"), email=_single(entry, "mail"),
                             groups=tuple(sorted(names)))

  @staticmethod
  def _openLDAPGroups(service: Connection, personDN: str, groupsBaseDN: str) -> set[str]:
    """The cn of every group holding the person, nested included, walked within the module's bounds."""
    deadline = time.monotonic() + maximumGroupWalkSeconds
    names: set[str] = set()
    seen: set[str] = set()
    searches = 0
    frontier = [personDN]
    for _ in range(maximumGroupNesting):
      reached = []
      for member in frontier:
        if searches == maximumGroupSearches:
          raise DirectoryRefused(f"the group walk needs more than {maximumGroupSearches} searches")
        if time.monotonic() >= deadline:
          raise DirectoryRefused(f"the group walk did not finish within {maximumGroupWalkSeconds} seconds")
        searches += 1
        for group in service.search(groupsBaseDN, All((Equal("objectClass", "groupOfNames"), Equal("member", member))),
                                    ("cn", "entryUUID"), oneLevel=True):
          identifier = _entryUUID(group)
          if identifier in seen:
            continue
          if len(seen) == maximumGroups:
            raise DirectoryRefused(f"the person is in more than {maximumGroups} groups")
          seen.add(identifier)
          names.add(_groupName(group))
          reached.append(group.dn)
      if not reached:
        return names
      frontier = reached
    raise DirectoryRefused(f"the groups nest deeper than {maximumGroupNesting}")
