# SPDX-License-Identifier: MIT
"""An LDAPv3 client for signing in against Active Directory and other directories (RFC 4511).

Only what sign-in needs: simple bind, search, StartTLS, unbind, always over TLS (LDAPS, or
StartTLS before anything else is said), with certificate and hostname checks. Filters are
built as values, never parsed from text, so a user name cannot inject filter syntax. A
bind with an empty password is refused before it is sent: LDAP treats it as an anonymous
bind that succeeds (RFC 4513 section 5.1.2), the classic way past a directory check.

Sign-in: the service account finds the one entry with the user name, the person's password
is checked by binding as that entry on a fresh connection, a disabled Active Directory
account is refused, and the groups are those the entry belongs to, nested ones included
(Active Directory's LDAP_MATCHING_RULE_IN_CHAIN).
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass


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
  return int.from_bytes(content, "big", signed=True)


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
  filters: tuple

  def encoded(self) -> bytes:
    return sequence(*(part.encoded() for part in self.filters), tag=0xA0)


# ---- the connection ---------------------------------------------------------

resultNames = {0: "success", 32: "noSuchObject", 34: "invalidDNSyntax", 48: "inappropriateAuthentication",
               49: "invalidCredentials", 50: "insufficientAccessRights", 53: "unwillingToPerform"}


@dataclass(frozen=True)
class Entry:
  dn: str
  attributes: dict[str, tuple[str, ...]]


class Connection:
  """One TLS-protected LDAP connection; use as a context manager so it is unbound and closed."""

  def __init__(self, host: str, port: int, context: ssl.SSLContext, startTLS: bool, timeoutSeconds: float = 10.0,
               maximumBytes: int = 4_000_000):
    self.maximumBytes = maximumBytes
    self._nextID = 1
    raw = socket.create_connection((host, port), timeout=timeoutSeconds)
    try:
      if startTLS:
        self._socket = raw
        tag, result = self._request(sequence(octets("1.3.6.1.4.1.1466.20037", 0x80), tag=0x77))
        if tag != 0x78:
          raise DirectoryRefused("the directory did not answer StartTLS")
        self._check(result, "StartTLS")
      self._socket = context.wrap_socket(raw, server_hostname=host)
    except BaseException:
      raw.close()
      raise

  def __enter__(self):
    return self

  def __exit__(self, *exception):
    try:
      self._send(self._message(tlv(0x42, b"")))
    except OSError:
      pass
    self._socket.close()

  def _message(self, operation: bytes) -> bytes:
    message = sequence(integer(self._nextID), operation)
    self._nextID += 1
    return message

  def _send(self, data: bytes) -> None:
    self._socket.sendall(data)

  def _receive(self) -> tuple[int, bytes]:
    """One LDAPMessage: its message ID and the protocol operation's (tag, content) inside."""
    head = self._exactly(2)
    if head[0] != 0x30:
      raise DirectoryRefused("the directory sent something that is not an LDAP message")
    if head[1] < 0x80:
      length, lengthBytes = head[1], b""
    else:
      count = head[1] & 0x7F
      if count == 0 or count > 4:
        raise DirectoryRefused("an LDAP length that is indefinite or out of range")
      lengthBytes = self._exactly(count)
      length = int.from_bytes(lengthBytes, "big")
    if length > self.maximumBytes:
      raise DirectoryRefused(f"the directory sent a message of more than {self.maximumBytes} bytes")
    parts = readAll(self._exactly(length))
    if len(parts) < 2 or parts[0][0] != 0x02:
      raise DirectoryRefused("an LDAP message without its ID and operation")
    return readInteger(parts[0][1]), parts[1]

  def _exactly(self, count: int) -> bytes:
    data = b""
    while len(data) < count:
      chunk = self._socket.recv(count - len(data))
      if not chunk:
        raise DirectoryRefused("the directory closed the connection")
      data += chunk
    return data

  def _request(self, operation: bytes) -> tuple[int, bytes]:
    messageID = self._nextID
    self._send(self._message(operation))
    answerID, answer = self._receive()
    if answerID != messageID:
      raise DirectoryRefused(f"the directory answered message {answerID}, not {messageID}")
    return answer

  @staticmethod
  def _check(result: bytes, what: str) -> None:
    parts = readAll(result)
    code = readInteger(parts[0][1])
    if code != 0:
      message = parts[2][1].decode("utf-8", "replace") if len(parts) > 2 else ""
      raise DirectoryRefused(f"{what}: {resultNames.get(code, code)} {message}".rstrip())

  def bind(self, name: str, password: str) -> None:
    if not password:
      raise DirectoryRefused("an empty password is refused: LDAP would take it for an anonymous bind")
    tag, result = self._request(sequence(integer(3), octets(name), octets(password, 0x80), tag=0x60))
    if tag != 0x61:
      raise DirectoryRefused("the directory did not answer the bind")
    self._check(result, "bind")

  def search(self, base: str, query, attributes: tuple[str, ...], sizeLimit: int = 1000) -> list[Entry]:
    messageID = self._nextID
    self._send(self._message(sequence(
      octets(base), integer(2, 0x0A), integer(0, 0x0A), integer(sizeLimit), integer(10), boolean(False),
      query.encoded(), sequence(*(octets(attribute) for attribute in attributes)), tag=0x63)))
    entries = []
    while True:
      answerID, (tag, content) = self._receive()
      if answerID != messageID:
        raise DirectoryRefused(f"the directory answered message {answerID}, not {messageID}")
      if tag == 0x64:
        parts = readAll(content)
        values = {}
        for _, pair in readAll(parts[1][1]):
          name, valueSet = readAll(pair)
          values[name[1].decode("utf-8")] = tuple(value.decode("utf-8") for _, value in readAll(valueSet[1]))
        entries.append(Entry(dn=parts[0][1].decode("utf-8"), attributes=values))
      elif tag == 0x73:
        continue
      elif tag == 0x65:
        self._check(content, "search")
        return entries
      else:
        raise DirectoryRefused(f"the directory answered a search with operation 0x{tag:02x}")


@dataclass(frozen=True)
class DirectoryIdentity:
  dn: str
  userName: str
  displayName: str | None
  email: str | None
  groups: tuple[str, ...]


class Directory:
  """Sign-in against a directory, Active Directory by default."""

  def __init__(self, host: str, context: ssl.SSLContext, baseDN: str, serviceName: str, servicePassword: str,
               port: int = 636, startTLS: bool = False, userAttribute: str = "sAMAccountName", timeoutSeconds: float = 10.0):
    self.host, self.port, self.context, self.startTLS = host, port, context, startTLS
    self.baseDN, self.userAttribute, self.timeoutSeconds = baseDN, userAttribute, timeoutSeconds
    self._serviceName, self._servicePassword = serviceName, servicePassword

  def _connect(self) -> Connection:
    try:
      return Connection(self.host, self.port, self.context, self.startTLS, self.timeoutSeconds)
    except (OSError, ssl.SSLError) as error:
      raise DirectoryRefused(f"cannot reach the directory at {self.host}:{self.port}: {error}") from None

  def signIn(self, userName: str, password: str) -> DirectoryIdentity:
    if not password:
      raise DirectoryRefused("an empty password is refused: LDAP would take it for an anonymous bind")
    with self._connect() as service:
      service.bind(self._serviceName, self._servicePassword)
      found = service.search(self.baseDN, All((Equal("objectClass", "user"), Equal(self.userAttribute, userName))),
                             ("displayName", "mail", "userAccountControl", self.userAttribute))
      if len(found) != 1:
        raise DirectoryRefused("the user name or the password is wrong")
      entry = found[0]
      control = int(entry.attributes.get("userAccountControl", ("0",))[0])
      if control & 0x2:
        raise DirectoryRefused("the user name or the password is wrong")
      with self._connect() as person:
        try:
          person.bind(entry.dn, password)
        except DirectoryRefused:
          raise DirectoryRefused("the user name or the password is wrong") from None
      groups = service.search(self.baseDN, All((Equal("objectClass", "group"), InChain("member", entry.dn))), ("cn",))
    return DirectoryIdentity(
      dn=entry.dn, userName=entry.attributes[self.userAttribute][0],
      displayName=entry.attributes.get("displayName", (None,))[0], email=entry.attributes.get("mail", (None,))[0],
      groups=tuple(sorted(group.attributes["cn"][0] for group in groups)),
    )
