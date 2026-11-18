# SPDX-License-Identifier: MIT
"""JSON over HTTPS for the protocols: certificate-checked, size- and time-limited.

Only https URLs are fetched, through Python's ssl with certificate and hostname checking,
which are verified on the context before every request; a test or a private deployment
names its own certificate authority instead of switching checks off. Each request has one
deadline for everything it waits on (resolving the name, connecting to each of its
addresses in turn, the TLS handshake, sending, every read), so a slow resolver, addresses
that do not answer or a peer that keeps sending slowly cannot hold it open. Redirects are
not followed and only a 200 answer is accepted. Errors name the URL with its query values
left out, since a query can carry a ticket or a code.

The standard library's resolver has no timeout, so a name is resolved in a thread of its
own that the request waits on until its deadline; a lookup still running then is left to
finish in the background, bounded by the system resolver's own timeout, and its answer
is dropped. A shared pool of resolver threads would let a few slow lookups stall every
request queued behind them, and its threads would hold up the interpreter's exit.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import math
import re
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Buffer, Callable, Iterator
from typing import Any, Protocol, TypeVar

__all__ = ["Fetcher", "DocumentFetcher", "DocumentStreamFetcher", "JSONFetcher", "HTTPFailure", "secureContext",
           "parseJSON", "shownURL"]

JSON = dict[str, Any]

_Result = TypeVar("_Result")


class DocumentFetcher(Protocol):
  def getBytes(self, url: str, accept: str) -> bytes: ...


class DocumentStreamFetcher(Protocol):
  def streamBytes(self, url: str, accept: str, maximumBytes: int) -> Iterator[bytes]: ...


class JSONFetcher(Protocol):
  def getJSON(self, url: str, headers: dict[str, str] | None = None) -> JSON: ...

  def postForm(self, url: str, fields: dict[str, str], headers: dict[str, str] | None = None) -> JSON: ...


class HTTPFailure(ValueError):
  """A request that could not be made, or a response that is refused."""


def secureContext(certificateAuthority: str | None = None) -> ssl.SSLContext:
  """Certificate and hostname checks on; the system's authorities, or only the one named."""
  context = ssl.create_default_context(cafile=certificateAuthority)
  context.minimum_version = ssl.TLSVersion.TLSv1_2
  return context


def _refuseConstant(name: str) -> object:
  raise ValueError(f"{name} is not a JSON number")


def _finiteNumber(text: str) -> float:
  value = float(text)
  if not math.isfinite(value):
    raise ValueError(f"{text} is too large for a number")
  return value


maximumJSONDepth = 32
_jsonStructurePattern = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|["\[\]{}]')


def checkNesting(text: str) -> None:
  """Refuses JSON nested deeper than maximumJSONDepth before it is parsed: whether the parser itself runs out of
  recursion, and where, differs by platform and Python version."""
  depth = 0
  for found in _jsonStructurePattern.finditer(text):
    mark = found.group()
    if mark in ("[", "{"):
      depth += 1
      if depth > maximumJSONDepth:
        raise ValueError(f"nests deeper than {maximumJSONDepth} arrays and objects")
    elif mark in ("]", "}"):
      depth -= 1
    elif mark == '"':
      # An unterminated string: the rest is string text, which the parser refuses; scanning on is quadratic.
      return


def parseJSON(data: bytes | str) -> Any:
  """Strict JSON: no NaN or Infinity, no number too large to be finite, no deep nesting; anything wrong is a ValueError."""
  try:
    text = data.decode("utf-8") if isinstance(data, bytes) else data
  except UnicodeDecodeError:
    raise ValueError("the JSON is not UTF-8") from None
  try:
    checkNesting(text)
  except ValueError as error:
    raise ValueError(f"the JSON {error}") from None
  return json.loads(text, parse_constant=_refuseConstant, parse_float=_finiteNumber)


def _checkedContext(context: ssl.SSLContext) -> ssl.SSLContext:
  if not context.check_hostname:
    raise HTTPFailure("the TLS context does not check hostnames; turn check_hostname on")
  if context.verify_mode != ssl.CERT_REQUIRED:
    raise HTTPFailure(f"the TLS context's verify_mode is {context.verify_mode!r}, not CERT_REQUIRED")
  return context


def shownURL(url: str) -> str:
  """A URL as errors name it: without user information, fragment or query values (a query can carry a ticket or a
  code), keeping the query's names."""
  try:
    parts = urllib.parse.urlsplit(url)
  except ValueError:
    return "a URL that cannot be read"
  query = "&".join(field.partition("=")[0] + "=..." for field in parts.query.split("&") if field)
  return urllib.parse.urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, query, ""))


def _remaining(deadline: float) -> float:
  remaining = deadline - time.monotonic()
  if remaining <= 0:
    raise TimeoutError
  return remaining


_AddressInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, Any]


def _resolved(host: str, port: int, deadline: float) -> list[_AddressInfo]:
  outcome: list[list[_AddressInfo] | Exception] = []
  finished = threading.Event()

  def resolve() -> None:
    try:
      addresses: list[_AddressInfo] = list(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
      outcome.append(addresses)
    except Exception as error:
      outcome.append(error)
    finally:
      finished.set()

  threading.Thread(target=resolve, name=f"resolve {host}", daemon=True).start()
  if not finished.wait(_remaining(deadline)):
    raise TimeoutError
  if isinstance(outcome[0], Exception):
    raise outcome[0]
  return outcome[0]


def _connected(host: str, port: int, deadline: float) -> socket.socket:
  failure: OSError | None = None
  for family, kind, protocol, _, address in _resolved(host, port, deadline):
    connection = socket.socket(family, kind, protocol)
    try:
      connection.settimeout(_remaining(deadline))
      connection.connect(address)
      return connection
    except OSError as error:
      connection.close()
      failure = error
  if failure is None:
    raise OSError(f"{host} has no address")
  raise failure


class _DeadlineTLS:
  """TLS through memory buffers over a plain socket, so every wait on the peer ends at one deadline."""

  def __init__(self, host: str, port: int, context: ssl.SSLContext, deadline: float) -> None:
    self._deadline = deadline
    self._socket = _connected(host, port, deadline)
    try:
      self._incoming, self._outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
      self._tls = context.wrap_bio(self._incoming, self._outgoing, server_hostname=host)
      self._readers = 0
      self._closing = False
      self._drive(self._tls.do_handshake)
    except BaseException:
      self._socket.close()
      raise

  def _remaining(self) -> float:
    return _remaining(self._deadline)

  def _flush(self) -> None:
    data = self._outgoing.read()
    if data:
      self._socket.settimeout(self._remaining())
      self._socket.sendall(data)

  def _drive(self, operation: Callable[[], _Result]) -> _Result:
    while True:
      try:
        result = operation()
      except ssl.SSLWantReadError:
        self._flush()
        self._socket.settimeout(self._remaining())
        data = self._socket.recv(65536)
        if data:
          self._incoming.write(data)
        else:
          self._incoming.write_eof()
        continue
      self._flush()
      return result

  def sendall(self, data: Buffer) -> None:
    self._drive(lambda: self._tls.write(data))

  def read(self, size: int) -> bytes:
    try:
      return self._drive(lambda: self._tls.read(size))
    except ssl.SSLZeroReturnError:
      return b""

  def makefile(self, mode: str) -> io.BufferedReader:
    self._readers += 1
    return io.BufferedReader(_DeadlineReader(self))

  # http.client closes the connection as soon as a response that ends the connection has its headers, and reads
  # the body through the file it made; like a socket's, that file keeps the connection open until it is closed.
  def close(self) -> None:
    self._closing = True
    if self._readers == 0:
      self._socket.close()

  def release(self) -> None:
    self._readers -= 1
    if self._closing and self._readers == 0:
      self._socket.close()


class _DeadlineReader(io.RawIOBase):
  def __init__(self, connection: _DeadlineTLS) -> None:
    super().__init__()
    self._connection = connection

  def readable(self) -> bool:
    return True

  def close(self) -> None:
    if not self.closed:
      self._connection.release()
    super().close()

  def readinto(self, buffer: Buffer) -> int:
    with memoryview(buffer) as view:
      data = self._connection.read(len(view))
      view[:len(data)] = data
      return len(data)


class _DeadlineConnection(http.client.HTTPConnection):
  default_port = 443

  def __init__(self, host: str, port: int | None, context: ssl.SSLContext, deadline: float) -> None:
    super().__init__(host, port)
    self._context = context
    self._deadline = deadline

  def connect(self) -> None:
    self.sock = _DeadlineTLS(self.host, self.port, self._context, self._deadline)


class Fetcher:
  def __init__(self, context: ssl.SSLContext, timeoutSeconds: float = 10.0, maximumBytes: int = 1_000_000) -> None:
    self.context = _checkedContext(context)
    self.timeoutSeconds = timeoutSeconds
    self.maximumBytes = maximumBytes

  @contextlib.contextmanager
  def _failures(self, url: str) -> Iterator[None]:
    try:
      yield
    except HTTPFailure:
      raise
    except TimeoutError:
      raise HTTPFailure(f"{shownURL(url)} ran past the request's deadline of {self.timeoutSeconds} seconds") from None
    except (OSError, http.client.HTTPException, ValueError) as error:
      raise HTTPFailure(f"{shownURL(url)}: {type(error).__name__}: {error}") from None

  def _opened(self, method: str, url: str, body: bytes | None,
              headers: dict[str, str]) -> tuple[_DeadlineConnection, http.client.HTTPResponse]:
    context = _checkedContext(self.context)
    deadline = time.monotonic() + self.timeoutSeconds
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
      raise HTTPFailure(f"only https is fetched, not {shownURL(url)}")
    connection = _DeadlineConnection(parts.hostname, parts.port, context, deadline)
    try:
      connection.request(method, urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, "")), body, headers)
      return connection, connection.getresponse()
    except BaseException:
      connection.close()
      raise

  def _exchange(self, method: str, url: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, bytes]:
    with self._failures(url):
      connection, response = self._opened(method, url, body, headers)
      try:
        answer = response.read(self.maximumBytes + 1)
        if len(answer) <= self.maximumBytes and response.length:
          raise HTTPFailure(f"{shownURL(url)} answered with fewer bytes than its Content-Length")
      finally:
        connection.close()
    if len(answer) > self.maximumBytes:
      raise HTTPFailure(f"{shownURL(url)} answered with more than {self.maximumBytes} bytes")
    return response.status, answer

  def _json(self, url: str, status: int, body: bytes) -> JSON:
    try:
      document = parseJSON(body)
    except ValueError:
      raise HTTPFailure(f"{shownURL(url)} answered {status} with something that is not JSON") from None
    if status != 200:
      reason = document.get("error_description") or document.get("error") if isinstance(document, dict) else None
      raise HTTPFailure(f"{shownURL(url)} answered {status}: {reason or body[:200]!r}")
    if not isinstance(document, dict):
      raise HTTPFailure(f"{shownURL(url)} answered with JSON that is not an object")
    return document

  def getBytes(self, url: str, accept: str) -> bytes:
    """A document that is not JSON (SAML metadata), as bytes; any status but 200 is refused."""
    status, body = self._exchange("GET", url, None, {"Accept": accept})
    if status != 200:
      raise HTTPFailure(f"{shownURL(url)} answered {status}, not 200")
    return body

  def streamBytes(self, url: str, accept: str, maximumBytes: int) -> Iterator[bytes]:
    """A document too large to hold, in chunks as it arrives: the whole stream within the one deadline, and
    HTTPFailure as soon as it passes maximumBytes, ends short of its Content-Length, or answers anything but 200."""
    with self._failures(url):
      connection, response = self._opened("GET", url, None, {"Accept": accept})
      try:
        if response.status != 200:
          raise HTTPFailure(f"{shownURL(url)} answered {response.status}, not 200")
        received = 0
        while chunk := response.read1(65536):
          received += len(chunk)
          if received > maximumBytes:
            raise HTTPFailure(f"{shownURL(url)} answered with more than {maximumBytes} bytes")
          yield chunk
        if response.length:
          raise HTTPFailure(f"{shownURL(url)} answered with fewer bytes than its Content-Length")
      finally:
        connection.close()

  def getJSON(self, url: str, headers: dict[str, str] | None = None) -> JSON:
    return self._json(url, *self._exchange("GET", url, None, {"Accept": "application/json", **(headers or {})}))

  def postForm(self, url: str, fields: dict[str, str], headers: dict[str, str] | None = None) -> JSON:
    body = urllib.parse.urlencode(fields).encode("ascii")
    return self._json(url, *self._exchange("POST", url, body, {
      "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", **(headers or {})}))
