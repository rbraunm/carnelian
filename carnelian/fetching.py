# SPDX-License-Identifier: MIT
"""JSON over HTTPS for the protocols: certificate-checked, size- and time-limited.

Only https URLs are fetched, through Python's ssl with certificate and hostname checking,
which are verified on the context before every request; a test or a private deployment
names its own certificate authority instead of switching checks off. Each request has one
deadline for everything it waits on (connecting, the TLS handshake, sending, every read),
so a peer that keeps sending slowly cannot hold it open. Redirects are not followed and
only a 200 answer is accepted.
"""

from __future__ import annotations

import http.client
import io
import json
import math
import re
import socket
import ssl
import time
import urllib.parse
from collections.abc import Buffer, Callable
from typing import Any, Protocol, TypeVar

__all__ = ["Fetcher", "DocumentFetcher", "JSONFetcher", "HTTPFailure", "secureContext", "parseJSON"]

JSON = dict[str, Any]

_Result = TypeVar("_Result")


class DocumentFetcher(Protocol):
  def getBytes(self, url: str, accept: str) -> bytes: ...


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


class _DeadlineTLS:
  """TLS through memory buffers over a plain socket, so every wait on the peer ends at one deadline."""

  def __init__(self, host: str, port: int, context: ssl.SSLContext, deadline: float) -> None:
    self._deadline = deadline
    self._socket = socket.create_connection((host, port), timeout=self._remaining())
    self._incoming, self._outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    self._tls = context.wrap_bio(self._incoming, self._outgoing, server_hostname=host)
    self._readers = 0
    self._closing = False
    self._drive(self._tls.do_handshake)

  def _remaining(self) -> float:
    remaining = self._deadline - time.monotonic()
    if remaining <= 0:
      raise TimeoutError
    return remaining

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

  def _exchange(self, method: str, url: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, bytes]:
    context = _checkedContext(self.context)
    deadline = time.monotonic() + self.timeoutSeconds
    try:
      parts = urllib.parse.urlsplit(url)
      if parts.scheme != "https" or not parts.hostname:
        raise HTTPFailure(f"only https is fetched, not {url}")
      connection = _DeadlineConnection(parts.hostname, parts.port, context, deadline)
      try:
        connection.request(method, urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, "")), body, headers)
        response = connection.getresponse()
        answer = response.read(self.maximumBytes + 1)
        if len(answer) <= self.maximumBytes and response.length:
          raise HTTPFailure(f"{url} answered with fewer bytes than its Content-Length")
      finally:
        connection.close()
    except HTTPFailure:
      raise
    except TimeoutError:
      raise HTTPFailure(f"{url} ran past the request's deadline of {self.timeoutSeconds} seconds") from None
    except (OSError, http.client.HTTPException, ValueError) as error:
      raise HTTPFailure(f"{url}: {type(error).__name__}: {error}") from None
    if len(answer) > self.maximumBytes:
      raise HTTPFailure(f"{url} answered with more than {self.maximumBytes} bytes")
    return response.status, answer

  def _json(self, url: str, status: int, body: bytes) -> JSON:
    try:
      document = parseJSON(body)
    except ValueError:
      raise HTTPFailure(f"{url} answered {status} with something that is not JSON") from None
    if status != 200:
      reason = document.get("error_description") or document.get("error") if isinstance(document, dict) else None
      raise HTTPFailure(f"{url} answered {status}: {reason or body[:200]!r}")
    if not isinstance(document, dict):
      raise HTTPFailure(f"{url} answered with JSON that is not an object")
    return document

  def getBytes(self, url: str, accept: str) -> bytes:
    """A document that is not JSON (SAML metadata), as bytes; any status but 200 is refused."""
    status, body = self._exchange("GET", url, None, {"Accept": accept})
    if status != 200:
      raise HTTPFailure(f"{url} answered {status}, not 200")
    return body

  def getJSON(self, url: str, headers: dict[str, str] | None = None) -> JSON:
    return self._json(url, *self._exchange("GET", url, None, {"Accept": "application/json", **(headers or {})}))

  def postForm(self, url: str, fields: dict[str, str], headers: dict[str, str] | None = None) -> JSON:
    body = urllib.parse.urlencode(fields).encode("ascii")
    return self._json(url, *self._exchange("POST", url, body, {
      "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", **(headers or {})}))
