# SPDX-License-Identifier: MIT
"""JSON over HTTPS for the protocols: certificate-checked, size- and time-limited.

Only https URLs are fetched, through Python's ssl with hostname checking; a test or a
private deployment names its own certificate authority instead of switching checks off.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


class HTTPFailure(ValueError):
  """A request that could not be made, or a response that is refused."""


def secureContext(certificateAuthority: str | None = None) -> ssl.SSLContext:
  """Certificate and hostname checks on; the system's authorities, or only the one named."""
  context = ssl.create_default_context(cafile=certificateAuthority)
  context.minimum_version = ssl.TLSVersion.TLSv1_2
  return context


class _NoRedirects(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, *arguments):
    return None


class Fetcher:
  def __init__(self, context: ssl.SSLContext, timeoutSeconds: float = 10.0, maximumBytes: int = 1_000_000):
    self.context = context
    self.timeoutSeconds = timeoutSeconds
    self.maximumBytes = maximumBytes
    self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirects())

  def _send(self, request: urllib.request.Request) -> dict:
    if urllib.parse.urlsplit(request.full_url).scheme != "https":
      raise HTTPFailure(f"only https is fetched, not {request.full_url}")
    try:
      with self._opener.open(request, timeout=self.timeoutSeconds) as response:
        body = response.read(self.maximumBytes + 1)
        status = response.status
    except urllib.error.HTTPError as error:
      body, status = error.read(self.maximumBytes + 1), error.code
    except (urllib.error.URLError, OSError) as error:
      raise HTTPFailure(f"{request.full_url}: {error}") from None
    if len(body) > self.maximumBytes:
      raise HTTPFailure(f"{request.full_url} answered with more than {self.maximumBytes} bytes")
    try:
      document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
      raise HTTPFailure(f"{request.full_url} answered {status} with something that is not JSON") from None
    if status != 200:
      reason = document.get("error_description") or document.get("error") if isinstance(document, dict) else None
      raise HTTPFailure(f"{request.full_url} answered {status}: {reason or body[:200]!r}")
    if not isinstance(document, dict):
      raise HTTPFailure(f"{request.full_url} answered with JSON that is not an object")
    return document

  def getJSON(self, url: str, headers: dict[str, str] | None = None) -> dict:
    return self._send(urllib.request.Request(url, headers={"Accept": "application/json", **(headers or {})}))

  def postForm(self, url: str, fields: dict[str, str], headers: dict[str, str] | None = None) -> dict:
    body = urllib.parse.urlencode(fields).encode("ascii")
    return self._send(urllib.request.Request(url, data=body, method="POST", headers={
      "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", **(headers or {})}))
