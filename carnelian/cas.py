# SPDX-License-Identifier: MIT
"""A CAS client (Apereo CAS protocol 3.0): the sign-in many universities run, in France, Spain and Latin America above all.

Sign-in has two halves, as for OpenID Connect: `beginSignIn` gives the CAS login address
and a Pending record to keep server-side; `finishSignIn` takes it and the query the browser
came back with. CAS has no state parameter, so the service address carries one: the ticket
is only accepted for the sign-in this browser started, and validated against exactly the
service address it was issued for. The ticket is checked by the CAS server itself
(`/p3/serviceValidate`, over HTTPS), which answers the user and the attributes it releases.
Proxy tickets and proxy-granting are not used.
"""

from __future__ import annotations

import hmac
import re
import secrets
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from carnelian.fetching import DocumentFetcher
from carnelian.xmlTree import Element, XMLRefused, parse

__all__ = ["CASRefused", "CASServer", "Pending", "CASIdentity"]

casNamespace = "http://www.yale.edu/tp/cas"
_ticketPattern = re.compile(r"^ST-[A-Za-z0-9.\-_]{1,256}$")


class CASRefused(ValueError):
  """A CAS sign-in that did not complete, with why."""


@dataclass(frozen=True)
class Pending:
  state: str
  startedAt: float


@dataclass(frozen=True)
class CASIdentity:
  userName: str
  attributes: dict[str, tuple[str, ...]] = field(repr=False)


class CASServer:
  """One CAS server (its address ends in /cas or wherever /login lives) and this service's return address."""

  def __init__(self, serverURL: str, serviceURL: str, fetcher: DocumentFetcher, pendingSeconds: int = 600,
               clock: Callable[[], float] = time.time) -> None:
    if not serverURL.startswith("https://") or serverURL.endswith("/"):
      raise ValueError("serverURL must be an https address without a trailing slash")
    if "?" in serviceURL or "#" in serviceURL:
      raise ValueError("serviceURL carries no query or fragment of its own; the sign-in adds its state")
    self.serverURL, self.serviceURL, self.fetcher = serverURL, serviceURL, fetcher
    self.pendingSeconds, self.clock = pendingSeconds, clock

  def _service(self, state: str) -> str:
    return f"{self.serviceURL}?{urllib.parse.urlencode({'state': state})}"

  def beginSignIn(self) -> tuple[str, Pending]:
    pending = Pending(state=secrets.token_urlsafe(32), startedAt=self.clock())
    return f"{self.serverURL}/login?{urllib.parse.urlencode({'service': self._service(pending.state)})}", pending

  def finishSignIn(self, pending: Pending, query: dict[str, str]) -> CASIdentity:
    if self.clock() - pending.startedAt > self.pendingSeconds:
      raise CASRefused("the sign-in took too long; start again")
    if not hmac.compare_digest(str(query.get("state", "")), pending.state):
      raise CASRefused("the sign-in's state does not match")
    ticket = query.get("ticket", "")
    if not _ticketPattern.match(ticket):
      raise CASRefused("the CAS server sent no service ticket")
    address = f"{self.serverURL}/p3/serviceValidate?" + urllib.parse.urlencode(
      {"service": self._service(pending.state), "ticket": ticket})
    return self.read(self.fetcher.getBytes(address, "application/xml"))

  def read(self, answer: bytes) -> CASIdentity:
    """The CAS server's validation answer: the user and the released attributes, or why it refused."""
    try:
      return self._read(parse(answer))
    except XMLRefused as error:
      raise CASRefused(f"the CAS server's answer is refused: {error}") from None

  def _read(self, root: Element) -> CASIdentity:
    if not root.isA(casNamespace, "serviceResponse"):
      raise CASRefused("the CAS server's answer is not a serviceResponse")
    failure = root.optional(casNamespace, "authenticationFailure")
    if failure is not None:
      raise CASRefused(f"the CAS server refused the ticket: {failure.attribute('code')} {failure.text.strip()}".rstrip())
    success = root.only(casNamespace, "authenticationSuccess")
    if success.childrenNamed(casNamespace, "proxies"):
      raise CASRefused("the ticket came through a proxy, which is refused")
    userName = success.only(casNamespace, "user").text.strip()
    if not userName:
      raise CASRefused("the CAS server named no user")
    attributes: dict[str, tuple[str, ...]] = {}
    released = success.optional(casNamespace, "attributes")
    if released is not None:
      for attribute in released.elements():
        if attribute.namespaceURI != casNamespace:
          raise CASRefused(f"an attribute outside the CAS namespace: {attribute.localName}")
        attributes[attribute.localName] = attributes.get(attribute.localName, ()) + (attribute.text.strip(),)
    return CASIdentity(userName=userName, attributes=attributes)
