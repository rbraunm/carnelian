# SPDX-License-Identifier: MIT
"""A CAS client (Apereo CAS protocol 3.0): the sign-in many universities run, in France, Spain and Latin America above all.

Sign-in has two halves, as for OpenID Connect: `beginSignIn` gives the CAS login address
and a Pending record to keep server-side; `finishSignIn` takes it and the query the browser
came back with. CAS has no state parameter, so the service address carries one: the ticket
is only accepted for the sign-in this browser started, and validated against exactly the
service address it was issued for. Both the CAS server and the service address must be
https. The ticket is checked by the CAS server itself (`/p3/serviceValidate`, over HTTPS),
which answers the user (text only) and the attributes it releases. Only service tickets
are accepted: a proxy ticket, an answer listing proxies and an answer carrying a
proxy-granting ticket are refused by name. A failure to reach the CAS server is a CASRefused
too, its message without the ticket or the state.
"""

from __future__ import annotations

import hmac
import re
import secrets
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from carnelian.fetching import DocumentFetcher, HTTPFailure
from carnelian.xmlTree import Element, XMLRefused, parse

__all__ = ["CASRefused", "CASServer", "Pending", "CASIdentity", "readLogoutRequest"]

casNamespace = "http://www.yale.edu/tp/cas"
samlProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"
_ticketPattern = re.compile(r"ST-[A-Za-z0-9.\-_]{1,256}")


class CASRefused(ValueError):
  """A CAS sign-in that did not complete, with why."""


@dataclass(frozen=True)
class Pending:
  state: str
  startedAt: float


@dataclass(frozen=True)
class CASIdentity:
  """The CAS user, the attributes released, and the service ticket: keep the ticket with the session it starts, so a
  single-logout notice naming it (`readLogoutRequest`) ends that session."""
  userName: str
  attributes: dict[str, tuple[str, ...]] = field(repr=False)
  ticket: str = field(repr=False)


class CASServer:
  """One CAS server (its address ends in /cas or wherever /login lives) and this service's return address."""

  def __init__(self, serverURL: str, serviceURL: str, fetcher: DocumentFetcher, pendingSeconds: int = 600,
               clock: Callable[[], float] = time.time) -> None:
    if not serverURL.startswith("https://") or serverURL.endswith("/"):
      raise ValueError("serverURL must be an https address without a trailing slash")
    if not serviceURL.startswith("https://"):
      raise ValueError("serviceURL must be an https address")
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
    if not hmac.compare_digest(str(query.get("state", "")).encode("utf-8", "surrogatepass"), pending.state.encode("utf-8")):
      raise CASRefused("the sign-in's state does not match")
    ticket = query.get("ticket", "")
    if not _ticketPattern.fullmatch(ticket):
      raise CASRefused("the CAS server sent no service ticket")
    validation = f"{self.serverURL}/p3/serviceValidate"
    address = f"{validation}?" + urllib.parse.urlencode({"service": self._service(pending.state), "ticket": ticket})
    try:
      answer = self.fetcher.getBytes(address, "application/xml")
    except HTTPFailure as error:
      reason = str(error).replace(address, validation)
      for secret in (ticket, pending.state):
        reason = reason.replace(secret, "(withheld)")
      raise CASRefused(f"the CAS server's validation could not be fetched: {reason}") from None
    userName, attributes = self.read(answer)
    return CASIdentity(userName=userName, attributes=attributes, ticket=ticket)

  def logoutAddress(self, returnURL: str | None = None) -> str:
    """Where to send the person to sign out of CAS too; CAS sends them on to returnURL if its service registry allows."""
    if returnURL is None:
      return f"{self.serverURL}/logout"
    if not returnURL.startswith("https://"):
      raise ValueError(f"a return address is https, not {returnURL!r}")
    return f"{self.serverURL}/logout?{urllib.parse.urlencode({'service': returnURL})}"

  def read(self, answer: bytes) -> tuple[str, dict[str, tuple[str, ...]]]:
    """The CAS server's validation answer: the user and the released attributes, or why it refused."""
    try:
      return self._read(parse(answer))
    except XMLRefused as error:
      raise CASRefused(f"the CAS server's answer is refused: {error}") from None

  def _read(self, root: Element) -> tuple[str, dict[str, tuple[str, ...]]]:
    if not root.isA(casNamespace, "serviceResponse"):
      raise CASRefused("the CAS server's answer is not a serviceResponse")
    failure = root.optional(casNamespace, "authenticationFailure")
    if failure is not None:
      raise CASRefused(f"the CAS server refused the ticket: {failure.attribute('code')} {failure.text.strip()}".rstrip())
    success = root.only(casNamespace, "authenticationSuccess")
    if success.childrenNamed(casNamespace, "proxies"):
      raise CASRefused("the ticket came through a proxy, which is refused")
    if success.childrenNamed(casNamespace, "proxyGrantingTicket"):
      raise CASRefused("the answer carries a proxy-granting ticket, which is refused")
    userName = success.only(casNamespace, "user").simpleText.strip()
    if not userName:
      raise CASRefused("the CAS server named no user")
    attributes: dict[str, tuple[str, ...]] = {}
    released = success.optional(casNamespace, "attributes")
    if released is not None:
      for attribute in released.elements():
        if attribute.namespaceURI != casNamespace:
          raise CASRefused(f"an attribute outside the CAS namespace: {attribute.localName}")
        attributes[attribute.localName] = attributes.get(attribute.localName, ()) + (attribute.text.strip(),)
    return userName, attributes


def readLogoutRequest(logoutRequest: str) -> str:
  """The service ticket a CAS single-logout notice (the POSTed logoutRequest) names.

  CAS does not sign these notices: end only the session that this ticket started, so a forged
  notice can do no more than sign out a session whose ticket its sender already knows."""
  try:
    document = logoutRequest.encode("utf-8")
  except UnicodeEncodeError:
    raise CASRefused("the logout notice holds a lone surrogate, which is not text") from None
  try:
    root = parse(document)
    if not root.isA(samlProtocolNamespace, "LogoutRequest") or not root.attribute("ID"):
      raise CASRefused("the notice is not a SAML LogoutRequest with an ID")
    ticket = root.only(samlProtocolNamespace, "SessionIndex").simpleText.strip()
  except XMLRefused as error:
    raise CASRefused(f"the logout notice is refused: {error}") from None
  if not _ticketPattern.fullmatch(ticket):
    raise CASRefused("the logout notice names no service ticket")
  return ticket
