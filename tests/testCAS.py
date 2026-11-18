# SPDX-License-Identifier: MIT
"""The CAS client: the protocol 3.0 validation answers, the state that binds a ticket to its sign-in,
then signing in through a real Apereo CAS server."""

import html.parser
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request

import pytest

from carnelian.cas import CASRefused, CASServer, Pending, readLogoutRequest
from carnelian.fetching import Fetcher, HTTPFailure, secureContext

from testOIDC import account

server = "https://cas.example.edu/cas"
service = "https://app.example.org/signin/cas/return"
now = 1_800_000_000


def answer(body):
  return f'<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">{body}</cas:serviceResponse>'.encode()


class Recorded:
  """The network, as far as the CAS client is concerned: what it asked for, and the answer."""

  def __init__(self, reply):
    self.reply, self.asked = reply, []

  def getBytes(self, address, accept):
    self.asked.append(address)
    return self.reply


def client(reply=b""):
  return CASServer(server, service, Recorded(reply), clock=lambda: now)


def testTheLoginAddressCarriesTheServiceWithItsState():
  address, pending = client().beginSignIn()
  query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(address).query))
  assert address.startswith(f"{server}/login?")
  assert query["service"] == f"{service}?state={pending.state}"


def testATicketIsValidatedForExactlyItsServiceAndReadWithItsAttributes():
  cas = client(answer('<cas:authenticationSuccess><cas:user>ana</cas:user><cas:attributes><cas:mail>ana@example.edu</cas:mail>'
                      '<cas:memberOf>/field</cas:memberOf><cas:memberOf>/analysts</cas:memberOf></cas:attributes>'
                      '</cas:authenticationSuccess>'))
  pending = Pending(state="s1", startedAt=now - 5)
  identity = cas.finishSignIn(pending, {"state": "s1", "ticket": "ST-1-abc"})
  assert (identity.userName, identity.ticket) == ("ana", "ST-1-abc")
  assert identity.attributes == {"mail": ("ana@example.edu",), "memberOf": ("/field", "/analysts")}
  query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(cas.fetcher.asked[0]).query))
  assert cas.fetcher.asked[0].startswith(f"{server}/p3/serviceValidate?")
  assert query == {"service": f"{service}?state=s1", "ticket": "ST-1-abc"}


@pytest.mark.parametrize("query, why", [
  ({"state": "other", "ticket": "ST-1-abc"}, "state does not match"),
  ({"state": "s1"}, "no service ticket"),
  ({"state": "s1", "ticket": "PT-1-abc"}, "no service ticket"),
  ({"state": "s1", "ticket": "ST-1-abc&renew=true"}, "no service ticket"),
])
def testATicketForAnotherSignInOrOfAnotherKindIsRefused(query, why):
  with pytest.raises(CASRefused, match=why):
    client().finishSignIn(Pending(state="s1", startedAt=now - 5), query)


@pytest.mark.parametrize("query, why", [
  ({"state": "é", "ticket": "ST-1-abc"}, "state does not match"),
  ({"state": "s1\udcff", "ticket": "ST-1-abc"}, "state does not match"),
  ({"state": "s1", "ticket": "ST-1-abc\n"}, "no service ticket"),
])
def testMalformedCallbacksAreRefusedByName(query, why):
  with pytest.raises(CASRefused, match=why):
    client().finishSignIn(Pending(state="s1", startedAt=now - 5), query)


class Unreachable:
  """A network that fails with a message, as the fetcher words it, naming the address it was asked for."""

  def __init__(self, words):
    self.words = words

  def getBytes(self, address, accept):
    raise HTTPFailure(self.words.format(address=address, quoted=urllib.parse.quote(address, safe="")))


@pytest.mark.parametrize("words, reason", [
  ("{address} answered 502, not 200", f"{server}/p3/serviceValidate answered 502, not 200"),
  ("{address}: ConnectionResetError: reset", f"{server}/p3/serviceValidate: ConnectionResetError: reset"),
  ("could not reach {quoted}", "could not reach https%3A%2F%2Fcas.example.edu%2Fcas%2Fp3%2FserviceValidate%3Fservice%3D"
                               "https%253A%252F%252Fapp.example.org%252Fsignin%252Fcas%252Freturn%253Fstate%253D(withheld)"
                               "%26ticket%3D(withheld)"),
])
def testAFailedValidationIsRefusedByNameWithoutTheTicketOrTheState(words, reason):
  cas = CASServer(server, service, Unreachable(words), clock=lambda: now)
  with pytest.raises(CASRefused) as refused:
    cas.finishSignIn(Pending(state="state-9Zq", startedAt=now - 5), {"state": "state-9Zq", "ticket": "ST-7-secretTicket"})
  assert str(refused.value) == f"the CAS server's validation could not be fetched: {reason}"


@pytest.mark.parametrize("serviceURL", ["http://app.example.org/signin/cas/return", "app.example.org/return"])
def testTheServiceAddressMustBeHTTPS(serviceURL):
  with pytest.raises(ValueError, match="serviceURL must be an https address"):
    CASServer(server, serviceURL, Recorded(b""))


def testAnOldSignInIsRefused():
  with pytest.raises(CASRefused, match="took too long"):
    client().finishSignIn(Pending(state="s1", startedAt=now - 601), {"state": "s1", "ticket": "ST-1-abc"})


@pytest.mark.parametrize("reply, why", [
  (answer('<cas:authenticationFailure code="INVALID_TICKET">Ticket ST-1 not recognized</cas:authenticationFailure>'),
   "INVALID_TICKET Ticket ST-1 not recognized"),
  (answer("<cas:authenticationSuccess><cas:user>ana</cas:user><cas:proxies><cas:proxy>https://p</cas:proxy></cas:proxies>"
          "</cas:authenticationSuccess>"), "through a proxy"),
  (answer("<cas:authenticationSuccess><cas:user> </cas:user></cas:authenticationSuccess>"), "named no user"),
  (answer('<cas:authenticationSuccess><cas:user>ana</cas:user><cas:attributes><x:role xmlns:x="urn:x">admin</x:role>'
          "</cas:attributes></cas:authenticationSuccess>"), "outside the CAS namespace"),
  (b'<!DOCTYPE a [<!ENTITY x "y">]><a/>', "refused"),
  (b"<serviceResponse/>", "not a serviceResponse"),
  (answer("<cas:authenticationSuccess><cas:user>ana</cas:user><cas:proxyGrantingTicket>PGTIOU-1</cas:proxyGrantingTicket>"
          "</cas:authenticationSuccess>"), "proxy-granting ticket"),
  (answer("<cas:authenticationSuccess><cas:user>ad<cas:x/>min</cas:user></cas:authenticationSuccess>"),
   "<user> must hold text only"),
  (answer("<cas:authenticationSuccess><cas:user>" + "<a>" * 5000 + "</a>" * 5000 + "</cas:user></cas:authenticationSuccess>"),
   "nested deeper than 64 elements"),
])
def testAnswersThatAreNotASuccessAreRefused(reply, why):
  with pytest.raises(CASRefused, match=why):
    client(reply).read(reply)


# ---- against the testbed's Apereo CAS -----------------------------------------

class _LoginForm(html.parser.HTMLParser):
  def __init__(self):
    super().__init__()
    self.action, self.fields = None, {}

  def handle_starttag(self, tag, attributes):
    attributes = dict(attributes)
    if tag == "form" and attributes.get("id") == "fm1":
      self.action = attributes.get("action")
    if tag == "input" and attributes.get("type") == "hidden" and attributes.get("name"):
      self.fields[attributes["name"]] = attributes.get("value", "")


class _Stop(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, request, fp, code, message, headers, newURL):
    raise urllib.error.HTTPError(newURL, code, message, headers, fp)


def signInAtCAS(address, userName, password, context):
  """What the person does in the browser: the query CAS sends back to the service, or None when it refuses."""
  opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                       urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _Stop())
  form = _LoginForm()
  with opener.open(address, timeout=30) as response:
    form.feed(response.read().decode("utf-8"))
  target = urllib.parse.urljoin(address, form.action) if form.action else address
  data = urllib.parse.urlencode({**form.fields, "username": userName, "password": password, "_eventId": "submit"}).encode()
  try:
    with opener.open(urllib.request.Request(target, data=data, method="POST"), timeout=30):
      return None
  except urllib.error.HTTPError as redirect:
    if redirect.code not in (301, 302, 303):
      return None
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect.url).query))


@pytest.fixture(scope="module")
def casServer(testbed):
  settings = testbed["cas"]
  return CASServer(settings["serverURL"], settings["serviceURL"], Fetcher(secureContext(testbed["certificateAuthority"])))


@pytest.mark.parametrize("userName", ["ana", "jose", "مريم"])
def testEveryoneSignsInThroughCAS(testbed, casServer, userName):
  expected = account(testbed, userName)
  address, pending = casServer.beginSignIn()
  query = signInAtCAS(address, userName, expected["password"], casServer.fetcher.context)
  assert query is not None and "ticket" in query
  identity = casServer.finishSignIn(pending, query)
  assert (identity.userName, identity.ticket) == (userName, query["ticket"])
  assert identity.attributes["mail"] == (expected["email"],)
  assert sorted(identity.attributes.get("memberOf", ())) == sorted(expected["groups"])
  with pytest.raises(CASRefused, match="INVALID_TICKET"):
    casServer.finishSignIn(pending, query)


@pytest.mark.parametrize("userName, password", [("ana", "not the password"), ("disabled", None)])
def testWrongAndDisabledSignInsGetNoTicket(testbed, casServer, userName, password):
  address, _ = casServer.beginSignIn()
  password = password or account(testbed, userName)["password"]
  assert signInAtCAS(address, userName, password, casServer.fetcher.context) is None


# ---- signing out ------------------------------------------------------------------

def testTheLogoutAddressCarriesTheReturn():
  cas = client()
  assert cas.logoutAddress() == f"{server}/logout"
  assert cas.logoutAddress("https://app.example.org/signed-out") == (
    f"{server}/logout?service=https%3A%2F%2Fapp.example.org%2Fsigned-out")
  with pytest.raises(ValueError, match="https"):
    cas.logoutAddress("http://app.example.org/signed-out")


notice = ('<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
          'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="LR-1" Version="2.0" IssueInstant="2026-11-18T07:00:00Z">'
          "<saml:NameID>@NOT_USED@</saml:NameID><samlp:SessionIndex>{ticket}</samlp:SessionIndex></samlp:LogoutRequest>")


def testASingleLogoutNoticeNamesItsTicket():
  assert readLogoutRequest(notice.format(ticket="ST-12-abcDEF")) == "ST-12-abcDEF"


@pytest.mark.parametrize("text, why", [
  (notice.format(ticket="PT-12-abc"), "names no service ticket"),
  (notice.format(ticket="ST-1<x/>"), "text only"),
  (notice.replace("<samlp:SessionIndex>{ticket}</samlp:SessionIndex>", ""), "SessionIndex"),
  ('<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x"/>', "not a SAML LogoutRequest"),
  ('<!DOCTYPE a [<!ENTITY x "y">]><a/>', "refused"),
  (notice.format(ticket="ST-12-abc\udcff"), "holds a lone surrogate"),
])
def testALogoutNoticeThatIsNotExactlyOneIsRefused(text, why):
  with pytest.raises(CASRefused, match=why):
    readLogoutRequest(text)


def testSigningOutAtCASReturnsToTheService(testbed, casServer):
  opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=casServer.fetcher.context), _Stop())
  with pytest.raises(urllib.error.HTTPError) as redirect:
    opener.open(casServer.logoutAddress(testbed["cas"]["serviceURL"]), timeout=30)
  assert redirect.value.code in (301, 302, 303) and redirect.value.url == testbed["cas"]["serviceURL"]
