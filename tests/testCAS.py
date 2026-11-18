# SPDX-License-Identifier: MIT
"""The CAS client: the protocol 3.0 validation answers, the state that binds a ticket to its sign-in,
then signing in through a real Apereo CAS server."""

import html.parser
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request

import pytest

from carnelian.cas import CASRefused, CASServer, Pending
from carnelian.fetching import Fetcher, secureContext

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
  assert identity.userName == "ana"
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
  assert identity.userName == userName
  assert identity.attributes["mail"] == (expected["email"],)
  assert sorted(identity.attributes.get("memberOf", ())) == sorted(expected["groups"])
  with pytest.raises(CASRefused, match="INVALID_TICKET"):
    casServer.finishSignIn(pending, query)


@pytest.mark.parametrize("userName, password", [("ana", "not the password"), ("disabled", None)])
def testWrongAndDisabledSignInsGetNoTicket(testbed, casServer, userName, password):
  address, _ = casServer.beginSignIn()
  password = password or account(testbed, userName)["password"]
  assert signInAtCAS(address, userName, password, casServer.fetcher.context) is None
