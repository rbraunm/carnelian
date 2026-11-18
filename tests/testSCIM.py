# SPDX-License-Identifier: MIT
"""The SCIM service provider: RFC 7644's filter and PATCH examples, Microsoft Entra ID's documented
request sequence replayed, and the strict refusals."""

import copy
import itertools
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from carnelian.scim import (And, Compare, Not, Or, Present, SCIMService, ValuePath, enterpriseUserSchema,
                            entraGroupSchema, matches, parseFilter, patchOpSchema, resourceTypes)

vectors = Path(__file__).parent / "vectors"
baseURL = "https://example.test/scim/v2"
token = "the-provisioning-token"
coreUser = "urn:ietf:params:scim:schemas:core:2.0:User"
coreGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"


class MemoryStore:
  """The application's storage, held in memory for the tests."""

  def __init__(self):
    self.resources = {"User": {}, "Group": {}}

  def create(self, resourceType, resource):
    assert resource["id"] not in self.resources[resourceType]
    self.resources[resourceType][resource["id"]] = copy.deepcopy(resource)

  def get(self, resourceType, resourceID):
    found = self.resources[resourceType].get(resourceID)
    return copy.deepcopy(found) if found is not None else None

  def replace(self, resourceType, resource):
    assert resource["id"] in self.resources[resourceType]
    self.resources[resourceType][resource["id"]] = copy.deepcopy(resource)

  def delete(self, resourceType, resourceID):
    del self.resources[resourceType][resourceID]

  def search(self, resourceType, query):
    return [copy.deepcopy(resource) for resource in self.resources[resourceType].values()
            if query is None or matches(resourceTypes[resourceType], query, resource)]


@pytest.fixture
def service():
  ticks = itertools.count()
  start = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
  return SCIMService(MemoryStore(), baseURL, lambda presented: presented == token, pageSize=20, maximumResults=50,
                     clock=lambda: start + timedelta(seconds=next(ticks)))


def call(service, method, path, body=None, query="", headers=None):
  sent = {"Authorization": f"Bearer {token}"} if headers is None else headers
  data = b""
  if body is not None:
    sent = {**sent, "Content-Type": "application/scim+json"}
    data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
  answer = service.handle(method, path, query, sent, data)
  document = json.loads(answer.body) if answer.body else None
  if answer.body:
    assert answer.headers["Content-Type"] == "application/scim+json"
  return answer.status, document, answer.headers


def filterQuery(text, extra=""):
  return "filter=" + quote(text) + extra


def refused(status, document, scimType=None):
  assert document["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
  assert document["status"] == str(status)
  assert document.get("scimType") == scimType
  return document["detail"]


def rfcUser():
  document = json.loads((vectors / "rfc7643EnterpriseUser.json").read_text(encoding="utf-8"))
  del document["password"]
  return document


def created(service, path, body):
  status, document, _ = call(service, "POST", path, body)
  assert status == 201, document
  return document


# ---- filters ----------------------------------------------------------------

def testFiltersParseIntoTheirStructure():
  assert parseFilter('userName eq "bjensen"') == Compare("userName", "eq", "bjensen")
  assert parseFilter("title pr") == Present("title")
  assert parseFilter('title pr and userType eq "Employee" or not (active eq false)') == Or(
    And(Present("title"), Compare("userType", "eq", "Employee")), Not(Compare("active", "eq", False)))
  assert parseFilter('emails[type eq "work" and value co "@example.com"]') == ValuePath(
    "emails", And(Compare("type", "eq", "work"), Compare("value", "co", "@example.com")))
  assert parseFilter('emails[type eq "work"].value eq "a@b.c"') == ValuePath(
    "emails", And(Compare("type", "eq", "work"), Compare("value", "eq", "a@b.c")))
  assert parseFilter('count GE 2.5e1') == Compare("count", "ge", 25.0)
  assert parseFilter(r'displayName eq "say \"hi\""') == Compare("displayName", "eq", 'say "hi"')


@pytest.mark.parametrize("text, expected", [
  ('userName eq "bjensen@example.com"', True),
  ('userName eq "BJensen@Example.com"', True),
  ('externalId eq "701984"', True),
  ('name.familyName co "O\'Malley"', False),
  ('name.familyName sw "jen"', True),
  ('urn:ietf:params:scim:schemas:core:2.0:User:userName sw "B"', True),
  ('title pr', True),
  ('meta.lastModified gt "2011-05-13T04:42:34Z"', True),
  ('meta.lastModified lt "2011-05-13T04:42:34Z"', False),
  ('title pr and userType eq "Employee"', True),
  ('title pr or userType eq "Intern"', True),
  (f'schemas eq "{enterpriseUserSchema}"', True),
  ('userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")', True),
  ('userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")', False),
  ('userType eq "Employee" and (emails.type eq "work")', True),
  ('userType eq "Employee" and emails[type eq "work" and value co "@example.com"]', True),
  ('emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]', True),
  ('emails[type eq "home" and value co "@example.com"]', False),
  ('emails[type eq "work"].value eq "bjensen@example.com"', True),
  (f'{enterpriseUserSchema}:manager.value eq "26118915-6090-4610-87e4-49d8ca9f808d"', True),
  (f'{enterpriseUserSchema}:department sw "Tour"', True),
  ('active eq true', True),
  ('nickName eq null', False),
  ('honorificPrefix eq null', None),
])
def testRFC7644FiltersAgainstTheRFC7643User(service, text, expected):
  user = created(service, "/Users", rfcUser())
  if expected is None:
    status, document, _ = call(service, "GET", "/Users", query=filterQuery(text))
    refused(400, document, "invalidFilter")
    return
  status, document, _ = call(service, "GET", "/Users", query=filterQuery(text))
  assert status == 200
  assert [found["id"] for found in document["Resources"]] == ([user["id"]] if expected else [])


@pytest.mark.parametrize("text, why", [
  ('active eq "true"', "boolean"),
  ('userName xx "a"', "unknown operator"),
  ('emails[type eq "work"', "ends too early"),
  ('nosuch eq "a"', "no such attribute"),
  ('name eq "x"', "complex"),
  ('emails[type eq "work"] and members[value eq "x"]', "no such attribute"),
  ('emails[display[value eq "x"]]', "inside another"),
  ('userName eq bjensen', "needs a value"),
  ('meta.created gt "yesterday"', "not a dateTime"),
  ('groups.value eq "x"', "members of /Groups"),
  ('userName eq "a" and', "ends too early"),
])
def testBadFiltersAreRefusedWithTheReason(service, text, why):
  status, document, _ = call(service, "GET", "/Users", query=filterQuery(text))
  assert status == 400
  assert why in refused(400, document, "invalidFilter")


# ---- Microsoft Entra ID's documented requests, in order ----------------------

entraUser = {
  "schemas": [coreUser, enterpriseUserSchema],
  "externalId": "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef",
  "userName": "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee",
  "active": True,
  "emails": [{"primary": True, "type": "work", "value": "Test_User_11bb11bb-cc22-dd33-ee44-55ff55ff55ff@testuser.com"}],
  "meta": {"resourceType": "User"},
  "name": {"formatted": "givenName familyName", "familyName": "familyName", "givenName": "givenName"},
  "roles": [],
}


def testTheEntraUserSequence(service):
  user = created(service, "/Users", entraUser)
  assert user["userName"] == entraUser["userName"] and user["active"] is True
  assert user["meta"]["resourceType"] == "User" and user["meta"]["location"] == f"{baseURL}/Users/{user['id']}"
  assert user["schemas"] == [coreUser] and "roles" not in user

  status, document, _ = call(service, "POST", "/Users", entraUser)
  assert status == 409 and "Test_User_00aa00aa" in refused(409, document, "uniqueness")

  status, document, _ = call(service, "GET", f"/Users/{user['id']}")
  assert status == 200 and document == user

  status, document, _ = call(service, "GET", "/Users/5171a35d82074e068ce2")
  assert status == 404 and refused(404, document)

  status, document, _ = call(service, "GET", "/Users", query=filterQuery(f'userName eq "{entraUser["userName"]}"'))
  assert (status, document["totalResults"], document["startIndex"]) == (200, 1, 1)
  assert document["Resources"] == [user]

  status, document, _ = call(service, "GET", "/Users", query=filterQuery('userName eq "non-existent user"'))
  assert (status, document["totalResults"], document["Resources"]) == (200, 0, [])

  status, document, _ = call(service, "PATCH", f"/Users/{user['id']}", {
    "schemas": [patchOpSchema],
    "Operations": [
      {"op": "Replace", "path": 'emails[type eq "work"].value', "value": "updatedEmail@microsoft.com"},
      {"op": "Replace", "path": "name.familyName", "value": "updatedFamilyName"}]})
  assert status == 200
  assert document["emails"] == [{"value": "updatedEmail@microsoft.com", "type": "work", "primary": True}]
  assert document["name"]["familyName"] == "updatedFamilyName" and document["name"]["givenName"] == "givenName"

  status, document, _ = call(service, "PATCH", f"/Users/{user['id']}", {
    "schemas": [patchOpSchema],
    "Operations": [{"op": "Replace", "path": "userName", "value": "5b50642d-79fc-4410-9e90-4c077cdd1a59@testuser.com"}]})
  assert status == 200
  status, document, _ = call(service, "GET", "/Users",
                             query=filterQuery('userName eq "5b50642d-79fc-4410-9e90-4c077cdd1a59@testuser.com"'))
  assert [found["id"] for found in document["Resources"]] == [user["id"]]

  status, document, _ = call(service, "PATCH", f"/Users/{user['id']}", {
    "Operations": [{"op": "Replace", "path": "active", "value": False}], "schemas": [patchOpSchema]})
  assert status == 200 and document["active"] is False
  assert document["meta"]["lastModified"] > user["meta"]["lastModified"]

  status, document, _ = call(service, "DELETE", f"/Users/{user['id']}")
  assert (status, document) == (204, None)
  status, document, _ = call(service, "GET", f"/Users/{user['id']}")
  assert status == 404


def testTheEntraGroupSequence(service):
  member = created(service, "/Users", entraUser)
  group = created(service, "/Groups", {
    "schemas": [coreGroup, entraGroupSchema], "externalId": "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159",
    "displayName": "displayName", "meta": {"resourceType": "Group"}})
  assert group["schemas"] == [coreGroup] and group["displayName"] == "displayName" and "members" not in group

  status, document, _ = call(service, "POST", "/Groups", {"schemas": [coreGroup], "displayName": "displayName"})
  assert status == 409 and refused(409, document, "uniqueness")

  status, document, _ = call(service, "GET", f"/Groups/{group['id']}", query="excludedAttributes=members")
  assert status == 200 and document == group

  status, document, _ = call(service, "GET", "/Groups",
                             query="excludedAttributes=members&" + filterQuery('displayName eq "displayName"'))
  assert status == 200 and document["Resources"] == [group]

  renamed = "1879db59-3bdf-4490-ad68-ab880a269474updatedDisplayName"
  status, document, _ = call(service, "PATCH", f"/Groups/{group['id']}", {
    "schemas": [patchOpSchema], "Operations": [{"op": "Replace", "path": "displayName", "value": renamed}]})
  assert (status, document) == (204, None)

  status, document, _ = call(service, "PATCH", f"/Groups/{group['id']}", {
    "schemas": [patchOpSchema],
    "Operations": [{"op": "Add", "path": "members", "value": [{"$ref": None, "value": member["id"]}]}]})
  assert (status, document) == (204, None)
  status, document, _ = call(service, "GET", f"/Groups/{group['id']}")
  assert document["displayName"] == renamed
  assert document["members"] == [{"value": member["id"], "$ref": f"{baseURL}/Users/{member['id']}", "type": "User"}]
  status, document, _ = call(service, "GET", f"/Users/{member['id']}")
  assert document["groups"] == [{"value": group["id"], "$ref": f"{baseURL}/Groups/{group['id']}",
                                 "display": renamed, "type": "direct"}]
  status, document, _ = call(service, "GET", "/Groups",
                             query=filterQuery(f'id eq "{group["id"]}" and members[value eq "{member["id"]}"]',
                                               "&attributes=displayName"))
  assert document["Resources"] == [{"schemas": [coreGroup], "id": group["id"], "displayName": renamed}]

  status, document, _ = call(service, "PATCH", f"/Groups/{group['id']}", {
    "schemas": [patchOpSchema],
    "Operations": [{"op": "Remove", "path": "members", "value": [{"$ref": None, "value": member["id"]}]}]})
  assert (status, document) == (204, None)
  status, document, _ = call(service, "GET", f"/Groups/{group['id']}")
  assert "members" not in document

  status, _, _ = call(service, "DELETE", f"/Groups/{group['id']}")
  assert status == 204
  status, _, _ = call(service, "GET", f"/Groups/{group['id']}")
  assert status == 404


# ---- RFC 7644 section 3.5.2's PATCH examples ---------------------------------

def patch(service, path, *operations):
  return call(service, "PATCH", path, {"schemas": [patchOpSchema], "Operations": list(operations)})


def testPatchAddWithoutAPathTakesAttributesInAnyCase(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "bjensen",
                                     "emails": [{"value": "bjensen@example.com", "type": "work", "primary": True}]})
  status, document, _ = patch(service, f"/Users/{user['id']}", {"op": "add", "value": {
    "emails": [{"value": "babs@jensen.org", "type": "home", "primary": True}], "nickname": "Babs"}})
  assert status == 200
  assert document["nickName"] == "Babs"
  assert document["emails"] == [{"value": "bjensen@example.com", "type": "work"},
                                {"value": "babs@jensen.org", "type": "home", "primary": True}]


def testPatchMembersByFilterByListAndAll(service):
  users = [created(service, "/Users", {"schemas": [coreUser], "userName": name}) for name in ("babs", "mandy", "dee")]
  group = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "Tour Guides",
                                       "members": [{"value": user["id"], "display": user["userName"]} for user in users]})
  assert [member["type"] for member in group["members"]] == ["User", "User", "User"]
  status, _, _ = patch(service, f"/Groups/{group['id']}",
                       {"op": "remove", "path": f'members[value eq "{users[0]["id"]}"]'})
  assert status == 204
  assert [member["value"] for member in call(service, "GET", f"/Groups/{group['id']}")[1]["members"]] == [
    users[1]["id"], users[2]["id"]]
  status, _, _ = patch(service, f"/Groups/{group['id']}", {"op": "replace", "path": "members", "value": [
    {"value": users[0]["id"], "display": "babs"}]})
  assert status == 204
  assert call(service, "GET", f"/Groups/{group['id']}")[1]["members"] == [
    {"value": users[0]["id"], "$ref": f"{baseURL}/Users/{users[0]['id']}", "display": "babs", "type": "User"}]
  status, _, _ = patch(service, f"/Groups/{group['id']}", {"op": "remove", "path": "members"})
  assert status == 204 and "members" not in call(service, "GET", f"/Groups/{group['id']}")[1]


def testPatchReplaceAFilteredValueAndOneOfItsSubAttributes(service):
  user = created(service, "/Users", rfcUser())
  status, document, _ = patch(service, f"/Users/{user['id']}", {
    "op": "replace", "path": 'addresses[type eq "work"]',
    "value": {"type": "work", "streetAddress": "911 Universal City Plaza", "locality": "Hollywood", "region": "CA",
              "postalCode": "91608", "country": "US", "formatted": "911 Universal City Plaza\nHollywood, CA 91608 US",
              "primary": True}})
  assert status == 200
  assert document["addresses"][0]["streetAddress"] == "911 Universal City Plaza"
  assert document["addresses"][1]["type"] == "home"
  status, document, _ = patch(service, f"/Users/{user['id']}", {
    "op": "replace", "path": 'addresses[type eq "work"].streetAddress', "value": "1010 Broadway Ave"})
  assert status == 200 and document["addresses"][0]["streetAddress"] == "1010 Broadway Ave"
  status, document, _ = patch(service, f"/Users/{user['id']}", {
    "op": "replace", "path": 'addresses[type eq "other"].streetAddress', "value": "nowhere"})
  assert status == 400 and refused(400, document, "noTarget")


def testPatchReplacesAnExtensionAttributeByItsFullName(service):
  user = created(service, "/Users", rfcUser())
  status, document, _ = patch(service, f"/Users/{user['id']}",
                              {"op": "replace", "path": f"{enterpriseUserSchema}:department", "value": "Rides"},
                              {"op": "remove", "path": f"{enterpriseUserSchema}:manager"})
  assert status == 200
  extension = document[enterpriseUserSchema]
  assert extension["department"] == "Rides" and "manager" not in extension and extension["costCenter"] == "4130"


def testPatchIsAllOrNothing(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "babs", "title": "Guide"})
  status, document, _ = patch(service, f"/Users/{user['id']}", {"op": "replace", "path": "title", "value": "Lead"},
                              {"op": "replace", "path": "active", "value": "False"})
  assert status == 400 and "active must be true or false" in refused(400, document, "invalidValue")
  assert call(service, "GET", f"/Users/{user['id']}")[1]["title"] == "Guide"


# ---- refusals ---------------------------------------------------------------

@pytest.mark.parametrize("body, scimType, why", [
  ({"schemas": [coreUser], "userName": "a", "active": "False"}, "invalidValue", "true or false"),
  ({"schemas": [coreUser], "userName": "a", "favouriteColour": "red"}, "invalidSyntax", "no such attribute"),
  ({"schemas": [coreUser], "userName": "a", "password": "hunter2"}, "invalidValue", "password is refused"),
  ({"schemas": [coreUser]}, "invalidValue", "userName is required"),
  ({"schemas": [coreUser], "userName": "a", "emails": [{"value": "a@x", "primary": True},
                                                       {"value": "b@x", "primary": True}]},
   "invalidValue", "more than one primary"),
  ({"schemas": [coreUser], "userName": "a", "emails": {"value": "a@x"}}, "invalidSyntax", "must be a list"),
  ({"schemas": [coreUser], "userName": "a", enterpriseUserSchema: {"department": "x"}}, "invalidSyntax",
   "not named in schemas"),
  ({"schemas": ["urn:example:unknown", coreUser], "userName": "a"}, "invalidSyntax", "not offered"),
  ({"userName": "a"}, "invalidSyntax", "schemas must be a list"),
  ({"schemas": [coreUser], "userName": "a", "UserName": "b"}, "invalidSyntax", "appears twice"),
  ({"schemas": [coreUser], "userName": "a", "x509Certificates": [{"value": "not base64!"}]}, "invalidValue", "base64"),
])
def testBadUsersAreRefusedWithTheReason(service, body, scimType, why):
  status, document, _ = call(service, "POST", "/Users", body)
  assert status == 400
  assert why in refused(400, document, scimType)


def testReadOnlyAttributesAreIgnoredOnPostButRefusedInPatch(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "a", "id": "chosen-by-the-client",
                                     "groups": [{"value": "g"}], "meta": {"created": "1999-01-01T00:00:00Z"}})
  assert user["id"] != "chosen-by-the-client" and "groups" not in user
  assert user["meta"]["created"].startswith("2026-")
  for path in ("id", "meta.created", "groups"):
    status, document, _ = patch(service, f"/Users/{user['id']}", {"op": "replace", "path": path, "value": "x"})
    assert status == 400 and refused(400, document, "mutability")


def testMembersMustExistAndMatchTheirType(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "a"})
  status, document, _ = call(service, "POST", "/Groups", {"schemas": [coreGroup], "displayName": "g",
                                                          "members": [{"value": "nobody"}]})
  assert "neither a user nor a group" in refused(400, document, "invalidValue")
  status, document, _ = call(service, "POST", "/Groups", {"schemas": [coreGroup], "displayName": "g",
                                                          "members": [{"value": user["id"], "type": "Group"}]})
  assert "is a User, not a Group" in refused(400, document, "invalidValue")
  inner = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "inner"})
  outer = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "outer", "members": [{"value": inner["id"]}]})
  assert outer["members"][0]["type"] == "Group" and outer["members"][0]["$ref"] == f"{baseURL}/Groups/{inner['id']}"
  status, document, _ = patch(service, f"/Groups/{inner['id']}", {"op": "add", "path": "members",
                                                                  "value": [{"value": inner["id"]}]})
  assert "its own member" in refused(400, document, "invalidValue")


def testDeletingAUserTakesItOutOfItsGroups(service):
  keep, leave = (created(service, "/Users", {"schemas": [coreUser], "userName": name}) for name in ("keep", "leave"))
  group = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "g",
                                       "members": [{"value": keep["id"]}, {"value": leave["id"]}]})
  assert call(service, "DELETE", f"/Users/{leave['id']}")[0] == 204
  assert [member["value"] for member in call(service, "GET", f"/Groups/{group['id']}")[1]["members"]] == [keep["id"]]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {token}"},
                                     {"Authorization": "Bearer "}])
def testRequestsWithoutTheTokenAreRefused(service, headers):
  status, document, sent = call(service, "GET", "/Users", headers=headers)
  assert status == 401 and refused(401, document)
  assert sent["WWW-Authenticate"].startswith("Bearer")


@pytest.mark.parametrize("method, path, query, status, scimType", [
  ("GET", "/Users", "sortBy=userName", 400, "invalidValue"),
  ("GET", "/Users", "count=51", 400, "tooMany"),
  ("GET", "/Users", "startIndex=0", 400, "invalidValue"),
  ("GET", "/Users", "count=-1", 400, "invalidValue"),
  ("GET", "/Users", "count=1&count=2", 400, "invalidValue"),
  ("GET", "/Users", "attributes=userName&excludedAttributes=title", 400, "invalidValue"),
  ("POST", "/Bulk", "", 501, None),
  ("GET", "/Me", "", 501, None),
  ("POST", "/Users/.search", "", 501, None),
  ("GET", "/Widgets", "", 404, None),
  ("DELETE", "/Users", "", 405, None),
])
def testUnofferedRequestsAreRefused(service, method, path, query, status, scimType):
  answered, document, _ = call(service, method, path, query=query)
  assert answered == status and refused(status, document, scimType)


def testBodiesMustBeStrictJSONOfTheSCIMType(service):
  status, document, _ = call(service, "POST", "/Users", b'{"schemas": [], "userName": "a", "userName": "b"}')
  assert "names userName twice" in refused(400, document, "invalidSyntax")
  status, document, _ = call(service, "POST", "/Users", b'{"schemas": ["%s"], "userName": NaN}' % coreUser.encode())
  assert "not JSON" in refused(400, document, "invalidSyntax")
  answer = service.handle("POST", "/Users", "", {"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
                          json.dumps({"schemas": [coreUser], "userName": "a"}).encode())
  assert answer.status == 415


def testTheServiceRefusesAnInsecureBaseURL():
  with pytest.raises(ValueError, match="https"):
    SCIMService(MemoryStore(), "http://example.test/scim", lambda presented: True)


# ---- the RFC 7643 user, paging, attribute selection, discovery ---------------

def testTheRFC7643EnterpriseUserIsKeptWhole(service):
  document = rfcUser()
  user = created(service, "/Users", document)
  assert user["schemas"] == [coreUser, enterpriseUserSchema]
  assert user["x509Certificates"] == document["x509Certificates"]
  assert user["addresses"] == document["addresses"]
  assert user[enterpriseUserSchema]["manager"] == {
    "value": "26118915-6090-4610-87e4-49d8ca9f808d", "$ref": f"{baseURL}/Users/26118915-6090-4610-87e4-49d8ca9f808d"}
  assert "groups" not in user and user["externalId"] == "701984"


def testPagesFollowCreationOrder(service):
  groups = [created(service, "/Groups", {"schemas": [coreGroup], "displayName": f"g{number}"}) for number in range(5)]
  status, document, _ = call(service, "GET", "/Groups", query="startIndex=3&count=2")
  assert (document["totalResults"], document["itemsPerPage"], document["startIndex"]) == (5, 2, 3)
  assert [found["displayName"] for found in document["Resources"]] == ["g2", "g3"]
  status, document, _ = call(service, "GET", "/Groups", query="count=0")
  assert (document["totalResults"], document["Resources"]) == (5, [])
  assert [group["displayName"] for group in groups] == [f"g{number}" for number in range(5)]


def testAttributesSelectWhatIsReturned(service):
  user = created(service, "/Users", rfcUser())
  status, document, _ = call(service, "GET", f"/Users/{user['id']}", query="attributes=userName,name.givenName")
  assert document == {"schemas": [coreUser, enterpriseUserSchema], "id": user["id"], "userName": "bjensen@example.com",
                      "name": {"givenName": "Barbara"}}
  status, document, _ = call(service, "GET", f"/Users/{user['id']}",
                             query=f"excludedAttributes=emails,name.formatted,{enterpriseUserSchema}:manager")
  assert "emails" not in document and "formatted" not in document["name"] and document["name"]["familyName"] == "Jensen"
  assert "manager" not in document[enterpriseUserSchema] and document[enterpriseUserSchema]["division"] == "Theme Park"


def testDiscoveryDescribesWhatIsOffered(service):
  status, document, _ = call(service, "GET", "/ServiceProviderConfig")
  assert document["patch"] == {"supported": True} and document["bulk"]["supported"] is False
  assert document["filter"] == {"supported": True, "maxResults": 50} and document["sort"] == {"supported": False}
  status, document, _ = call(service, "GET", "/ResourceTypes/User")
  assert (document["endpoint"], document["schema"]) == ("/Users", coreUser)
  assert document["schemaExtensions"] == [{"schema": enterpriseUserSchema, "required": False}]
  status, document, _ = call(service, "GET", "/Schemas")
  assert document["totalResults"] == 3
  userName = next(attribute for attribute in document["Resources"][0]["attributes"] if attribute["name"] == "userName")
  assert (userName["required"], userName["uniqueness"], userName["caseExact"]) == (True, "server", False)
  status, document, _ = call(service, "GET", f"/Schemas/{coreGroup}")
  assert [attribute["name"] for attribute in document["attributes"]] == ["displayName", "members"]
