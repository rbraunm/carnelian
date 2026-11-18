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
  ("GET", "/Users", "sortOrder=descending", 400, "invalidValue"),
  ("GET", "/Users", "sortBy=name", 400, "invalidValue"),
  ("GET", "/Users", "count=51", 400, "tooMany"),
  ("GET", "/Users", "startIndex=0", 400, "invalidValue"),
  ("GET", "/Users", "count=-1", 400, "invalidValue"),
  ("GET", "/Users", "count=1&count=2", 400, "invalidValue"),
  ("GET", "/Users", "attributes=userName&excludedAttributes=title", 400, "invalidValue"),
  ("GET", "/Bulk", "", 405, None),
  ("POST", "/Bulk/x", "", 501, None),
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
  assert document["patch"] == {"supported": True} and document["etag"] == {"supported": True}
  assert document["filter"] == {"supported": True, "maxResults": 50} and document["sort"] == {"supported": True}
  assert document["bulk"] == {"supported": True, "maxOperations": 1000, "maxPayloadSize": 1_000_000}
  status, document, _ = call(service, "GET", "/ResourceTypes/User")
  assert (document["endpoint"], document["schema"]) == ("/Users", coreUser)
  assert document["schemaExtensions"] == [{"schema": enterpriseUserSchema, "required": False}]
  status, document, _ = call(service, "GET", "/Schemas")
  assert document["totalResults"] == 3
  userName = next(attribute for attribute in document["Resources"][0]["attributes"] if attribute["name"] == "userName")
  assert (userName["required"], userName["uniqueness"], userName["caseExact"]) == (True, "server", False)
  status, document, _ = call(service, "GET", f"/Schemas/{coreGroup}")
  assert [attribute["name"] for attribute in document["attributes"]] == ["displayName", "members"]


# ---- integrity and bounds ---------------------------------------------------

class RecordingStore(MemoryStore):
  """The memory store, noting every ID the service asks it for."""

  def __init__(self):
    super().__init__()
    self.asked = []

  def get(self, resourceType, resourceID):
    self.asked.append(resourceID)
    return super().get(resourceType, resourceID)


def groupOfOne(service):
  users = [created(service, "/Users", {"schemas": [coreUser], "userName": name}) for name in ("babs", "mandy")]
  group = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "g", "members": [{"value": users[0]["id"]}]})
  return users, group


@pytest.mark.parametrize("operation", [
  {"op": "replace", "path": 'members[value eq "{first}"].value', "value": "{second}"},
  {"op": "add", "path": 'members[value eq "{first}"].value', "value": "{second}"},
  {"op": "replace", "path": 'members[value eq "{first}"].type', "value": "Group"},
  {"op": "replace", "path": 'members[value eq "{first}"].type', "value": None},
  {"op": "remove", "path": 'members[value eq "{first}"].type'},
  {"op": "replace", "path": 'members[value eq "{first}"].$ref', "value": "https://example.test/elsewhere"},
  {"op": "replace", "path": 'members[value eq "{first}"]', "value": {"value": "{second}"}},
])
def testPatchCannotChangeAnImmutableSubAttributeOfAMember(service, operation):
  users, group = groupOfOne(service)
  operation = json.loads(json.dumps(operation).replace("{first}", users[0]["id"]).replace("{second}", users[1]["id"]))
  status, document, _ = patch(service, f"/Groups/{group['id']}", operation)
  assert status == 400 and "is immutable" in refused(400, document, "mutability")
  assert call(service, "GET", f"/Groups/{group['id']}")[1]["members"] == group["members"]


def testPatchMayRewriteAMemberKeepingItsValue(service):
  users, group = groupOfOne(service)
  status, _, _ = patch(service, f"/Groups/{group['id']}", {
    "op": "replace", "path": f'members[value eq "{users[0]["id"]}"]', "value": {"value": users[0]["id"], "display": "B"}})
  assert status == 204
  assert call(service, "GET", f"/Groups/{group['id']}")[1]["members"] == [
    {"value": users[0]["id"], "$ref": f"{baseURL}/Users/{users[0]['id']}", "display": "B", "type": "User"}]


@pytest.mark.parametrize("op", ["remove", "replace"])
def testPatchCannotRemoveAMembersRequiredValue(service, op):
  users, group = groupOfOne(service)
  operation = {"op": op, "path": f'members[value eq "{users[0]["id"]}"].value'}
  if op == "replace":
    operation["value"] = None
  status, document, _ = patch(service, f"/Groups/{group['id']}", operation)
  assert status == 400 and "members.value is required" in refused(400, document, "invalidValue")
  assert call(service, "GET", f"/Groups/{group['id']}")[1]["members"] == group["members"]


@pytest.mark.parametrize("operation", [
  {"op": "remove", "path": f"{enterpriseUserSchema}:manager.value"},
  {"op": "replace", "path": f"{enterpriseUserSchema}:manager.value", "value": None},
])
def testPatchCannotRemoveTheManagersRequiredValue(service, operation):
  user = created(service, "/Users", rfcUser())
  status, document, _ = patch(service, f"/Users/{user['id']}", operation)
  assert status == 400 and "manager.value is required" in refused(400, document, "invalidValue")
  assert call(service, "GET", f"/Users/{user['id']}")[1] == user


def testGroupsCannotContainThemselvesThroughOtherGroups(service):
  inner = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "inner"})
  middle = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "middle",
                                        "members": [{"value": inner["id"]}]})
  outer = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "outer",
                                       "members": [{"value": middle["id"]}]})
  for holder in (middle, outer):
    status, document, _ = patch(service, f"/Groups/{inner['id']}", {"op": "add", "path": "members",
                                                                    "value": [{"value": holder["id"]}]})
    assert status == 400 and "would contain itself" in refused(400, document, "invalidValue")
  status, document, _ = call(service, "PUT", f"/Groups/{inner['id']}", {
    "schemas": [coreGroup], "displayName": "inner", "members": [{"value": outer["id"]}]})
  assert status == 400 and "would contain itself" in refused(400, document, "invalidValue")
  assert "members" not in call(service, "GET", f"/Groups/{inner['id']}")[1]
  sibling = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "sibling",
                                         "members": [{"value": inner["id"]}, {"value": outer["id"]}]})
  assert [member["value"] for member in sibling["members"]] == [inner["id"], outer["id"]]


def testARefusedProjectionLeavesTheStoreUnchanged(service):
  status, document, _ = call(service, "POST", "/Users", {"schemas": [coreUser], "userName": "babs"},
                             query="attributes=nosuch")
  assert status == 400 and "no such attribute" in refused(400, document, "invalidValue")
  assert call(service, "GET", "/Users")[1]["totalResults"] == 0
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "babs", "title": "Guide"})
  status, document, _ = call(service, "PUT", f"/Users/{user['id']}", {"schemas": [coreUser], "userName": "babs",
                                                                      "title": "Lead"}, query="excludedAttributes=nosuch")
  assert status == 400 and "no such attribute" in refused(400, document, "invalidValue")
  status, document, _ = call(service, "PATCH", f"/Users/{user['id']}", {"schemas": [patchOpSchema], "Operations": [
    {"op": "replace", "path": "title", "value": "Lead"}]}, query="attributes=nosuch")
  assert status == 400 and "no such attribute" in refused(400, document, "invalidValue")
  assert call(service, "GET", f"/Users/{user['id']}")[1] == user


@pytest.mark.parametrize("body", [
  b'{"schemas": ["%s"], "userName": "\\ud800"}' % coreUser.encode(),
  b'{"schemas": ["%s"], "userName": "a", "\\udfff": 1}' % coreUser.encode(),
  b'{"schemas": ["%s"], "userName": "a", "emails": [{"value": "x\\ude00y"}]}' % coreUser.encode(),
])
def testLoneSurrogatesInTheBodyAreRefused(service, body):
  status, document, _ = call(service, "POST", "/Users", body)
  assert status == 400 and "lone surrogate" in refused(400, document, "invalidValue")
  assert call(service, "GET", "/Users")[1]["totalResults"] == 0


def testAPairedSurrogateEscapeIsOneCharacter(service):
  user = created(service, "/Users", b'{"schemas": ["%s"], "userName": "a\\ud83d\\ude00"}' % coreUser.encode())
  assert user["userName"] == "a\U0001f600"


def testLoneSurrogatesInThePathAndQueryAreRefused(service):
  status, document, _ = call(service, "GET", "/Users", query=filterQuery('userName eq "\\ud800"'))
  assert status == 400 and "lone surrogate" in refused(400, document, "invalidValue")
  status, document, _ = call(service, "GET", "/Users", query="attributes=user\udc80Name")
  assert status == 400 and "lone surrogate" in refused(400, document, "invalidValue")
  status, document, _ = call(service, "GET", "/Users/\udc80")
  assert status == 400 and "lone surrogate" in refused(400, document, "invalidValue")


def nested(depth):
  return b'{"schemas": ["%s"], "userName": "a", "x": %s}' % (coreUser.encode(), b"[" * depth + b"]" * depth)


def testDeeplyNestedBodiesAreRefusedBeforeParsing(service):
  status, document, _ = call(service, "POST", "/Users", b"[" * 100000 + b"]" * 100000)
  assert status == 400 and "nests deeper than 32" in refused(400, document, "invalidSyntax")
  status, document, _ = call(service, "POST", "/Users", nested(31))
  assert "no such attribute" in refused(400, document, "invalidSyntax")
  status, document, _ = call(service, "POST", "/Users", nested(32))
  assert "nests deeper than 32" in refused(400, document, "invalidSyntax")
  userName = "[" * 100 + '\\"{' * 100
  user = created(service, "/Users", {"schemas": [coreUser], "userName": userName})
  assert user["userName"] == userName


@pytest.mark.parametrize("number, why", [("1" * 5000, "longer than 64"), ("1e999", "beyond the range"),
                                         ("-1e999", "beyond the range")])
def testNumbersTooLongOrTooLargeAreRefused(service, number, why):
  body = b'{"schemas": ["%s"], "userName": "a", "active": %s}' % (coreUser.encode(), number.encode())
  status, document, _ = call(service, "POST", "/Users", body)
  assert status == 400 and why in refused(400, document, "invalidValue")


@pytest.mark.parametrize("text, why", [
  ("meta.created gt 1e999", "beyond the range"),
  ("title eq " + "1" * 65, "longer than 64"),
  (" or ".join(["title pr"] * 101), "more than 100 comparisons"),
])
def testFiltersAreBounded(service, text, why):
  status, document, _ = call(service, "GET", "/Users", query=filterQuery(text))
  assert status == 400 and why in refused(400, document, "invalidFilter")


def testAFilterOfOneHundredComparisonsIsRead(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "a", "title": "t"})
  status, document, _ = call(service, "GET", "/Users", query=filterQuery(" or ".join(["title pr"] * 100)))
  assert status == 200 and [found["id"] for found in document["Resources"]] == [user["id"]]


@pytest.mark.parametrize("query, why", [
  ("filter=" + "a" * 16384, "longer than 16384"),
  ("&".join(f"x{number}=1" for number in range(9)), "more than 8 parameters"),
])
def testQueryStringsAreBounded(service, query, why):
  status, document, _ = call(service, "GET", "/Users", query=query)
  assert status == 400 and why in refused(400, document, "invalidValue")


def testOnlyCanonicalUUIDsReachTheStore():
  store = RecordingStore()
  service = SCIMService(store, baseURL, lambda presented: presented == token)
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "a"})
  bodies = {"GET": None, "DELETE": None, "PUT": {"schemas": [coreUser], "userName": "a"},
            "PATCH": {"schemas": [patchOpSchema], "Operations": [{"op": "remove", "path": "title"}]}}
  for path in ("/Users/..%2F..%2Fetc%2Fpasswd", f"/Users/{user['id'].upper()}", f"/Users/{{{user['id']}}}",
               f"/Users/{user['id'].replace('-', '')}"):
    for method, body in bodies.items():
      store.asked.clear()
      status, document, _ = call(service, method, path, body)
      assert status == 404 and refused(404, document)
      assert store.asked == []
  status, document, _ = call(service, "POST", "/Groups", {"schemas": [coreGroup], "displayName": "g",
                                                          "members": [{"value": "../../etc/passwd"}]})
  assert "neither a user nor a group" in refused(400, document, "invalidValue")
  assert "../../etc/passwd" not in store.asked
  assert call(service, "GET", f"/Users/{user['id']}")[0] == 200


# ---- Okta's documented requests, in order ------------------------------------------

def oktaUser(userName, password="1mz050nq"):
  return {"schemas": [coreUser], "userName": userName, "name": {"givenName": "Test", "familyName": "User"},
          "emails": [{"primary": True, "value": userName, "type": "work"}], "displayName": "Test User",
          "locale": "en-US", "externalId": "00ujl29u0le5T6Aj10h7", "groups": [], "password": password, "active": True}


def testTheOktaSequence():
  okta = SCIMService(MemoryStore(), baseURL, lambda presented: presented == token, discardPasswords=True)
  status, document, _ = call(okta, "GET", "/Users", query="startIndex=1&count=2")
  assert (status, document["totalResults"]) == (200, 0)
  status, document, _ = call(okta, "GET", "/Users", query=filterQuery('userName eq "test.user@okta.local"', "&startIndex=1&count=100"))
  assert (status, document["totalResults"], document["Resources"]) == (200, 0, [])
  user = created(okta, "/Users", oktaUser("test.user@okta.local"))
  assert "password" not in user and user["userName"] == "test.user@okta.local" and user["active"] is True
  other = created(okta, "/Users", oktaUser("other.user@okta.local"))

  status, document, _ = call(okta, "GET", f"/Users/{user['id']}")
  assert status == 200 and document == user
  replaced = {**oktaUser("test.user@okta.local"), "id": user["id"], "name": {"givenName": "Another", "familyName": "User"},
              "meta": {"resourceType": "User"}}
  status, document, _ = call(okta, "PUT", f"/Users/{user['id']}", replaced)
  assert status == 200 and document["name"] == {"givenName": "Another", "familyName": "User"}
  status, document, _ = patch(okta, f"/Users/{user['id']}", {"op": "replace", "value": {"active": False}})
  assert status == 200 and document["active"] is False
  status, document, _ = patch(okta, f"/Users/{user['id']}", {"op": "replace", "value": {"password": "t1meMa$heen"}})
  assert status == 200 and document["active"] is False and "password" not in document

  group = created(okta, "/Groups", {"schemas": [coreGroup], "displayName": "Test SCIMv2", "members": []})
  status, document, _ = call(okta, "GET", "/Groups", query=filterQuery('displayName eq "Test SCIMv2"', "&startIndex=1&count=100"))
  assert [found["id"] for found in document["Resources"]] == [group["id"]]
  status, _, _ = patch(okta, f"/Groups/{group['id']}", {"op": "replace", "value": {"id": group["id"], "displayName": "Renamed"}})
  assert status == 204
  status, document, _ = patch(okta, f"/Groups/{group['id']}", {"op": "replace", "value": {"id": other["id"], "displayName": "X"}})
  assert status == 400 and refused(400, document, "mutability")

  status, _, _ = patch(okta, f"/Groups/{group['id']}",
                       {"op": "add", "path": "members", "value": [{"value": user["id"], "display": "test.user@okta.local"}]})
  assert status == 204
  status, _, _ = patch(okta, f"/Groups/{group['id']}",
                       {"op": "remove", "path": f'members[value eq "{user["id"]}"]'},
                       {"op": "add", "path": "members", "value": [{"value": other["id"], "display": "other.user@okta.local"}]})
  assert status == 204
  status, document, _ = call(okta, "GET", f"/Groups/{group['id']}")
  assert document["displayName"] == "Renamed" and [member["value"] for member in document["members"]] == [other["id"]]
  status, _, _ = patch(okta, f"/Groups/{group['id']}", {"op": "replace", "path": "members", "value": [
    {"value": user["id"], "display": "test.user@okta.local"}, {"value": other["id"], "display": "other.user@okta.local"}]})
  assert status == 204
  status, document, _ = call(okta, "PUT", f"/Groups/{group['id']}", {
    "schemas": [coreGroup], "id": group["id"], "displayName": "Renamed again",
    "members": [{"value": user["id"], "display": "test.user@okta.local"}]})
  assert status == 200 and [member["value"] for member in document["members"]] == [user["id"]]
  status, document, _ = call(okta, "DELETE", f"/Groups/{group['id']}")
  assert (status, document) == (204, None)


def testPasswordsAreRefusedUnlessTheServiceDiscardsThem(service):
  status, document, _ = call(service, "POST", "/Users", oktaUser("test.user@okta.local"))
  assert status == 400 and "password is refused" in refused(400, document, "invalidValue")


# ---- sorting, version tags and bulk -----------------------------------------------

def testListsSortByAnAttributeWithTheUnsetLast(service):
  for userName, title, email in (("cara", "b", "z@x.org"), ("ana", None, "m@x.org"), ("bea", "A", None)):
    body = {"schemas": [coreUser], "userName": userName}
    if title:
      body["title"] = title
    if email:
      body["emails"] = [{"value": "first@x.org"}, {"value": email, "primary": True}]
    created(service, "/Users", body)
  def names(query):
    return [user["userName"] for user in call(service, "GET", "/Users", query=query)[1]["Resources"]]
  assert names("sortBy=userName") == ["ana", "bea", "cara"]
  assert names("sortBy=userName&sortOrder=descending") == ["cara", "bea", "ana"]
  assert names("sortBy=title") == ["bea", "cara", "ana"]
  assert names("sortBy=emails") == ["ana", "cara", "bea"]
  assert names("sortBy=meta.created&sortOrder=descending&count=2") == ["bea", "ana"]


def testVersionTagsGuardChangesAndAnswerUnchangedReads(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "ana"})
  version = user["meta"]["version"]
  status, document, headers = call(service, "GET", f"/Users/{user['id']}")
  assert headers["ETag"] == version and version.startswith('W/"')
  assert call(service, "GET", f"/Users/{user['id']}", headers={"Authorization": f"Bearer {token}", "If-None-Match": version})[0] == 304
  stale = {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json", "If-Match": 'W/"0"'}
  answer = service.handle("PATCH", f"/Users/{user['id']}", "", stale,
                          json.dumps({"schemas": [patchOpSchema], "Operations": [{"op": "replace", "path": "title", "value": "x"}]}).encode())
  assert answer.status == 412
  fresh = {**stale, "If-Match": version}
  answer = service.handle("PATCH", f"/Users/{user['id']}", "", fresh,
                          json.dumps({"schemas": [patchOpSchema], "Operations": [{"op": "replace", "path": "title", "value": "x"}]}).encode())
  assert answer.status == 200 and answer.headers["ETag"] != version
  assert service.handle("DELETE", f"/Users/{user['id']}", "", fresh, b"").status == 412


def testABulkRequestRunsInOrderWithEarlierIDsAvailableToLaterOperations(service):
  status, document, _ = call(service, "POST", "/Bulk", {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {"method": "POST", "path": "/Users", "bulkId": "ana", "data": {"schemas": [coreUser], "userName": "ana"}},
      {"method": "POST", "path": "/Groups", "bulkId": "team",
       "data": {"schemas": [coreGroup], "displayName": "Team", "members": [{"value": "bulkId:ana"}]}},
      {"method": "PATCH", "path": "/Users/bulkId:ana",
       "data": {"schemas": [patchOpSchema], "Operations": [{"op": "replace", "path": "title", "value": "Lead"}]}},
      {"method": "POST", "path": "/Users", "bulkId": "dup", "data": {"schemas": [coreUser], "userName": "ana"}},
      {"method": "POST", "path": "/Groups", "bulkId": "late", "data": {"schemas": [coreGroup], "displayName": "Late",
                                                                         "members": [{"value": "bulkId:later"}]}},
    ]})
  assert status == 200
  answers = document["Operations"]
  assert [answer["status"] for answer in answers] == ["201", "201", "200", "409", "409"]
  userID = answers[0]["location"].rsplit("/", 1)[1]
  group = call(service, "GET", answers[1]["location"].removeprefix(baseURL))[1]
  assert [member["value"] for member in group["members"]] == [userID]
  assert call(service, "GET", f"/Users/{userID}")[1]["title"] == "Lead"
  assert answers[3]["response"]["scimType"] == "uniqueness" and "bulkId" in answers[4]["response"]["detail"]


def testABulkRequestStopsAfterFailOnErrors(service):
  operations = [{"method": "POST", "path": "/Users", "bulkId": f"u{number}", "data": {"schemas": [coreUser], "userName": "same"}}
                for number in range(4)]
  status, document, _ = call(service, "POST", "/Bulk", {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "failOnErrors": 2, "Operations": operations})
  assert [answer["status"] for answer in document["Operations"]] == ["201", "409", "409"]


bulkSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
nobody = "00000000-0000-4000-8000-000000000000"


def bulk(service, *operations, **extra):
  status, document, _ = call(service, "POST", "/Bulk", {"schemas": [bulkSchema], "Operations": list(operations), **extra})
  assert status == 200, document
  return document["Operations"]


def postUser(bulkId, userName, **attributes):
  return {"method": "POST", "path": "/Users", "bulkId": bulkId, "data": {"schemas": [coreUser], "userName": userName, **attributes}}


@pytest.mark.parametrize("operation, why, scimType", [
  ({"method": "GET", "path": "/Users"}, "needs a method", "invalidSyntax"),
  ({"method": "POST", "path": "/Users", "data": {}}, "needs a bulkId", "invalidSyntax"),
  ({"method": "POST", "path": "/Bulk", "bulkId": "x", "data": {}}, "not a resource operation", "invalidPath"),
  ({"method": "DELETE", "path": "/Users"}, "not a resource operation", "invalidPath"),
  ("DELETE /Users", "must be an object", "invalidSyntax"),
  ({"method": "DELETE", "path": f"/Users/{nobody}", "data": {}}, "a DELETE takes no data", "invalidSyntax"),
  ({"method": "DELETE", "path": f"/Users/{nobody}", "version": 123}, "version must be an entity tag", "invalidSyntax"),
  ({"method": "DELETE", "path": f"/Users/{nobody}", "version": "abc"}, "version must be an entity tag", "invalidSyntax"),
  ({"method": "POST", "path": "/Users", "bulkId": "x", "version": 'W/"1"', "data": {}}, "a POST takes no version",
   "invalidSyntax"),
  ({"method": "POST", "path": "/Users", "bulkId": "a b", "data": {}}, "a bulkId is 1 to 64", "invalidSyntax"),
  ({"method": "POST", "path": "/Users", "bulkId": "x" * 65, "data": {}}, "a bulkId is 1 to 64", "invalidSyntax"),
])
def testAMalformedBulkOperationIsAnsweredOnItsOwnAfterTheOnesBefore(service, operation, why, scimType):
  answers = bulk(service, postUser("kept", "kept"), operation, postUser("after", "after"))
  assert [answer["status"] for answer in answers] == ["201", "400", "201"]
  assert why in refused(400, answers[1]["response"], scimType)
  assert sorted(user["userName"] for user in service.store.resources["User"].values()) == ["after", "kept"]


def testAMalformedBulkOperationCountsTowardFailOnErrors(service):
  answers = bulk(service, {"method": "GET", "path": "/Users"}, postUser("never", "never"), failOnErrors=1)
  assert [answer["status"] for answer in answers] == ["400"]
  assert service.store.resources["User"] == {}


def testABulkVersionIsTheIfMatchOfItsOperation(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "ana"})
  replace = {"schemas": [patchOpSchema], "Operations": [{"op": "replace", "path": "title", "value": "x"}]}
  answers = bulk(service, {"method": "PATCH", "path": f"/Users/{user['id']}", "version": 'W/"0"', "data": replace},
                 {"method": "PATCH", "path": f"/Users/{user['id']}", "version": user["meta"]["version"], "data": replace})
  assert [answer["status"] for answer in answers] == ["412", "200"]


def testBulkIDsResolveOnlyAsWholeReferences(service):
  answers = bulk(
    service, postUser("u1", "first"), postUser("u10", "second"),
    postUser("u2", "third", displayName="see bulkId:u10", externalId="bulkId:u1"),
    {"method": "PATCH", "path": "/Users/bulkId:u10",
     "data": {"schemas": [patchOpSchema], "Operations": [{"op": "replace", "path": "title", "value": "bulkId:u1"}]}},
    {"method": "POST", "path": "/Groups", "bulkId": "team",
     "data": {"schemas": [coreGroup], "displayName": "bulkId:u1", "members": [{"value": "bulkId:u10"}]}},
    {"method": "PATCH", "path": "/Groups/bulkId:team", "data": {"schemas": [patchOpSchema], "Operations": [
      {"op": "add", "path": "members", "value": [{"value": "bulkId:u2"}]},
      {"op": "add", "value": {"members": [{"value": "bulkId:u1"}]}}]}},
    postUser("u3", "fourth", schemas=[coreUser, enterprise], **{enterprise: {"manager": {"value": "bulkId:u1"}}}),
    {"method": "PATCH", "path": "/Users/bulkId:u2", "data": {"schemas": [patchOpSchema], "Operations": [
      {"op": "add", "path": f"{enterprise}:manager.value", "value": "bulkId:u10"}]}},
  )
  assert [answer["status"] for answer in answers] == ["201", "201", "201", "200", "201", "204", "201", "200"]
  ids = {user["userName"]: userID for userID, user in service.store.resources["User"].items()}
  users = service.store.resources["User"]
  assert (users[ids["third"]]["displayName"], users[ids["third"]]["externalId"]) == ("see bulkId:u10", "bulkId:u1")
  assert users[ids["second"]]["title"] == "bulkId:u1"
  group = next(iter(service.store.resources["Group"].values()))
  assert group["displayName"] == "bulkId:u1"
  assert [member["value"] for member in group["members"]] == [ids["second"], ids["third"], ids["first"]]
  assert users[ids["fourth"]][enterprise]["manager"] == {"value": ids["first"]}
  assert users[ids["third"]][enterprise]["manager"] == {"value": ids["second"]}


@pytest.mark.parametrize("operation, status, why, scimType", [
  ({"method": "PATCH", "path": "/Users/bulkId:u10", "data": {"schemas": [patchOpSchema], "Operations": [
    {"op": "replace", "path": "title", "value": "x"}]}}, "409", "bulkId u10, which no earlier operation", "invalidValue"),
  ({"method": "POST", "path": "/Groups", "bulkId": "g", "data": {"schemas": [coreGroup], "displayName": "g",
                                                                  "members": [{"value": "bulkId:later"}]}},
   "409", "bulkId later, which no earlier operation", "invalidValue"),
  ({"method": "POST", "path": "/Groups", "bulkId": "g", "data": {"schemas": [coreGroup], "displayName": "g",
                                                                  "members": [{"value": "bulkId:failed"}]}},
   "409", "bulkId failed, whose POST failed", "invalidValue"),
  ({"method": "POST", "path": "/Groups", "bulkId": "g", "data": {"schemas": [coreGroup], "displayName": "g",
                                                                  "members": [{"value": "bulkId:a b"}]}},
   "400", "whose name is not a bulkId", "invalidValue"),
  (postUser("u1", "again"), "400", "bulkId u1 is used by an earlier operation", "invalidSyntax"),
  (postUser("failed", "again"), "400", "bulkId failed is used by an earlier operation", "invalidSyntax"),
])
def testBulkIDReferencesAreRefusedByName(service, operation, status, why, scimType):
  answers = bulk(service, postUser("u1", "first"), postUser("failed", "first"), operation)
  assert [answer["status"] for answer in answers] == ["201", "409", status]
  assert why in refused(int(status), answers[2]["response"], scimType)


def testAResolvedBulkOperationIsBoundedByTheBodyLimit():
  service = SCIMService(MemoryStore(), baseURL, lambda presented: presented == token, maximumBytes=2000)
  group = {"method": "POST", "path": "/Groups", "bulkId": "g",
           "data": {"schemas": [coreGroup], "displayName": "g", "members": [{"value": "bulkId:a"}] * 60}}
  body = {"schemas": [bulkSchema], "Operations": [postUser("a", "a"), group]}
  assert len(json.dumps(body)) < 2000
  answers = bulk(service, *body["Operations"])
  assert [answer["status"] for answer in answers] == ["201", "413"]


def versionOf(service, path, headers=None):
  status, _, answered = call(service, "GET", path, headers=headers)
  assert status in (200, 304)
  return answered["ETag"]


def testAUsersVersionChangesWithItsGroupsAndNeverReturns(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "ana"})
  path = f"/Users/{user['id']}"
  versions = [versionOf(service, path)]
  group = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "admins", "members": [{"value": user["id"]}]})
  versions.append(versionOf(service, path))
  assert call(service, "GET", path, headers={"Authorization": f"Bearer {token}", "If-None-Match": versions[0]})[0] == 200
  assert patch(service, f"/Groups/{group['id']}", {"op": "replace", "path": "displayName", "value": "staff"})[0] == 204
  versions.append(versionOf(service, path))
  assert call(service, "GET", path)[1]["groups"] == [{"value": group["id"], "display": "staff", "type": "direct",
                                                    "$ref": f"{baseURL}/Groups/{group['id']}"}]
  assert patch(service, f"/Groups/{group['id']}", {"op": "remove", "path": "members"})[0] == 204
  versions.append(versionOf(service, path))
  assert patch(service, f"/Groups/{group['id']}", {"op": "add", "path": "members", "value": [{"value": user["id"]}]})[0] == 204
  versions.append(versionOf(service, path))
  assert call(service, "DELETE", f"/Groups/{group['id']}")[0] == 204
  versions.append(versionOf(service, path))
  assert len(set(versions)) == len(versions)


def testAChangeUndoneGivesANewVersion(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "ana"})
  first = user["meta"]["version"]
  assert patch(service, f"/Users/{user['id']}", {"op": "add", "path": "title", "value": "x"})[0] == 200
  status, document, _ = patch(service, f"/Users/{user['id']}", {"op": "remove", "path": "title"})
  assert status == 200 and "title" not in document and document["meta"]["version"] != first
  answer = service.handle("PATCH", f"/Users/{user['id']}", "", {
    "Authorization": f"Bearer {token}", "Content-Type": "application/scim+json", "If-Match": first},
    json.dumps({"schemas": [patchOpSchema], "Operations": [{"op": "replace", "path": "title", "value": "y"}]}).encode())
  assert answer.status == 412


def testIfMatchComparesExactlyAndIfNoneMatchWeakly(service):
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "ana"})
  path, version = f"/Users/{user['id']}", user["meta"]["version"]
  strong = version.removeprefix("W/")
  def get(header, value):
    return call(service, "GET", path, headers={"Authorization": f"Bearer {token}", header: value})
  assert get("If-None-Match", strong)[0] == 304
  assert get("If-None-Match", f'"other", {version}')[0] == 304
  assert get("If-Match", strong)[0] == 412
  assert get("If-Match", f'"other", {version}')[0] == 200
  assert get("If-Match", "*")[0] == 200
  status, document, _ = get("If-Match", version.removeprefix("W/").strip('"'))
  assert "If-Match is not * or a list of entity tags" in refused(400, document, "invalidSyntax")
  deleting = {"Authorization": f"Bearer {token}", "If-None-Match": version}
  assert service.handle("DELETE", path, "", deleting, b"").status == 412
  assert service.handle("DELETE", path, "", {**deleting, "If-None-Match": 'W/"other"'}, b"").status == 204


def oktaService():
  return SCIMService(MemoryStore(), baseURL, lambda presented: presented == token, discardPasswords=True)


@pytest.mark.parametrize("body, why", [
  ({"Operations": [], "schemas": "not a list", "junk": 1}, "names exactly the schema"),
  ({"schemas": [patchOpSchema], "Operations": []}, "needs a list of Operations"),
  ({"schemas": [patchOpSchema], "Operations": [{"op": "bogus", "path": "password", "value": "x"}]}, "op must be add"),
  ({"schemas": [patchOpSchema], "Operations": [{"op": "replace", "path": "password", "value": "x", "junk": 1}]},
   "unknown members"),
  ({"schemas": [patchOpSchema], "Operations": [{"op": "replace", "value": "password"}]}, "needs an object of attributes"),
])
def testAPatchWithPasswordsDiscardedIsStillReadStrictly(body, why):
  okta = oktaService()
  user = created(okta, "/Users", {"schemas": [coreUser], "userName": "ana"})
  status, document, _ = call(okta, "PATCH", f"/Users/{user['id']}", body)
  assert status == 400 and why in refused(400, document, "invalidSyntax")
  assert okta.store.resources["User"][user["id"]]["meta"]["revision"] == 1


def testAPatchOfOnlyPasswordsWritesNothing():
  okta = oktaService()
  user = created(okta, "/Users", {"schemas": [coreUser], "userName": "ana"})
  stored = copy.deepcopy(okta.store.resources["User"])
  status, document, headers = patch(okta, f"/Users/{user['id']}", {"op": "replace", "path": "password", "value": "x"},
                                    {"op": "replace", "value": {"Password": "y"}})
  assert (status, headers["ETag"], document) == (200, user["meta"]["version"], user)
  assert okta.store.resources["User"] == stored
  status, document, _ = patch(okta, f"/Users/{user['id']}", {"op": "replace", "value": {"password": "y", "title": "t"}})
  assert status == 200 and document["title"] == "t"


def testABinaryValueOutsideASCIIIsRefusedAsBase64(service):
  status, document, _ = call(service, "POST", "/Users", {"schemas": [coreUser], "userName": "ana",
                                                         "x509Certificates": [{"value": "\u00e9"}]})
  assert status == 400 and "must be base64 text" in refused(400, document, "invalidValue")


class FailingStore(MemoryStore):
  """The memory store, failing (as a database can) at the given replace call."""

  def __init__(self):
    super().__init__()
    self.replacesLeft = None

  def replace(self, resourceType, resource):
    if self.replacesLeft == 0:
      raise ConnectionError("the database went away")
    if self.replacesLeft is not None:
      self.replacesLeft -= 1
    super().replace(resourceType, resource)


def danglingMembers(store):
  return [member["value"] for group in store.resources["Group"].values() for member in group.get("members", [])
          if member["value"] not in store.resources[member["type"]]]


@pytest.mark.parametrize("deleted, replacesLeft", [("user", 0), ("user", 1), ("inner", 0), ("inner", 1)])
def testADeleteFailingMidwayLeavesNoMemberDangling(deleted, replacesLeft):
  store = FailingStore()
  service = SCIMService(store, baseURL, lambda presented: presented == token)
  user = created(service, "/Users", {"schemas": [coreUser], "userName": "ana"})
  inner = created(service, "/Groups", {"schemas": [coreGroup], "displayName": "inner", "members": [{"value": user["id"]}]})
  created(service, "/Groups", {"schemas": [coreGroup], "displayName": "outer",
                               "members": [{"value": user["id"]}, {"value": inner["id"]}]})
  target = {"user": f"/Users/{user['id']}", "inner": f"/Groups/{inner['id']}"}[deleted]
  store.replacesLeft = replacesLeft
  with pytest.raises(ConnectionError):
    service.handle("DELETE", target, "", {"Authorization": f"Bearer {token}"}, b"")
  assert danglingMembers(store) == []
  store.replacesLeft = None
  assert service.handle("DELETE", target, "", {"Authorization": f"Bearer {token}"}, b"").status == 204
  assert danglingMembers(store) == []
