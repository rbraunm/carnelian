# SPDX-License-Identifier: MIT
"""The LDAP client: its BER and filters, then sign-in against a Samba Active Directory."""

import pytest

from carnelian.fetching import secureContext
from carnelian.ldap import All, Directory, DirectoryRefused, Equal, InChain, Present, integer, readAll, readTLV

from testOIDC import account


def testEncodingsAreTheStandardOnes():
  assert integer(0) == bytes.fromhex("020100")
  assert integer(127) == bytes.fromhex("02017f") and integer(128) == bytes.fromhex("02020080")
  assert integer(3) == bytes.fromhex("020103")
  assert Equal("cn", "ana").encoded() == bytes.fromhex("a3090402636e0403616e61")
  assert Present("cn").encoded() == bytes.fromhex("8702636e")


def testAUserNameCannotInjectFilterSyntax():
  injected = Equal("sAMAccountName", "*)(objectClass=*").encoded()
  tag, content, _ = readTLV(injected)
  attribute, value = readAll(content)
  assert tag == 0xA3 and value[1] == b"*)(objectClass=*"


def testInChainIsAnExtensibleMatch():
  tag, content, _ = readTLV(InChain("member", "CN=ana,DC=x").encoded())
  assert tag == 0xA9
  assert [(part[0], part[1]) for part in readAll(content)] == [
    (0x81, b"1.2.840.113556.1.4.1941"), (0x82, b"member"), (0x83, b"CN=ana,DC=x")]


def testLongFormLengthsAreRead():
  assert readTLV(bytes.fromhex("0484000000026869")) == (0x04, b"hi", 8)
  with pytest.raises(DirectoryRefused, match="indefinite"):
    readTLV(bytes.fromhex("3080"))


def testAnEmptyPasswordIsRefusedBeforeAnythingIsSent():
  directory = Directory("directory.invalid", secureContext(), "DC=x", "svc", "secret")
  with pytest.raises(DirectoryRefused, match="empty password is refused"):
    directory.signIn("ana", "")


# ---- against the testbed's Samba Active Directory --------------------------

@pytest.fixture(scope="module", params=["ldaps", "startTLS"])
def directory(request, testbed):
  if not request.config.getoption("--directory"):
    pytest.skip("directory test: run with --directory against a testbed whose Samba is running")
  settings = testbed["directory"]
  startTLS = request.param == "startTLS"
  return Directory(settings["host"], secureContext(testbed["certificateAuthority"]), settings["baseDN"],
                   settings["serviceDN"], settings["servicePassword"],
                   port=settings["ldapPort"] if startTLS else settings["ldapsPort"], startTLS=startTLS)


def expectedGroups(paths):
  return tuple(sorted({segment for path in paths for segment in path.strip("/").split("/")}))


@pytest.mark.parametrize("userName", ["ana", "jose", "layla", "wei", "manygroups"])
def testEveryoneSignsInWithNestedGroups(testbed, directory, userName):
  expected = account(testbed, userName)
  identity = directory.signIn(userName, expected["password"])
  assert identity.userName == userName
  assert identity.email == expected["email"]
  assert identity.groups == expectedGroups(expected["groups"])


@pytest.mark.parametrize("userName, password", [
  ("ana", "not the password"), ("disabled", None), ("nobody", "whatever-password"), ("*", "whatever-password"),
])
def testWrongDisabledUnknownAndWildcardSignInsAreRefusedAlike(testbed, directory, userName, password):
  if password is None:
    password = account(testbed, userName)["password"]
  with pytest.raises(DirectoryRefused, match="^the user name or the password is wrong$"):
    directory.signIn(userName, password)
