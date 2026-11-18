# SPDX-License-Identifier: MIT
"""The LDAP client: its BER, filters and strict reading, sign-in against a stand-in directory, then a Samba one."""

import datetime
import ipaddress
import socket
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from carnelian import ldap
from carnelian.fetching import secureContext
from carnelian.ldap import (DirectoryKind, All, Connection, Directory, DirectoryRefused, Equal, InChain, Present, checkResult,
                            integer, octets, readAll, readEntry, readTLV, sequence, tlv)

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


@pytest.mark.parametrize("change", ["verify_mode", "check_hostname", "minimum_version"])
def testATLSContextThatDoesNotVerifyIsRefused(change):
  context = secureContext()
  if change == "verify_mode":
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
  elif change == "check_hostname":
    context.check_hostname = False
  else:
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
  with pytest.raises(DirectoryRefused, match="does not require a verified certificate"):
    Directory("directory.invalid", context, "DC=x", "svc", "secret")


def testATLSContextWeakenedAfterwardsIsRefusedAtConnection():
  context = secureContext()
  directory = Directory("directory.invalid", context, "DC=x", "svc", "secret")
  context.check_hostname = False
  with pytest.raises(DirectoryRefused, match="does not require a verified certificate"):
    directory.signIn("ana", "password")


# ---- LDAPResult ---------------------------------------------------------------

def result(code=b"\x00", matched=octets(""), diagnostic=octets(""), *extra, codeTag=0x0A):
  return tlv(codeTag, code) + matched + diagnostic + b"".join(extra)


def testAWellFormedSuccessPasses():
  checkResult(result(), "bind")
  checkResult(result(b"\x00", octets(""), octets(""), octets(b"creds", 0x87)), "bind", frozenset({0x87}))


@pytest.mark.parametrize("answer, reason", [
  (result(b""), "LDAP integer without content"),
  (result(codeTag=0x02), "without its result code"),
  (octets(b"\x00", 0x0A) + octets(b""), "without its result code"),
  (result(b"\x00", octets("", 0x80)), "without its result code"),
  (result(b"\x00", octets(""), sequence()), "without its result code"),
  (b"", "without its result code"),
  (result(b"\x00", octets(""), octets(""), octets(b"x", 0x87)), "unexpected parts"),
  (result(b"\x00", octets(""), octets(""), octets(b"x", 0x04)), "unexpected parts"),
  (result(b"\x00", octets(""), octets(""), sequence(octets("ldap://elsewhere/"), tag=0xA3)), "carries a referral"),
  (result(b"\x31", octets(""), octets("bad password")), "invalidCredentials bad password"),
])
def testAMalformedOrFailedResultIsNeverSuccess(answer, reason):
  with pytest.raises(DirectoryRefused, match=reason):
    checkResult(answer, "bind")


# ---- search entries -----------------------------------------------------------

def attributeList(attributes):
  return sequence(*(sequence(octets(name), sequence(*(octets(value) for value in values), tag=0x31))
                    for name, values in attributes.items()))


def entry(dn, attributes):
  return sequence(octets(dn), attributeList(attributes), tag=0x64)


def entryContent(dn, attributes):
  return readTLV(entry(dn, attributes))[1]


def testAnEntryIsReadWithAttributeNamesWithoutCase():
  read = readEntry(entryContent("CN=ana,DC=x", {"USERACCOUNTCONTROL": ["512"], "mail": ["a@x", "b@x"]}))
  assert read.dn == "CN=ana,DC=x"
  assert read.attributes == {"useraccountcontrol": ("512",), "mail": ("a@x", "b@x")}
  assert read.values("userAccountControl") == ("512",) and read.values("displayName") is None


@pytest.mark.parametrize("content, reason", [
  (octets("CN=ana"), "not a DN and an attribute list"),
  (octets("CN=ana") + attributeList({}) + octets("x"), "not a DN and an attribute list"),
  (octets("CN=ana", 0x80) + attributeList({}), "not a DN and an attribute list"),
  (octets("CN=ana") + sequence(attributeList({}), tag=0x31), "not a DN and an attribute list"),
  (octets("CN=ana") + sequence(sequence(octets("mail"), tag=0x31)), "not a name and a set of values"),
  (octets("CN=ana") + sequence(sequence(octets("mail"), sequence(tag=0x30))), "not a name and a set of values"),
  (octets("CN=ana") + sequence(sequence(octets("mail"), sequence(octets("a", 0x80), tag=0x31))), "other than OCTET"),
  (octets("CN=ana") + sequence(sequence(octets("mail"), sequence(tag=0x31)), sequence(octets("MAIL"), sequence(tag=0x31))),
   "'mail' empty or twice"),
  (octets(b"CN=\xff") + attributeList({}), "a DN that is not UTF-8"),
])
def testAMalformedEntryIsRefused(content, reason):
  with pytest.raises(DirectoryRefused, match=reason):
    readEntry(content)


# ---- a connection over a stand-in socket --------------------------------------

def message(messageID, operation, *more):
  return sequence(integer(messageID), operation, *more)


def bindResponse(messageID, code=0):
  return message(messageID, sequence(integer(code, 0x0A), octets(""), octets(""), tag=0x61))


def searchDone(messageID, code=0):
  return message(messageID, sequence(integer(code, 0x0A), octets(""), octets(""), tag=0x65))


@pytest.fixture
def standIn():
  """A Connection whose peer sends `answers` from a thread; yields a function that starts it."""
  sockets = []

  def start(*answers, pause=0.0, idleSeconds=None):
    ours, theirs = socket.socketpair()
    ours.settimeout(idleSeconds)
    sockets.extend((ours, theirs))

    def send():
      try:
        for answer in answers:
          theirs.sendall(answer)
          time.sleep(pause)
      except OSError:
        pass

    threading.Thread(target=send, daemon=True).start()
    return Connection(ours), theirs

  yield start
  for each in sockets:
    each.close()


def testABindAnsweredWellSucceedsAndIsSentAsSimpleBind(standIn):
  connection, theirs = standIn(bindResponse(1))
  connection.bind("CN=svc,DC=x", "secret")
  sent = theirs.recv(1000)
  assert sent == message(1, sequence(integer(3), octets("CN=svc,DC=x"), octets("secret", 0x80), tag=0x60))


def testABindWithAnEmptyNameIsRefusedBeforeItIsSent(standIn):
  connection, theirs = standIn(bindResponse(1))
  with pytest.raises(DirectoryRefused, match="empty name is refused"):
    connection.bind("", "secret")
  theirs.setblocking(False)
  with pytest.raises(BlockingIOError):
    theirs.recv(1)


@pytest.mark.parametrize("answer, reason", [
  (message(1, sequence(octets(b"", 0x0A), octets(""), octets(""), tag=0x61)), "integer without content"),
  (message(1, sequence(integer(0), octets(""), octets(""), tag=0x61)), "without its result code"),
  (message(1, sequence(integer(0, 0x0A), octets(""), tag=0x61)), "without its result code"),
  (message(1, sequence(integer(0, 0x0A), integer(0), octets(""), tag=0x61)), "without its result code"),
  (sequence(octets(b"", 0x02), sequence(integer(0, 0x0A), octets(""), octets(""), tag=0x61)), "integer without content"),
  (message(1, sequence(integer(0, 0x0A), octets(""), octets(""), tag=0x61), octets("x")), "optional controls"),
  (message(2, sequence(integer(0, 0x0A), octets(""), octets(""), tag=0x61)), "answered message 2, not 1"),
])
def testAMalformedBindResponseIsNeverSuccess(standIn, answer, reason):
  connection, _ = standIn(answer)
  with pytest.raises(DirectoryRefused, match=reason):
    connection.bind("CN=svc,DC=x", "secret")


def search(connection):
  return connection.search("DC=x", Equal("objectClass", "group"), ("sAMAccountName",))


def testASearchReturnsItsEntries(standIn):
  connection, _ = standIn(message(1, entry("CN=a,DC=x", {"sAMAccountName": ["a"]})),
                          message(1, entry("CN=b,DC=x", {"sAMAccountName": ["b"]})), searchDone(1))
  assert [found.dn for found in search(connection)] == ["CN=a,DC=x", "CN=b,DC=x"]


def testASearchReferenceIsRefused(standIn):
  connection, _ = standIn(message(1, entry("CN=a,DC=x", {})),
                          message(1, sequence(octets("ldap://other.example/DC=x"), tag=0x73)), searchDone(1))
  with pytest.raises(DirectoryRefused, match="reference to another server"):
    search(connection)


def testMoreEntriesThanTheMaximumAreRefusedWhateverTheServerDoes(standIn):
  one = message(1, entry("CN=a,DC=x", {}))
  connection, _ = standIn(one * ldap.maximumEntries, one, searchDone(1))
  with pytest.raises(DirectoryRefused, match=f"more than {ldap.maximumEntries} entries"):
    search(connection)


def testExactlyTheMaximumOfEntriesIsRead(standIn):
  connection, _ = standIn(message(1, entry("CN=a,DC=x", {})) * ldap.maximumEntries, searchDone(1))
  assert len(search(connection)) == ldap.maximumEntries


def testASearchIsRefusedPastItsByteBudget(standIn):
  big = message(1, entry("CN=a,DC=x", {"description": ["x" * (ldap.maximumMessageBytes - 100)]}))
  count = ldap.maximumOperationBytes // len(big) + 1
  connection, _ = standIn(*([big] * count), searchDone(1))
  with pytest.raises(DirectoryRefused, match=f"more than {ldap.maximumOperationBytes} bytes for one operation"):
    search(connection)


def testASlowTrickleIsRefusedAtTheOperationDeadline(standIn, monkeypatch):
  monkeypatch.setattr(ldap, "maximumOperationSeconds", 0.6)
  answer = bindResponse(1)
  connection, _ = standIn(*(answer[index:index + 1] for index in range(len(answer))), pause=0.1, idleSeconds=0.3)
  began = time.monotonic()
  with pytest.raises(DirectoryRefused, match="did not finish within 0.6 seconds"):
    connection.bind("CN=svc,DC=x", "secret")
  assert time.monotonic() - began < 1.0


def testASilentDirectoryIsRefusedAtTheOperationDeadline(standIn, monkeypatch):
  monkeypatch.setattr(ldap, "maximumOperationSeconds", 0.3)
  connection, _ = standIn(bindResponse(1)[:3])
  with pytest.raises(DirectoryRefused, match="did not finish within 0.3 seconds"):
    connection.bind("CN=svc,DC=x", "secret")


def testAnIdleDirectoryIsRefusedAtItsSocketTimeout(standIn):
  connection, _ = standIn(bindResponse(1)[:3], idleSeconds=0.2)
  with pytest.raises(DirectoryRefused, match="silent for 0.2 seconds"):
    connection.bind("CN=svc,DC=x", "secret")


# ---- sign-in against a stand-in directory over TLS -----------------------------

@pytest.fixture(scope="module")
def tlsFiles(tmp_path_factory):
  folder = tmp_path_factory.mktemp("tls")
  now = datetime.datetime.now(datetime.UTC)
  authorityKey, serverKey = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
  authorityName = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test authority")])
  authority = (x509.CertificateBuilder().subject_name(authorityName).issuer_name(authorityName)
               .public_key(authorityKey.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(authorityKey.public_key()), critical=False)
               .sign(authorityKey, hashes.SHA256()))
  server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(authorityName).public_key(serverKey.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authorityKey.public_key()), critical=False)
            .sign(authorityKey, hashes.SHA256()))
  (folder / "authority.pem").write_bytes(authority.public_bytes(serialization.Encoding.PEM))
  (folder / "server.pem").write_bytes(server.public_bytes(serialization.Encoding.PEM) + serverKey.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
  return folder


class StandInDirectory:
  """Answers binds for the accepted name and password pairs and searches with the given entries, over LDAPS."""

  def __init__(self, tlsFiles, users, groups, accepted):
    self.users, self.groups, self.accepted = users, groups, accepted
    self.binds, self.searches = [], []
    self.serverContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    self.serverContext.load_cert_chain(tlsFiles / "server.pem")
    self.listener = socket.create_server(("127.0.0.1", 0))
    self.port = self.listener.getsockname()[1]
    threading.Thread(target=self.accept, daemon=True).start()

  def accept(self):
    while True:
      try:
        raw, _ = self.listener.accept()
      except OSError:
        return
      threading.Thread(target=self.serve, args=(raw,), daemon=True).start()

  def serve(self, raw):
    with self.serverContext.wrap_socket(raw, server_side=True) as connection, connection.makefile("rb") as reader:
      while True:
        head = reader.read(2)
        if len(head) < 2:
          return
        length = head[1]
        if length & 0x80:
          length = int.from_bytes(reader.read(length & 0x7F), "big")
        idPart, (tag, content) = readAll(reader.read(length))[:2]
        messageID = int.from_bytes(idPart[1], "big")
        parts = readAll(content)
        if tag == 0x60:
          pair = (parts[1][1].decode(), parts[2][1].decode())
          self.binds.append(pair)
          connection.sendall(bindResponse(messageID, 0 if pair in self.accepted else 49))
        elif tag == 0x63:
          query = parts[6]
          self.searches.append((tlv(*query),
                                [name.decode() for _, name in readAll(parts[7][1])]))
          found = self.groups if b"group" in query[1] and b"person" not in query[1] else self.users
          if isinstance(found, dict):
            found = found.get(readAll(readAll(query[1])[1][1])[1][1].decode(), [])
          connection.sendall(b"".join(message(messageID, each) for each in found) + searchDone(messageID))
        else:
          return

  def directory(self, tlsFiles):
    return Directory("127.0.0.1", secureContext(str(tlsFiles / "authority.pem")), "DC=x", "CN=svc,DC=x", "svc password",
                     port=self.port)

  def openLDAP(self, tlsFiles):
    return Directory("127.0.0.1", secureContext(str(tlsFiles / "authority.pem")), "dc=x", "CN=svc,DC=x", "svc password",
                     port=self.port, kind=DirectoryKind.openLDAP, groupsBaseDN="ou=groups,dc=x")

  def close(self):
    self.listener.close()


anaDN = "CN=ana,OU=People,DC=x"
service = ("CN=svc,DC=x", "svc password")


@pytest.fixture
def standInDirectory(tlsFiles):
  made = []

  def make(users, groups=(), accepted=(service, (anaDN, "right"))):
    made.append(StandInDirectory(tlsFiles, list(users), groups if isinstance(groups, dict) else list(groups), set(accepted)))
    return made[-1].directory(tlsFiles), made[-1]

  yield make
  for each in made:
    each.close()


def ana(**overrides):
  attributes = {"sAMAccountName": ["ana"], "displayName": ["Ana"], "mail": ["ana@x"], "userAccountControl": ["512"]}
  attributes.update(overrides)
  return entry(anaDN, {name: values for name, values in attributes.items() if values is not None})


def testSignInFindsOnlyPeopleAndNamesGroupsByTheirDomainUniqueName(standInDirectory):
  directory, server = standInDirectory(
    [ana()], [entry("CN=Domain Admins,OU=Students,DC=x", {"sAMAccountName": ["students-admins"], "cn": ["Domain Admins"]}),
              entry("CN=staff,DC=x", {"sAMAccountName": ["staff"]})])
  identity = directory.signIn("ana", "right")
  assert identity.groups == ("staff", "students-admins")
  assert (identity.dn, identity.userName, identity.displayName, identity.email) == (anaDN, "ana", "Ana", "ana@x")
  assert server.searches[0][0] == All((Equal("objectCategory", "person"), Equal("objectClass", "user"),
                                       Equal("sAMAccountName", "ana"))).encoded()
  assert server.searches[1] == (All((Equal("objectClass", "group"), InChain("member", anaDN))).encoded(), ["sAMAccountName"])
  assert server.binds == [service, (anaDN, "right")]


def testAttributeNamesFromTheDirectoryAreMatchedWithoutCase(standInDirectory):
  directory, _ = standInDirectory([entry(anaDN, {"SAMACCOUNTNAME": ["ana"], "MAIL": ["ana@x"], "useraccountcontrol": ["512"]})],
                                  [entry("CN=staff,DC=x", {"samaccountname": ["staff"]})])
  identity = directory.signIn("ana", "right")
  assert (identity.userName, identity.email, identity.displayName, identity.groups) == ("ana", "ana@x", None, ("staff",))


def testAMissingUserAccountControlIsRefusedNotTakenAsEnabled(standInDirectory):
  directory, server = standInDirectory([ana(userAccountControl=None)])
  with pytest.raises(DirectoryRefused, match="did not send userAccountControl for the user"):
    directory.signIn("ana", "right")
  assert server.binds == [service]


@pytest.mark.parametrize("control, reason", [
  ("514", "^the user name or the password is wrong$"),
  ("5_12", "userAccountControl that is not a number"),
  (" 512", "userAccountControl that is not a number"),
])
def testADisabledOrUnreadableAccountIsRefused(standInDirectory, control, reason):
  directory, server = standInDirectory([ana(userAccountControl=[control])])
  with pytest.raises(DirectoryRefused, match=reason):
    directory.signIn("ana", "right")
  assert server.binds == [service]


def testAnEntryWithAnEmptyDNIsRefusedBeforeAnythingBindsWithIt(standInDirectory):
  directory, server = standInDirectory([entry("", {"sAMAccountName": ["ana"], "userAccountControl": ["512"]})],
                                       accepted=(service, ("", "right")))
  with pytest.raises(DirectoryRefused, match="empty DN"):
    directory.signIn("ana", "right")
  assert server.binds == [service]


def testAGroupWithoutItsSAMAccountNameIsRefused(standInDirectory):
  directory, _ = standInDirectory([ana()], [entry("CN=staff,DC=x", {"cn": ["staff"]})])
  with pytest.raises(DirectoryRefused, match="did not send sAMAccountName for a group"):
    directory.signIn("ana", "right")


def testTwoValuesOfASingleAttributeAreRefused(standInDirectory):
  directory, _ = standInDirectory([ana(sAMAccountName=["ana", "other"])])
  with pytest.raises(DirectoryRefused, match="2 values of sAMAccountName, not one"):
    directory.signIn("ana", "right")


def testAWrongPasswordIsRefused(standInDirectory):
  directory, server = standInDirectory([ana()])
  with pytest.raises(DirectoryRefused, match="^the user name or the password is wrong$"):
    directory.signIn("ana", "wrong")
  assert server.binds == [service, (anaDN, "wrong")]


# ---- OpenLDAP groups against a stand-in directory -------------------------------

personDN = "uid=ana,ou=people,dc=x"


def openLDAPDirectory(standInDirectory, tlsFiles, groupsOf):
  _, server = standInDirectory([entry(personDN, {"uid": ["ana"], "mail": ["ana@x"]})], groupsOf,
                               accepted=(service, (personDN, "right")))
  return server.openLDAP(tlsFiles), server


def group(dn, name, number):
  return entry(dn, {"cn": [name], "entryUUID": [f"00000000-0000-4000-8000-{number:012d}"]})


def testOpenLDAPGroupsAreWalkedOnceEachByTheirEntryUUID(standInDirectory, tlsFiles):
  staff, everyone = "cn=staff,ou=groups,dc=x", "cn=everyone,ou=groups,dc=x"
  directory, server = openLDAPDirectory(standInDirectory, tlsFiles, {
    personDN: [group(staff, "staff", 1)],
    staff: [group(everyone, "everyone", 2)],
    everyone: [group("cn=staff, ou=groups,dc=x", "staff", 1)],
  })
  assert directory.signIn("ana", "right").groups == ("everyone", "staff")
  groupSearches = server.searches[1:]
  assert [query for query, _ in groupSearches] == [
    All((Equal("objectClass", "groupOfNames"), Equal("member", member))).encoded() for member in (personDN, staff, everyone)]
  assert {tuple(attributes) for _, attributes in groupSearches} == {("cn", "entryUUID")}


@pytest.mark.parametrize("dn, reason", [
  ("description=x,ou=groups,dc=x", "not named by cn=admins as its first RDN"),
  ("cn=other,ou=groups,dc=x", "not named by cn=admins as its first RDN"),
  ("cn=admins+ou=x,ou=groups,dc=x", "first RDN of more than one attribute"),
  ("cn=#0406061646d696e73,ou=groups,dc=x", "by a BER value"),
  ("cn=adm\\qins,ou=groups,dc=x", "escape RFC 4514 does not define"),
  ("cn=\\ff,ou=groups,dc=x", "escapes bytes that are not UTF-8"),
])
def testAnOpenLDAPGroupNotNamedByItsCnIsRefused(standInDirectory, tlsFiles, dn, reason):
  directory, _ = openLDAPDirectory(standInDirectory, tlsFiles, {personDN: [group(dn, "admins", 1)]})
  with pytest.raises(DirectoryRefused, match=reason):
    directory.signIn("ana", "right")


def testAnOpenLDAPGroupRDNIsReadWithItsEscapes(standInDirectory, tlsFiles):
  directory, _ = openLDAPDirectory(standInDirectory, tlsFiles, {
    personDN: [group("CN=r\\+d\\2C \\c3\\a9quipe,ou=groups,dc=x", "R+D, \u00c9quipe", 1)]})
  assert directory.signIn("ana", "right").groups == ("R+D, \u00c9quipe",)


def testAnOpenLDAPGroupWithoutAUUIDIsRefused(standInDirectory, tlsFiles):
  directory, _ = openLDAPDirectory(standInDirectory, tlsFiles, {
    personDN: [entry("cn=staff,ou=groups,dc=x", {"cn": ["staff"], "entryUUID": ["staff"]})]})
  with pytest.raises(DirectoryRefused, match="entryUUID that is not a UUID"):
    directory.signIn("ana", "right")


def chain(length):
  dns = [personDN] + [f"cn=g{index},ou=groups,dc=x" for index in range(length)]
  return {dns[index]: [group(dns[index + 1], f"g{index}", index)] for index in range(length)}


@pytest.mark.parametrize("bound, value, groupsOf, reason", [
  ("maximumGroupSearches", 3, chain(3), "needs more than 3 searches"),
  ("maximumGroups", 2, {personDN: [group(f"cn=g{index},ou=groups,dc=x", f"g{index}", index) for index in range(3)]},
   "in more than 2 groups"),
  ("maximumGroupWalkSeconds", 0.0, chain(1), "did not finish within 0.0 seconds"),
])
def testTheOpenLDAPGroupWalkIsBounded(standInDirectory, tlsFiles, monkeypatch, bound, value, groupsOf, reason):
  monkeypatch.setattr(ldap, bound, value)
  directory, _ = openLDAPDirectory(standInDirectory, tlsFiles, groupsOf)
  with pytest.raises(DirectoryRefused, match=reason):
    directory.signIn("ana", "right")


def testTheOpenLDAPGroupWalkReadsUpToItsBounds(standInDirectory, tlsFiles, monkeypatch):
  monkeypatch.setattr(ldap, "maximumGroupSearches", 4)
  monkeypatch.setattr(ldap, "maximumGroups", 3)
  directory, _ = openLDAPDirectory(standInDirectory, tlsFiles, chain(3))
  assert directory.signIn("ana", "right").groups == ("g0", "g1", "g2")


# ---- against the testbed's Samba Active Directory --------------------------

def testEachKindOfDirectoryTakesItsOwnSettings():
  with pytest.raises(ValueError, match="needs groupsBaseDN"):
    Directory("directory.invalid", secureContext(), "dc=x", "cn=svc", "secret", kind=DirectoryKind.openLDAP)
  with pytest.raises(ValueError, match="Active Directory takes none"):
    Directory("directory.invalid", secureContext(), "DC=x", "svc", "secret", groupsBaseDN="ou=groups,DC=x")
  openLDAP = Directory("directory.invalid", secureContext(), "dc=x", "cn=svc", "secret", kind=DirectoryKind.openLDAP,
                       groupsBaseDN="ou=groups,dc=x")
  assert (openLDAP.userAttribute, Directory("directory.invalid", secureContext(), "DC=x", "svc", "s").userAttribute) == (
    "uid", "sAMAccountName")

@pytest.fixture(scope="module", params=["activeDirectory-ldaps", "activeDirectory-startTLS", "openLDAP-ldaps", "openLDAP-startTLS"])
def directory(request, testbed):
  kind, transport = request.param.split("-")
  startTLS = transport == "startTLS"
  if kind == "activeDirectory":
    if not request.config.getoption("--directory"):
      pytest.skip("directory test: run with --directory against a testbed whose Samba is running")
    settings = testbed["directory"]
    return Directory(settings["host"], secureContext(testbed["certificateAuthority"]), settings["baseDN"],
                     settings["serviceDN"], settings["servicePassword"],
                     port=settings["ldapPort"] if startTLS else settings["ldapsPort"], startTLS=startTLS)
  settings = testbed["openLDAP"]
  return Directory(settings["host"], secureContext(testbed["certificateAuthority"]), settings["baseDN"],
                   settings["serviceDN"], settings["servicePassword"],
                   port=settings["ldapPort"] if startTLS else settings["ldapsPort"], startTLS=startTLS,
                   kind=DirectoryKind.openLDAP, groupsBaseDN=settings["groupsBaseDN"])

def expectedGroups(paths):
  return tuple(sorted({segment for path in paths for segment in path.strip("/").split("/")}))


@pytest.mark.parametrize("userName", ["ana", "jose", "layla", "wei", "\u0645\u0631\u064a\u0645", "manygroups"])
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
