# SPDX-License-Identifier: MIT
"""The HTTPS fetcher against a local TLS server that answers with scripted bytes."""

import datetime
import gc
import socket
import ssl
import threading
import time
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from carnelian.fetching import Fetcher, HTTPFailure, parseJSON, secureContext


def _certificate(subject, issuer, publicKey, signingKey, isAuthority, issuerKey):
  start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
  builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(publicKey)
             .serial_number(x509.random_serial_number()).not_valid_before(start)
             .not_valid_after(start + datetime.timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=isAuthority, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(publicKey), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuerKey), critical=False))
  if isAuthority:
    builder = builder.add_extension(x509.KeyUsage(
      digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
      key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
  else:
    builder = (builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
  return builder.sign(signingKey, hashes.SHA256())


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
  folder = tmp_path_factory.mktemp("tls")
  authorityKey, serverKey = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
  authorityName = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test authority")])
  serverName = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
  authority = _certificate(authorityName, authorityName, authorityKey.public_key(), authorityKey, True, authorityKey.public_key())
  server = _certificate(serverName, authorityName, serverKey.public_key(), authorityKey, False, authorityKey.public_key())
  (folder / "authority.pem").write_bytes(authority.public_bytes(serialization.Encoding.PEM))
  (folder / "server.pem").write_bytes(server.public_bytes(serialization.Encoding.PEM))
  (folder / "server.key").write_bytes(serverKey.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
  return folder


@pytest.fixture
def serve(certificates):
  """Starts a server that runs `script` on each TLS connection after reading the request; returns its port."""
  listeners = []

  def start(script):
    serverContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    serverContext.load_cert_chain(certificates / "server.pem", certificates / "server.key")
    listener = socket.create_server(("::", 0), family=socket.AF_INET6, dualstack_ipv6=True)
    listeners.append(listener)

    def run():
      while True:
        try:
          connection, _ = listener.accept()
        except OSError:
          return
        try:
          with serverContext.wrap_socket(connection, server_side=True) as tls:
            request = b""
            while b"\r\n\r\n" not in request:
              chunk = tls.recv(4096)
              if not chunk:
                break
              request += chunk
            script(tls)
        except OSError:
          pass

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]

  yield start
  for listener in listeners:
    listener.close()


def answer(status, body, extra=b""):
  return lambda tls: tls.sendall(b"HTTP/1.1 %d X\r\nContent-Length: %d\r\n%s\r\n" % (status, len(body), extra) + body)


def fetcher(certificates, **options):
  return Fetcher(secureContext(str(certificates / "authority.pem")), **options)


def testAJSONObjectIsFetched(certificates, serve):
  port = serve(answer(200, b'{"issuer": "https://id.example.org", "n": 1.5}'))
  assert fetcher(certificates).getJSON(f"https://localhost:{port}/x") == {"issuer": "https://id.example.org", "n": 1.5}


def testAContextWithoutChecksIsRefusedWhenTheFetcherIsMade():
  noHostnames = secureContext()
  noHostnames.check_hostname = False
  with pytest.raises(HTTPFailure, match="does not check hostnames"):
    Fetcher(noHostnames)
  optional = secureContext()
  optional.verify_mode = ssl.CERT_OPTIONAL
  with pytest.raises(HTTPFailure, match="not CERT_REQUIRED"):
    Fetcher(optional)


def testAContextWhoseChecksAreTurnedOffLaterIsRefusedBeforeTheRequest(certificates, serve):
  port = serve(answer(200, b"{}"))
  context = ssl.create_default_context()
  made = Fetcher(context)
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  with pytest.raises(HTTPFailure, match="does not check hostnames"):
    made.getJSON(f"https://localhost:{port}/x")


def testACertificateForAnotherNameIsRefused(certificates, serve):
  port = serve(answer(200, b"{}"))
  with pytest.raises(HTTPFailure, match="CERTIFICATE_VERIFY_FAILED"):
    fetcher(certificates).getJSON(f"https://127.0.0.1:{port}/x")


@pytest.mark.parametrize("status", [206, 302])
def testOnlyA200AnswerIsAccepted(certificates, serve, status):
  port = serve(answer(status, b"{}"))
  with pytest.raises(HTTPFailure, match=f"answered {status}"):
    fetcher(certificates).getBytes(f"https://localhost:{port}/metadata", "application/xml")
  with pytest.raises(HTTPFailure, match=f"answered {status}"):
    fetcher(certificates).getJSON(f"https://localhost:{port}/x")


def testAnAnswerOverTheSizeLimitIsRefused(certificates, serve):
  port = serve(answer(200, b'{"a": "' + b"x" * 200 + b'"}'))
  with pytest.raises(HTTPFailure, match="more than 100 bytes"):
    fetcher(certificates, maximumBytes=100).getJSON(f"https://localhost:{port}/x")


@pytest.mark.parametrize("body", [b'{"exp": NaN}', b'{"exp": -Infinity}', b'{"exp": 1e999}', b"[" * 100_000, b"<html>"])
def testJSONThatIsNotStrictlyJSONIsRefusedByName(certificates, serve, body):
  port = serve(answer(200, body))
  with pytest.raises(HTTPFailure, match="not JSON"):
    fetcher(certificates).getJSON(f"https://localhost:{port}/x")


def shortThenClosedCleanly(tls):
  tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}")
  tls.settimeout(1)
  tls.unwrap()


@pytest.mark.parametrize("script, message", [
  (lambda tls: tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}"), "SSLEOFError"),
  (shortThenClosedCleanly, "fewer bytes than its Content-Length"),
  (lambda tls: tls.sendall(b"not http at all\r\n\r\n"), "BadStatusLine"),
  (lambda tls: tls.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"), "IncompleteRead"),
], ids=["short", "shortClosedCleanly", "statusLine", "chunk"])
def testBrokenFramingIsAnHTTPFailure(certificates, serve, script, message):
  port = serve(script)
  with pytest.raises(HTTPFailure, match=message):
    fetcher(certificates).getJSON(f"https://localhost:{port}/x")


def testASlowPeerCannotHoldARequestPastItsDeadline(certificates, serve):
  def trickle(tls):
    tls.sendall(b"HTTP/1.1 200 OK\r\n")
    for _ in range(100):
      tls.sendall(b"X-Slow: 1\r\n")
      time.sleep(0.05)

  port = serve(trickle)
  started = time.monotonic()
  with pytest.raises(HTTPFailure, match="deadline"):
    fetcher(certificates, timeoutSeconds=1.0).getJSON(f"https://localhost:{port}/x")
  assert time.monotonic() - started < 2.0


def testOnlyHTTPSIsFetched(certificates):
  with pytest.raises(HTTPFailure, match="only https is fetched"):
    fetcher(certificates).getJSON("http://localhost/x")


def testStrictJSONKeepsOrdinaryNumbers():
  assert parseJSON('{"a": 1, "b": 2.5, "c": -1e3}') == {"a": 1, "b": 2.5, "c": -1000.0}
  with pytest.raises(ValueError, match="Infinity is not a JSON number"):
    parseJSON('{"a": Infinity}')


def headersThenLaterTheBody(tls):
  body = b"<EntityDescriptor/>" * 200
  tls.sendall(b"HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n" % len(body))
  time.sleep(0.3)
  tls.sendall(body)


def testABodyThatComesAfterTheHeadersOfAClosingAnswerIsRead(certificates, serve):
  port = serve(headersThenLaterTheBody)
  assert fetcher(certificates).getBytes(f"https://localhost:{port}/entities/x", "application/samlmetadata+xml") == (
    b"<EntityDescriptor/>" * 200)


def testAnErrorNamesTheURLWithoutItsQueryValues(certificates, serve):
  port = serve(answer(200, b"{}"))
  with pytest.raises(HTTPFailure) as refused:
    fetcher(certificates).getBytes(
      f"https://someone:hunter2@127.0.0.1:{port}/validate?ticket=ST-secret&service=https%3A%2F%2Fapp#part", "application/xml")
  assert str(refused.value).startswith(f"https://127.0.0.1:{port}/validate?ticket=...&service=...: SSLCertVerificationError")
  assert "ST-secret" not in str(refused.value) and "hunter2" not in str(refused.value)


def testResolvingTheNameIsWithinTheDeadline(certificates, serve, monkeypatch):
  port = serve(answer(200, b"{}"))
  resolve = socket.getaddrinfo

  def slowResolver(*arguments, **options):
    time.sleep(3)
    return resolve(*arguments, **options)

  monkeypatch.setattr(socket, "getaddrinfo", slowResolver)
  started = time.monotonic()
  with pytest.raises(HTTPFailure, match="ran past the request's deadline of 0.5 seconds"):
    fetcher(certificates, timeoutSeconds=0.5).getJSON(f"https://localhost:{port}/x")
  assert time.monotonic() - started < 1.0


def testEveryAddressIsTriedWithinTheOneDeadline(certificates, monkeypatch):
  closed = socket.create_server(("127.0.0.1", 0))
  port = closed.getsockname()[1]
  closed.close()
  monkeypatch.setattr(socket, "getaddrinfo", lambda *arguments, **options: [
    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))] * 3)
  started = time.monotonic()
  with pytest.raises(HTTPFailure):
    fetcher(certificates, timeoutSeconds=1.0).getJSON(f"https://localhost:{port}/x")
  assert time.monotonic() - started < 1.5


def testTheSocketIsClosedWhenTheHandshakeFails(certificates, serve):
  port = serve(answer(200, b"{}"))
  with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always", ResourceWarning)
    with pytest.raises(HTTPFailure, match="CERTIFICATE_VERIFY_FAILED"):
      fetcher(certificates).getJSON(f"https://127.0.0.1:{port}/x")
    gc.collect()
  assert [str(warning.message) for warning in caught if issubclass(warning.category, ResourceWarning)] == []


streamed = b"<EntityDescriptor/>" * 20_000


def testADocumentIsStreamedInChunksUnderItsOwnSizeLimit(certificates, serve):
  port = serve(answer(200, streamed))
  chunks = list(fetcher(certificates, maximumBytes=100).streamBytes(f"https://localhost:{port}/x", "application/xml", len(streamed)))
  assert b"".join(chunks) == streamed
  assert len(chunks) > 1 and max(len(chunk) for chunk in chunks) <= 65536


def testAStreamIsCutOffAsSoonAsItPassesItsSizeLimit(certificates, serve):
  port = serve(answer(200, streamed))
  received = []
  with pytest.raises(HTTPFailure, match=f"more than {len(streamed) - 1} bytes"):
    for chunk in fetcher(certificates).streamBytes(f"https://localhost:{port}/x", "application/xml", len(streamed) - 1):
      received.append(chunk)
  assert sum(len(chunk) for chunk in received) <= len(streamed) - 1


@pytest.mark.parametrize("script, message", [
  (answer(404, b"gone"), "answered 404, not 200"),
  (shortThenClosedCleanly, "fewer bytes than its Content-Length"),
  (lambda tls: tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}"), "SSLEOFError"),
], ids=["status", "shortClosedCleanly", "short"])
def testAStreamThatIsNotAWhole200AnswerIsRefused(certificates, serve, script, message):
  port = serve(script)
  with pytest.raises(HTTPFailure, match=message):
    for _ in fetcher(certificates).streamBytes(f"https://localhost:{port}/x?code=c-secret", "application/xml", 1000):
      pass


def testAStreamEndsAtTheRequestsDeadline(certificates, serve):
  def trickle(tls):
    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
    for _ in range(100):
      tls.sendall(b"x")
      time.sleep(0.05)

  port = serve(trickle)
  started = time.monotonic()
  received = []
  with pytest.raises(HTTPFailure, match="ran past the request's deadline of 1.0 seconds"):
    for chunk in fetcher(certificates, timeoutSeconds=1.0).streamBytes(f"https://localhost:{port}/x", "application/xml", 1000):
      received.append(chunk)
  assert time.monotonic() - started < 2.0 and 0 < sum(len(chunk) for chunk in received) < 100
