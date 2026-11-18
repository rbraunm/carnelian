# SPDX-License-Identifier: MIT
"""The testbed federation's MDQ service: GET /entities/<url-encoded entity ID> answers the signed metadata
prepare.py wrote for that entity (named by the SHA-256 of its entity ID), over HTTPS."""

import hashlib
import http.server
import ssl
import sys
import urllib.parse
from pathlib import Path

folder = Path(sys.argv[1])


class Handler(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    prefix = "/entities/"
    if not self.path.startswith(prefix):
      self.send_error(404)
      return
    entityID = urllib.parse.unquote(self.path[len(prefix):])
    document = folder / f"{hashlib.sha256(entityID.encode('utf-8')).hexdigest()}.xml"
    if not document.is_file():
      self.send_error(404)
      return
    body = document.read_bytes()
    self.send_response(200)
    self.send_header("Content-Type", "application/samlmetadata+xml")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


server = http.server.ThreadingHTTPServer(("0.0.0.0", 8444), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
