# SPDX-License-Identifier: MIT
"""The testbed option: integration tests run against real identity providers named in testbed.json."""

import json
from pathlib import Path

import pytest


def pytest_addoption(parser):
  parser.addoption("--testbed", help="testbed.json written by testbed/prepare.py; integration tests need it")
  parser.addoption("--directory", action="store_true", help="the testbed's Samba directory is running too")
  parser.addoption("--live", action="store_true", help="also check real federations' published metadata over the internet")


def pytest_collection_modifyitems(items):
  # Keycloak refuses some logins as expired codes when one realm's sign-ins run at once; and eduGAIN's
  # aggregate, fetched once per worker, is fetched once only when its tests share a worker.
  for item in items:
    fixtures = set(getattr(item, "fixturenames", ()))
    if "testbed" in fixtures:
      item.add_marker(pytest.mark.xdist_group("identityProviders"))
    elif "eduGAIN" in fixtures:
      item.add_marker(pytest.mark.xdist_group("eduGAIN"))


@pytest.fixture(scope="session")
def testbed(request):
  path = request.config.getoption("--testbed")
  if path is None:
    pytest.skip("integration test: run with --testbed testbed/generated/testbed.json against a running testbed")
  return json.loads(Path(path).read_text(encoding="utf-8"))
