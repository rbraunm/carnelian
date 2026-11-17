# SPDX-License-Identifier: MIT
"""The testbed option: integration tests run against real identity providers named in testbed.json."""

import json
from pathlib import Path

import pytest


def pytest_addoption(parser):
  parser.addoption("--testbed", help="testbed.json written by testbed/prepare.py; integration tests need it")


@pytest.fixture(scope="session")
def testbed(request):
  path = request.config.getoption("--testbed")
  if path is None:
    pytest.skip("integration test: run with --testbed testbed/generated/testbed.json against a running testbed")
  return json.loads(Path(path).read_text(encoding="utf-8"))
