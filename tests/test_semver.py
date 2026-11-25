import pytest
from crateguard.semver import matches

CASES = [("1.2.3", "^1.2", True), ("2.0.0", "^1.2", False), ("0.3.0", "^0.2.3", False),
         ("0.2.9", "^0.2.3", True), ("0.10.71", ">= 0.10.39, < 0.10.72", True),
         ("0.10.72", ">= 0.10.39, < 0.10.72", False), ("1.3.0", "~1.2", False),
         ("1.2.9", "~1.2.3", True), ("0.4.20", "^0.4.2", True), ("5.0.0", "*", True),
         ("1.2.3", "=1.2.3", True), ("1.2.4", "=1.2.3", False), ("1.2.4", "<= 1.2", True),
         ("1.3.0", "<= 1.2", False), ("0.0.4", "^0.0.3", False), ("1.0.0", "1", True)]


@pytest.mark.parametrize("version,req,want", CASES)
def test_matches(version, req, want):
    assert matches(version, req) == want
