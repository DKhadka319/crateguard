"""Checker logic with a fake graph and a fake crates.io index (no network, no Neo4j)."""
import pytest
from crateguard import checker, index

RELEASES = {
    "openssl": ["0.10.30", "0.10.55", "0.10.70", "0.10.72"],
    "time": ["0.1.43", "0.1.45", "0.2.27", "0.3.36"],
    "serde-xml-rs": ["0.6.0", "0.8.1"],
    "neo4j": ["0.1.0", "0.2.0"],
    "fresh": ["1.0.0", "1.1.0"],
}
ADVS = {
    "openssl": [{"id": "RUSTSEC-2025-0004", "kind": "vulnerability", "title": "x", "severity": "High",
                 "patched": [">= 0.10.70"], "unaffected": []}],
    "time": [{"id": "RUSTSEC-2020-0071", "kind": "vulnerability", "title": "segfault", "severity": "Medium",
              "patched": [">= 0.2.23"], "unaffected": ["= 0.2.0", "= 0.2.1", "= 0.2.2", "= 0.2.3",
                                                    "= 0.2.4", "= 0.2.5", "= 0.2.6"]}],
    "fresh": [{"id": "RUSTSEC-2099-0001", "kind": "unmaintained", "title": "old", "severity": "Unknown",
               "patched": [], "unaffected": ["< 1.1.0"]}],
}


class FakeGraph:
    def memory(self):
        return {"neo4j-driver": "neo4j"}

    def advisories(self, name):
        return ADVS.get(name, [])


@pytest.fixture
def ck(monkeypatch):
    fake = lambda name, offline=False: ([{"num": v, "yanked": False} for v in RELEASES[name]]
                                        if name in RELEASES else None)
    monkeypatch.setattr(index, "releases", fake)
    return checker.Checker(FakeGraph())


def test_verdicts(ck):
    v = {r["crate"]: r for r in ck.check_all([("openssl", "=0.10.55"), ("openssl", "0.10"),
                                                ("time", "0.1"), ("time", "9"), ("fresh", "1"),
                                                ("serde_xml_rs", "0.6"), ("neo4j-driver", "1")])}
    assert ck.check("openssl", "=0.10.55")["verdict"] == "VULNERABLE"
    assert ck.check("openssl", "0.10")["verdict"] == "OLD_FLOOR"
    assert ck.check("time", "0.1")["verdict"] == "VULNERABLE"
    assert ck.check("time", "9")["verdict"] == "NO_SUCH_VERSION"
    assert ck.check("fresh", "1")["verdict"] == "UNMAINTAINED"
    assert ck.check("fresh", "=1.0.0")["verdict"] == "OK"
    assert v["serde_xml_rs"]["verdict"] == "HALLUCINATED"


def test_fixes(ck):
    assert ck.check("openssl", "=0.10.55")["fix"] == {"crate": "openssl", "req": "0.10.72"}
    assert ck.check("time", "0.1")["fix"] == {"crate": "time", "req": "0.3.36"}
    assert ck.check("serde_xml_rs", "0.6")["fix"] == {"crate": "serde-xml-rs", "req": "0.8.1"}  # spelling
    assert ck.check("neo4j-driver", "1")["fix"] == {"crate": "neo4j", "req": "0.2.0"}           # memory
    assert ck.check("totally-made-up", "1")["fix"] is None


def test_feedback_text(ck):
    res = [ck.check("serde_xml_rs", "0.6"), ck.check("time", "0.1")]
    fb = checker.feedback(res)
    assert "does not exist on crates.io" in fb and 'Use `serde-xml-rs = "0.8.1"`' in fb
    assert "RUSTSEC-2020-0071" in fb
    assert len(checker.serious(res)) == 2
