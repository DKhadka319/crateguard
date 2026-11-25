"""Tiny Cargo-style semver matcher (enough for RustSec ranges and Cargo.toml reqs).

Neo4j/Cypher has no semver functions, so version matching happens here in
Python and the results are stored as properties on the graph.
"""
import re

_V = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def parse(v):
    """'1.2.3-beta.1' -> (1, 2, 3, ('beta', 1)). Missing parts become None."""
    m = _V.match(v.strip())
    if not m:
        raise ValueError(v)
    major, minor, patch, pre = m.groups()
    return int(major), (int(minor) if minor else None), (int(patch) if patch else None), pre


def key(v):
    """Sort key for a full version string. A prerelease sorts before its release."""
    major, minor, patch, pre = parse(v)
    pre_key = (1,) if pre is None else (0,) + tuple(
        (0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (major, minor or 0, patch or 0, pre_key)


def is_prerelease(v):
    return parse(v)[3] is not None


def _bound(major, minor, patch, pre=None):
    return key(f"{major}.{minor or 0}.{patch or 0}" + (f"-{pre}" if pre else ""))


def _comparator(c):
    """One comparator -> (low, low_inclusive, high) with high exclusive; None = unbounded."""
    c = c.strip()
    m = re.match(r"^(\^|~|=|>=|<=|>|<)?\s*(.*)$", c)
    op, ver = m.group(1) or "^", m.group(2).strip()
    if ver in ("*", ""):
        return (None, True, None)
    ver = ver.replace(".*", "").replace(".x", "")
    if "*" in ver:
        op = "="
    major, minor, patch, pre = parse(ver)
    lo = _bound(major, minor, patch, pre)
    if op == "^":
        if major > 0 or minor is None:
            hi = (major + 1, 0, 0, (0,))
        elif minor > 0 or patch is None:
            hi = (0, minor + 1, 0, (0,))
        else:
            hi = (0, 0, patch + 1, (0,))
        return (lo, True, hi)
    if op == "~":
        hi = (major + 1, 0, 0, (0,)) if minor is None else (major, minor + 1, 0, (0,))
        return (lo, True, hi)
    if op == "=":
        if minor is None:
            return (lo, True, (major + 1, 0, 0, (0,)))
        if patch is None:
            return (lo, True, (major, minor + 1, 0, (0,)))
        return (lo, True, key(ver) + ("eq",))
    if op == ">=":
        return (lo, True, None)
    if op == ">":
        if minor is None:
            return ((major + 1, 0, 0, (0,)), True, None)
        if patch is None:
            return ((major, minor + 1, 0, (0,)), True, None)
        return (lo, False, None)
    if op == "<":
        return (None, True, (major, minor or 0, patch or 0, (0,)) if not pre else lo)
    if op == "<=":
        if minor is None:
            return (None, True, (major + 1, 0, 0, (0,)))
        if patch is None:
            return (None, True, (major, minor + 1, 0, (0,)))
        return (None, True, key(ver) + ("eq",))
    raise ValueError(c)


def matches(version, req):
    """True if `version` satisfies Cargo requirement `req` (comparators joined by commas)."""
    k = key(version)
    for c in req.split(","):
        lo, lo_inc, hi = _comparator(c)
        if lo is not None and (k < lo or (k == lo and not lo_inc)):
            return False
        if hi is not None:
            if len(hi) == 5:  # inclusive upper bound marker
                if k > hi[:4]:
                    return False
            elif k >= hi:
                return False
    return True


def matches_any(version, reqs):
    return any(matches(version, r) for r in reqs)


if __name__ == "__main__":
    t = [("1.2.3", "^1.2", True), ("2.0.0", "^1.2", False), ("0.3.0", "^0.2.3", False),
         ("0.2.9", "^0.2.3", True), ("0.10.71", ">= 0.10.39, < 0.10.72", True),
         ("0.10.72", ">= 0.10.39, < 0.10.72", False), ("1.3.0", "~1.2", False),
         ("1.2.9", "~1.2.3", True), ("0.4.20", "^0.4.2", True), ("5.0.0", "*", True),
         ("1.2.3", "=1.2.3", True), ("1.2.4", "=1.2.3", False), ("1.2.4", "<= 1.2", True),
         ("1.3.0", "<= 1.2", False), ("0.0.4", "^0.0.3", False), ("1.0.0", "1", True)]
    for v, r, want in t:
        assert matches(v, r) == want, (v, r, want)
    print("cargo_semver self-test: all", len(t), "cases pass")
