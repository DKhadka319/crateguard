"""Read releases from the crates.io sparse index (https://index.crates.io), with a local cache."""
import json, os, time, urllib.error, urllib.parse, urllib.request

UA = "crateguard (https://github.com/DKhadka319/crateguard)"
CACHE = os.environ.get("CRATEGUARD_CACHE", os.path.join(os.path.expanduser("~"), ".cache", "crateguard", "index"))
MAX_AGE = 24 * 3600  # re-download index entries older than a day


def index_path(name):
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def releases(name, offline=False):
    """[{'num': '1.2.3', 'yanked': False}, ...] or None if the crate does not exist."""
    os.makedirs(CACHE, exist_ok=True)
    cache = os.path.join(CACHE, urllib.parse.quote(name.lower(), safe="") + ".json")
    if os.path.exists(cache) and (offline or time.time() - os.path.getmtime(cache) < MAX_AGE):
        return json.load(open(cache))
    if offline:
        raise RuntimeError(f"--offline: `{name}` is not in the local cache ({CACHE})")
    try:
        req = urllib.request.Request("https://index.crates.io/" + index_path(name), headers={"User-Agent": UA})
        lines = urllib.request.urlopen(req, timeout=30).read().decode().splitlines()
        data = [{"num": e["vers"], "yanked": e["yanked"]} for e in map(json.loads, filter(None, lines))]
    except urllib.error.HTTPError as e:
        if e.code not in (403, 404):
            raise
        data = None
    json.dump(data, open(cache, "w"))
    return data
