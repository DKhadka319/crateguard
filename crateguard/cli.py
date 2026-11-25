"""Command line interface.

  crateguard load                     load the bundled RustSec snapshot (+ mistake memory) into Neo4j
  crateguard load --latest            download today's advisory-db from GitHub and load it
  crateguard load --advisory-db DIR   load a local advisory-db checkout
  crateguard check Cargo.toml         report problems (exit code 1 if anything serious)
  crateguard check --dep serde=1 --dep made-up=0.1
  crateguard fix Cargo.toml [--write] repair versions and names (prints a diff, or writes the file)
  crateguard feedback answer.txt      warnings to send back to an AI assistant (reads an AI reply or Cargo.toml)
  crateguard memory add WRONG RIGHT   teach the shared mistake memory; `memory export FILE` / `memory import FILE`
Neo4j connection: --uri/--user/--password or CRATEGUARD_NEO4J_URI / _USER / _PASSWORD.
"""
import argparse, difflib, json, os, sys
from importlib import resources
from . import __version__, advisories, cargo_toml
from .checker import Checker, feedback, serious, RANK
from .graph import Graph

COLOR = {"HALLUCINATED": "31", "NO_SUCH_VERSION": "31", "VULNERABLE": "31", "OLD_FLOOR": "33", "UNMAINTAINED": "33", "OK": "32"}


def _read(path):
    return sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()


def _deps(a):
    if a.dep:
        return [tuple(d.split("=", 1)) if "=" in d else (d, "*") for d in a.dep], None
    text = cargo_toml.extract(_read(a.file))
    return cargo_toml.dependencies(text), text


def _print(results, use_color):
    for r in sorted(results, key=lambda r: RANK.index(r["verdict"])):
        v = r["verdict"]
        tag = f"\033[{COLOR[v]}m{v:15s}\033[0m" if use_color else f"{v:15s}"
        line = f"{tag} {r['crate']} = \"{r['req']}\""
        if r["installs"]:
            line += f" -> installs {r['installs']}"
        if r["advisories"]:
            line += "  [" + ", ".join(f"{x['id']} ({x['severity']})" for x in r["advisories"]) + "]"
        if r["fix"] and r["fix"]["req"]:
            line += f"  fix: {r['fix']['crate']} = \"{r['fix']['req']}\""
        print(line)
    bad = [r for r in results if r["verdict"] != "OK"]
    print(f"\n{len(bad)} of {len(results)} dependencies need attention ({len(serious(results))} serious).")


def main(argv=None):
    try:
        return _main(argv)
    except RuntimeError as e:
        print(f"crateguard: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        if type(e).__name__ in ("ServiceUnavailable", "AuthError"):
            print(f"crateguard: cannot reach Neo4j ({e}). Start it with `docker compose up -d`, then set "
                  "CRATEGUARD_NEO4J_URI / CRATEGUARD_NEO4J_PASSWORD.", file=sys.stderr)
            return 2
        raise


def _main(argv=None):
    p = argparse.ArgumentParser(prog="crateguard", description="Check and repair Rust dependencies against RustSec, using Neo4j.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--uri"); p.add_argument("--user"); p.add_argument("--password"); p.add_argument("--database")
    p.add_argument("--offline", action="store_true", help="use only the cached crates.io index")
    sp = p.add_subparsers(dest="cmd", required=True)
    l = sp.add_parser("load"); l.add_argument("--latest", action="store_true"); l.add_argument("--advisory-db"); l.add_argument("--wipe", action="store_true")
    for name in ("check", "fix", "feedback"):
        c = sp.add_parser(name); c.add_argument("file", nargs="?", default="Cargo.toml"); c.add_argument("--dep", action="append")
        c.add_argument("--json", action="store_true")
        if name == "fix":
            c.add_argument("--write", action="store_true")
    m = sp.add_parser("memory"); m.add_argument("action", choices=["add", "list", "export", "import"]); m.add_argument("args", nargs="*")
    a = p.parse_args(argv)

    g = Graph(a.uri, a.user, a.password, a.database)
    try:
        if a.cmd == "load":
            if a.latest:
                advs = advisories.download_latest()
            elif a.advisory_db:
                advs = advisories.from_dir(a.advisory_db)
            else:
                advs = json.loads(resources.files("crateguard.data").joinpath("advisories.json").read_text())
            print("loaded:", g.load_advisories(advs, wipe=a.wipe))
            mem = json.loads(resources.files("crateguard.data").joinpath("mistake_memory.json").read_text())
            g.remember(mem["names"])
            print("mistake memory:", len(g.memory()), "entries")
            return 0
        if a.cmd == "memory":
            if a.action == "add":
                g.remember({a.args[0]: a.args[1]})
            elif a.action == "import":
                g.remember(json.load(open(a.args[0]))["names"])
            elif a.action == "export":
                g.export_memory(a.args[0])
            for w, r in sorted(g.memory().items()):
                print(f"{w} -> {r}")
            return 0
        ck = Checker(g, offline=a.offline)
        deps, text = _deps(a)
        results = ck.check_all(deps)
        if a.cmd == "check":
            print(json.dumps(results, indent=1)) if a.json else _print(results, sys.stdout.isatty())
            return 1 if serious(results) else 0
        if a.cmd == "feedback":
            print(json.dumps({"feedback": feedback(results), "results": results}, indent=1) if a.json else feedback(results))
            return 1 if serious(results) else 0
        # fix
        fixes, stuck = {}, []
        for r in results:
            if r["verdict"] not in ("HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE", "OLD_FLOOR"):
                continue
            if r["fix"] and r["fix"]["req"]:
                fixes[r["crate"]] = r["fix"]
            elif r["verdict"] == "HALLUCINATED":
                fixes[r["crate"]] = {"crate": None, "req": None}  # invented crate: comment it out
            else:
                stuck.append(r["crate"])  # real crate, but no safe release exists
        if text is None:
            text = "[dependencies]\n" + "".join(f'{n} = "{r}"\n' for n, r in deps)
        new = cargo_toml.rewrite(text, fixes)
        if a.write and a.file != "-":
            open(a.file, "w", encoding="utf-8").write(new)
            print(f"wrote {a.file}: {len(fixes)} dependencies changed")
        else:
            sys.stdout.writelines(difflib.unified_diff(text.splitlines(True), new.splitlines(True), "before", "after"))
        removed = [c for c, f in fixes.items() if f["crate"] is None]
        if removed:
            print("\nRemoved (no real crate found, choose one yourself): " + ", ".join(removed), file=sys.stderr)
        if stuck:
            print("Not changed (every release has a known vulnerability, consider another crate): " + ", ".join(stuck), file=sys.stderr)
        return 0
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
