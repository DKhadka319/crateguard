# crateguard

**Check and repair the Rust dependencies that AI coding assistants suggest.**

AI assistants often write `[dependencies]` blocks that name crates that do not exist, versions that were
never published, or versions with known security vulnerabilities. `crateguard` checks every dependency
against the live [crates.io](https://crates.io) index and a [Neo4j](https://neo4j.com) graph of
[RustSec](https://rustsec.org) advisories, explains what is wrong, tells the AI (or you) exactly what to use
instead, and can repair the `Cargo.toml` for you.

It comes from the research project *"Do AI Coding Assistants Recommend Vulnerable Rust Libraries? Using a
Neo4j Vulnerability Graph as a Guard"* (CSCI 5304, 2026). On 100 Rust tasks and six AI models, this guard
cut the share of answers with a serious problem from **5–61%** to **0–6%** (see [Results](#results)).

```
$ crateguard check Cargo.toml
HALLUCINATED    serde_xml_rs = "0.6"  fix: serde-xml-rs = "0.8.2"
HALLUCINATED    neo4j-driver = "0.3"  fix: neo4j = "0.2.0"
HALLUCINATED    fancy-quantum-json = "0.2"
VULNERABLE      zip = "0.6" -> installs 0.6.6  [RUSTSEC-2026-0367 (High), RUSTSEC-2026-0369 (Critical), ...]  fix: zip = "9.8.2"
VULNERABLE      time = "0.1" -> installs 0.1.45  [RUSTSEC-2020-0071 (Medium)]  fix: time = "0.3.55"
VULNERABLE      rsa = "0.9" -> installs 0.9.10  [RUSTSEC-2023-0071 (Medium)]
OLD_FLOOR       tokio = "1" -> installs 1.54.1  [RUSTSEC-2021-0072, ...]  fix: tokio = "1.54.1"
OK              serde = "1.0" -> installs 1.0.229

8 of 9 dependencies need attention (7 serious).
```

## What it checks

| Verdict | Meaning | Serious |
|---|---|---|
| `HALLUCINATED` | the crate is not on crates.io | yes |
| `NO_SUCH_VERSION` | no published, non-yanked release matches the version requirement | yes |
| `VULNERABLE` | the version Cargo would install today is inside a RustSec vulnerability range | yes |
| `OLD_FLOOR` | today's install is fine, but the requirement still allows vulnerable releases | no |
| `UNMAINTAINED` | RustSec marks the installed version unmaintained or unsound | no |
| `OK` | none of the above | no |

Version requirements are matched with Cargo's own rules (`^`, `~`, `=`, `*`, ranges, pre-releases).

## Install

```bash
pip install git+https://github.com/DKhadka319/crateguard
```

You also need a Neo4j 5 database. The easiest way is Docker:

```bash
docker compose up -d                       # uses docker-compose.yml from this repo
export CRATEGUARD_NEO4J_PASSWORD=crateguard
crateguard load                            # loads the bundled RustSec snapshot (1,336 advisories)
crateguard load --latest                   # or: download today's advisory database from GitHub
```

Neo4j Desktop or Aura work too: set `CRATEGUARD_NEO4J_URI`, `CRATEGUARD_NEO4J_USER` and
`CRATEGUARD_NEO4J_PASSWORD` (or pass `--uri`, `--user`, `--password`).

## Use it

```bash
crateguard check Cargo.toml                 # report; exit code 1 if anything is serious (use it in CI)
crateguard check --dep serde=1 --dep rand=0.8
crateguard check answer.txt                 # an AI reply with a ```toml block works too
crateguard check Cargo.toml --json          # machine-readable output

crateguard fix Cargo.toml                   # show a diff of the repair
crateguard fix Cargo.toml --write           # apply it (comments, features and layout are kept)

crateguard feedback answer.txt              # warnings to paste back into the AI chat
```

`fix` updates unsafe versions to the newest release with no known vulnerability, corrects invented names
when it knows the real one, and comments out invented crates it cannot correct. A real crate whose every
release is vulnerable is left alone and reported, because only you can choose a replacement.

### Feedback for an AI assistant

The research found that telling the AI only *what* is wrong barely helps, while telling it *what to use
instead* works. `crateguard feedback` produces exactly that:

```
- `serde_xml_rs` does not exist on crates.io. Use `serde-xml-rs = "0.8.2"` instead.
- `time = "0.1"` installs 0.1.45, which has known vulnerabilities (RUSTSEC-2020-0071). Use `time = "0.3.55"` instead.
```

### Shared mistake memory

AI models repeat the same invented names (`serde_xml_rs`, `neo4j-driver`, ...). crateguard keeps a
**mistake memory** in the graph, `(:Mistake)-[:CORRECTED_TO]->(:Crate)`, and uses it to suggest the real
crate. You can teach it and share what it learned:

```bash
crateguard memory add neo4j-driver neo4j
crateguard memory export memory.json        # share this file, e.g. in a pull request to this repo
crateguard memory import memory.json
```

Contributions to `crateguard/data/mistake_memory.json` are welcome.

### As a Python library

```python
from crateguard import Graph, Checker, feedback, serious

g = Graph("bolt://localhost:7687", "neo4j", "crateguard")
ck = Checker(g)
results = ck.check_all([("time", "0.1"), ("serde_xml_rs", "0.6")])
print(feedback(results))
assert not serious(results)
```

### In CI (GitHub Actions)

```yaml
- run: pip install git+https://github.com/DKhadka319/crateguard
- run: crateguard load
- run: crateguard check Cargo.toml
```
(with a `neo4j:5` service container; see `docker-compose.yml` for the settings).

## Results

From the paper (100 tasks per model; number of tasks whose answer had a serious problem):

| Model | No guard | Guard v1 (warnings) | Guard v2 (warnings + fix) | v2 + auto-fix |
|---|---:|---:|---:|---:|
| Llama 3.1 8B | 61 | 49 | 11 | 5 |
| DeepSeek Coder 6.7B | 43 | 24 | 10 | 6 |
| Qwen2.5 Coder 7B | 31 | 26 | 4 | 1 |
| gpt-oss 20B | 30 | 23 | 8 | 6 |
| GPT-4o-mini | 21 | 20 | 8 | 1 |
| Gemini 3.5 Flash-Lite | 5 | 2 | 1 | 0 |

Guard v2 was significantly better than no guard for five of six models (exact McNemar test, p < 0.02).
The data, scripts and figures to reproduce this are in [`paper/`](paper/).

## How it works

```
Cargo.toml / AI reply ──► parse deps ──► crates.io sparse index ──► does it exist? which version installs?
                                     └─► Neo4j: (:Advisory)-[:AFFECTS]->(:Crate)  ──► vulnerable? safe version?
                                     └─► Neo4j: (:Mistake)-[:CORRECTED_TO]->(:Crate) ──► real name?
                                                       ▼
                                   verdicts ─► report / feedback text / repaired Cargo.toml
```

crates.io index entries are cached in `~/.cache/crateguard` for 24 hours (`--offline` uses only the cache).
The bundled advisory snapshot is RustSec advisory-db commit `40f5be6` (2026-10-28); run
`crateguard load --latest` for newer advisories.

## Development

```bash
pip install -e ".[test,severity]"
pytest                                    # no network or Neo4j needed
```

## Citation

If you use crateguard or its data, please cite it (see [`CITATION.cff`](CITATION.cff)):

> D. Khadka, "Do AI Coding Assistants Recommend Vulnerable Rust Libraries? Using a Neo4j Vulnerability
> Graph as a Guard," CSCI 5304 Research Project Report, 2026. Software: https://github.com/DKhadka319/crateguard

## License

MIT. Advisory data comes from the [RustSec advisory database](https://github.com/rustsec/advisory-db)
(CC0-1.0).
