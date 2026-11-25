# Paper data and scripts

Everything needed to check or reproduce the numbers in the report
*"Do AI Coding Assistants Recommend Vulnerable Rust Libraries? Using a Neo4j Vulnerability Graph as a Guard."*

| Folder | Contents |
|---|---|
| `data/tasks.csv` | the 100 Rust programming tasks (10 categories x 10) |
| `data/mistake_memory.json` | mistake memory learned from guard v1 repairs |
| `runs/experiment/` | guard v1 runs: one JSONL per model, conditions `baseline` and `guarded` |
| `runs/experiment_v2/` | guard v2 runs: conditions `baseline`, `autofix_only`, `v2_repair`, `v2_final` |
| `results/` | `table_v1_v2.csv` (main table with Wilson 95% CIs and exact McNemar p values), `table1.csv`, `E1`–`E6.csv` (Neo4j query results), `fig1_serious_rate.png` |
| `cypher/` | graph schema, loading and the research queries (E1–E6) |
| `scripts/` | experiment, guard v1/v2, statistics and figure scripts |
| `neo4j_embedded/` | small Java launcher used to run Neo4j 5.26 without Docker |

Each JSONL line is one answer: task, model, condition, the raw reply, and the guard verdict for every crate.

## Reproduce the statistics

```bash
pip install neo4j networkx matplotlib cvss scipy statsmodels
python scripts/stats_all.py        # rebuilds results/table_v1_v2.csv from runs/
python scripts/make_figure.py      # rebuilds results/fig1_serious_rate.png
```

## Re-run the experiment

Models were queried with temperature 0: Gemini 3.5 Flash-Lite (Google API), GPT-4o-mini (OpenAI API), and
Llama 3.1 8B, DeepSeek Coder 6.7B, Qwen2.5 Coder 7B and gpt-oss 20B (local, through Ollama;
`scripts/ollama_laptop.py`). Model answers change over time and crates.io keeps publishing new versions,
so a re-run will give close but not identical numbers. Advisory data: RustSec advisory-db commit
`40f5be6fb12ed93fc591bf4ab23b7d793b3f2239` (2026-10-28). The scripts were written for the project's own
folder layout, so paths may need adjusting.
