"""Cloud side of the two-pass Ollama run (laptop/ollama_laptop.py does the AI calls).
  python scripts/ollama_bridge.py feedback laptop/baseline_<tag>.jsonl         -> laptop/feedback_<tag>.json
  python scripts/ollama_bridge.py merge laptop/baseline_<tag>.jsonl laptop/guarded_<tag>.jsonl
      -> output/experiment/ollama-<model>-<date>.jsonl  (same format as run_experiment.py)"""
import csv, datetime, json, os, sys
from neo4j import GraphDatabase
sys.path.insert(0, os.path.dirname(__file__))
import guard
from run_experiment import parse_deps, ROOT

def load(p):
    return {r["task_id"]: r for r in map(json.loads, open(p, encoding="utf-8"))}

def check(s, reply):
    deps = parse_deps(reply) if reply.strip() else None  # empty reply = no usable answer
    return deps, [guard.check(s, n, r) for n, r in (deps or [])]

def main():
    mode = sys.argv[1]
    base = load(sys.argv[2])
    with GraphDatabase.driver("neo4j://localhost:7687", auth=None) as d, d.session() as s:
        if mode == "feedback":
            fb = {}
            for tid, r in base.items():
                _, res = check(s, r["reply"])
                problems = guard.feedback(res)
                if problems:
                    fb[tid] = {"reply": r["reply"], "feedback": problems}
            out = os.path.join(os.path.dirname(sys.argv[2]), os.path.basename(sys.argv[2]).replace("baseline_", "feedback_").replace(".jsonl", ".json"))
            json.dump(fb, open(out, "w", encoding="utf-8"), indent=1)
            print(f"{len(fb)} of {len(base)} answers need a guarded retry; wrote {out}")
            return
        guarded = load(sys.argv[3])
        tasks = list(csv.DictReader(open(os.path.join(ROOT, "data", "experiment", "tasks.csv"))))
        model = next(iter(base.values()))["model"]
        prov = "openai" if model.startswith("gpt-") and ":" not in model else "ollama"
        out = os.path.join(ROOT, "output", "experiment",
                           f"{prov}-{model.replace(':', '-')}-{datetime.datetime.now():%Y%m%d-%H%M}.jsonl")
        with open(out, "w") as f:
            for t in tasks:
                b = base[t["id"]]
                meta = {"task_id": t["id"], "category": t["category"], "task": t["task"], "provider": prov, "model": model}
                deps, res = check(s, b["reply"])
                f.write(json.dumps({**meta, "condition": "baseline", "reply": b["reply"], "parsed": deps is not None, "results": res}) + "\n")
                if not guard.feedback(res):
                    f.write(json.dumps({**meta, "condition": "guarded", "reply": b["reply"], "parsed": deps is not None,
                                        "results": res, "unchanged": True}) + "\n")
                else:
                    g = guarded[t["id"]]["reply"]
                    deps, res = check(s, g)
                    f.write(json.dumps({**meta, "condition": "guarded", "reply": g, "parsed": deps is not None, "results": res}) + "\n")
        print("wrote", out)

if __name__ == "__main__":
    main()
