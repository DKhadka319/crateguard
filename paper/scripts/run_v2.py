"""Guard v2 experiment, driven from the v1 result files in output/experiment/.
  python scripts/run_v2.py feedback   -> laptop/runs/feedback2_<tag>.json for every model (2-fold mistake memory)
  python scripts/run_v2.py gemini     -> asks Gemini for its v2 repairs directly (needs GEMINI_API_KEY)
  python scripts/run_v2.py final      -> output/experiment_v2/<model>.jsonl with conditions
        baseline, autofix_only (guard rewrites, no AI), v2_repair (AI after v2 feedback), v2_final (v2_repair + autofix)
Mistake memory is learned from v1 runs on the OTHER half of the tasks (odd vs even task numbers), so no task
benefits from its own mistakes."""
import glob, json, os, sys
from neo4j import GraphDatabase
sys.path.insert(0, os.path.dirname(__file__))
import guard, guard_v2 as g2
from run_experiment import parse_deps, ask, PROMPT, ROOT

def tag(model): return model.replace(":", "-").replace("/", "_")
def fold(tid): return int(tid[1:]) % 2

def v1_runs():
    runs = {}
    for f in sorted(glob.glob(os.path.join(ROOT, "output", "experiment", "*.jsonl"))):
        rows = [json.loads(l) for l in open(f)]
        runs[rows[0]["model"]] = rows
    return runs

def memories(runs):
    """memory[k] is learned only from tasks in fold 1-k, used for tasks in fold k."""
    mem = {}
    for k in (0, 1):
        pairs = []
        for rows in runs.values():
            b = {r["task_id"]: r for r in rows if r["condition"] == "baseline" and fold(r["task_id"]) != k}
            g = {r["task_id"]: r for r in rows if r["condition"] == "guarded" and fold(r["task_id"]) != k}
            pairs += [(b[t]["results"], g[t]["results"]) for t in b]
        mem[k] = g2.learn(pairs)
    return mem

def check(s, reply):
    deps = parse_deps(reply) if reply and reply.strip() else None
    return deps, [guard.check(s, n, r) for n, r in (deps or [])]

def main():
    mode = sys.argv[1]
    runs = v1_runs(); mem = memories(runs)
    with GraphDatabase.driver("neo4j://localhost:7687", auth=None) as d, d.session() as s:
        full = g2.learn([(b["results"], g["results"]) for rows in runs.values()
                         for b, g in zip([r for r in rows if r["condition"] == "baseline"],
                                         [r for r in rows if r["condition"] == "guarded"])])
        print("mistake memory (all tasks, for sharing):", g2.save_memory(s, full), len(full["names"]), "names")
        for model, rows in runs.items():
            base = {r["task_id"]: r for r in rows if r["condition"] == "baseline"}
            fbf = os.path.join(ROOT, "laptop", "runs", f"feedback2_{tag(model)}.json")
            if mode == "feedback":
                fb = {t: {"reply": r["reply"], "feedback": g2.feedback(s, r["results"], mem[fold(t)])}
                      for t, r in base.items() if r["parsed"] and r["results"] and guard.feedback(r["results"])}
                json.dump(fb, open(fbf, "w"), indent=1); print(model, len(fb), "tasks get v2 feedback")
            elif mode == "gemini" and model.startswith("gemini"):
                fb = json.load(open(fbf)); out = os.path.join(ROOT, "laptop", "runs", f"guarded2_{tag(model)}.jsonl")
                with open(out, "w") as f:
                    for t, x in fb.items():
                        msgs = [{"role": "user", "content": PROMPT.format(task=base[t]["task"])},
                                {"role": "assistant", "content": x["reply"]},
                                {"role": "user", "content": __import__("run_experiment").FOLLOW_UP.format(feedback=x["feedback"])}]
                        f.write(json.dumps({"task_id": t, "model": model, "reply": ask("gemini", model, msgs, 0.0)}) + "\n")
                print("wrote", out)
            elif mode == "final":
                gf = os.path.join(ROOT, "laptop", "runs", f"guarded2_{tag(model)}.jsonl")
                rep = {}
                if not os.path.exists(gf):
                    print("no v2 replies yet (autofix_only still computed):", model); gf = os.devnull
                for r in map(json.loads, open(gf)):
                    if r["reply"].strip() or r["task_id"] not in rep: rep[r["task_id"]] = r["reply"]
                os.makedirs(os.path.join(ROOT, "output", "experiment_v2"), exist_ok=True)
                out = os.path.join(ROOT, "output", "experiment_v2", f"{tag(model)}.jsonl")
                with open(out, "w") as f:
                    for t, b in base.items():
                        meta = {k: b[k] for k in ("task_id", "category", "task", "provider", "model")}
                        f.write(json.dumps({**meta, "condition": "baseline", "parsed": b["parsed"], "results": b["results"]}) + "\n")
                        # autofix only: the guard repairs the baseline itself, no AI involved
                        if b["parsed"] and b["results"]:
                            txt, rm = g2.autofix(s, b["results"], mem[fold(t)]); _, res = check(s, txt)
                            f.write(json.dumps({**meta, "condition": "autofix_only", "reply": txt, "parsed": True, "results": res, "removed": rm}) + "\n")
                        else:
                            f.write(json.dumps({**meta, "condition": "autofix_only", "reply": "", "parsed": False, "results": [], "removed": []}) + "\n")
                        # v2: AI repair after v2 feedback, re-checked, then autofix for whatever is left
                        reply = rep.get(t, b["reply"])
                        deps, res = check(s, reply) if t in rep else (b["parsed"], b["results"])
                        parsed = deps is not None if t in rep else b["parsed"]
                        f.write(json.dumps({**meta, "condition": "v2_repair", "reply": reply, "parsed": parsed, "results": res}) + "\n")
                        if parsed and res and any(x["verdict"] in g2.SERIOUS | {"OLD_FLOOR"} for x in res):
                            txt, rm = g2.autofix(s, res, mem[fold(t)]); _, res2 = check(s, txt)
                            f.write(json.dumps({**meta, "condition": "v2_final", "reply": txt, "parsed": True, "results": res2, "removed": rm}) + "\n")
                        else:
                            f.write(json.dumps({**meta, "condition": "v2_final", "reply": reply, "parsed": parsed, "results": res, "removed": []}) + "\n")
                print("wrote", out)

if __name__ == "__main__":
    main()
