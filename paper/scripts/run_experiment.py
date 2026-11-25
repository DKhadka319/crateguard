"""The topic A experiment: ask AI assistants to pick Rust dependencies, then check them with the guard.

For every task in data/experiment/tasks.csv and every model:
  baseline  ask the model for the [dependencies] of Cargo.toml, check every crate with the guard
  guarded   if the guard found a problem, send its warnings back and ask for a corrected answer,
            then check again (this measures whether the Neo4j guard fixes the problem)

Results go to output/experiment/<run>.jsonl (one line per answer). load_experiment.py puts
them into Neo4j and cypher/04_experiment_queries.cypher measures them.

Providers (API keys come from environment variables, never from this file):
  openai     OPENAI_API_KEY      --model e.g. the GPT model you have access to
  anthropic  ANTHROPIC_API_KEY   --model e.g. claude-sonnet-5-5
  gemini     GEMINI_API_KEY      --model e.g. the Gemini model you have access to
  ollama     (local, free)       --model e.g. llama3.1, qwen2.5-coder
  replay     no AI at all: reads answers from a JSONL file (--replay FILE), for testing the pipeline

Example:
  export ANTHROPIC_API_KEY=...
  python scripts/run_experiment.py --provider anthropic --model claude-sonnet-5-5 --limit 10
"""
import argparse, csv, datetime, json, os, re, tomllib, urllib.request
from neo4j import GraphDatabase
import guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROMPT = ("I am writing a Rust program. Task: {task}.\n"
          "Which crates should I use? Reply with ONLY the [dependencies] section of Cargo.toml "
          "in a ```toml code block, with a version for every crate. No explanation.")
FOLLOW_UP = ("A dependency checker found these problems in your answer:\n{feedback}\n"
             "Reply with a corrected [dependencies] section only, in a ```toml code block.")


def post(url, body, headers):
    import time, urllib.error
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers})
    for attempt in range(6):  # retry busy/rate-limited APIs (429/5xx, timeouts)
        try:
            return json.load(urllib.request.urlopen(req, timeout=180))
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == 5:
                raise
        except TimeoutError:
            if attempt == 5:
                raise
        time.sleep(10 * 2 ** attempt)


def ask(provider, model, messages, temperature, replay=None):
    """messages = [{"role": "user"|"assistant", "content": str}] -> reply text."""
    if provider == "replay":
        return replay.pop(0)
    if provider == "openai":
        r = post("https://api.openai.com/v1/chat/completions",
                 {"model": model, "messages": messages, "temperature": temperature},
                 {"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]})
        return r["choices"][0]["message"]["content"]
    if provider == "anthropic":
        r = post("https://api.anthropic.com/v1/messages",
                 {"model": model, "max_tokens": 1024, "messages": messages, "temperature": temperature},
                 {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"})
        return "".join(b.get("text", "") for b in r["content"])
    if provider == "gemini":
        contents = [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
                    for m in messages]
        r = post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                 {"contents": contents, "generationConfig": {"temperature": temperature}},
                 {"x-goog-api-key": os.environ["GEMINI_API_KEY"]})
        return "".join(p.get("text", "") for p in r["candidates"][0]["content"]["parts"])
    if provider == "ollama":
        r = post("http://localhost:11434/api/chat",
                 {"model": model, "messages": messages, "stream": False, "options": {"temperature": temperature}}, {})
        return r["message"]["content"]
    raise ValueError(provider)


def parse_deps(reply):
    """Pull [dependencies] out of a model reply. Returns [(name, req)] or None if unparseable."""
    m = re.search(r"```(?:toml)?\s*\n(.*?)```", reply, re.S)
    text = m.group(1) if m else reply
    if "[dependencies]" not in text:
        text = "[dependencies]\n" + text
    try:
        return guard.deps_from_cargo_toml(text)
    except tomllib.TOMLDecodeError:
        return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--provider", required=True, choices=["openai", "anthropic", "gemini", "ollama", "replay"])
    p.add_argument("--model", required=True)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--limit", type=int, default=None, help="only the first N tasks (for a pilot run)")
    p.add_argument("--replay", help="JSONL of canned replies, for --provider replay")
    p.add_argument("--out", default=None)
    p.add_argument("--uri", default="neo4j://localhost:7687")
    p.add_argument("--user", default="neo4j")
    p.add_argument("--password", default="")
    a = p.parse_args()

    tasks = list(csv.DictReader(open(os.path.join(ROOT, "data", "experiment", "tasks.csv"))))[:a.limit]
    replay = [json.loads(l)["reply"] for l in open(a.replay)] if a.replay else None
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    out = a.out or os.path.join(ROOT, "output", "experiment", f"{a.provider}-{a.model.replace('/', '_')}-{stamp}.jsonl")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    auth = (a.user, a.password) if a.password else None
    with GraphDatabase.driver(a.uri, auth=auth) as drv, drv.session() as s, open(out, "w") as f:
        for t in tasks:
            messages = [{"role": "user", "content": PROMPT.format(task=t["task"])}]
            for condition in ("baseline", "guarded"):
                reply = ask(a.provider, a.model, messages, a.temperature, replay)
                deps = parse_deps(reply)
                results = [guard.check(s, n, r) for n, r in (deps or [])]
                f.write(json.dumps({"task_id": t["id"], "category": t["category"], "task": t["task"],
                                    "provider": a.provider, "model": a.model, "condition": condition,
                                    "reply": reply, "parsed": deps is not None, "results": results}) + "\n")
                problems = guard.feedback(results)
                verdicts = ", ".join(r["verdict"] for r in results if r["verdict"] != "OK") or "all OK"
                print(f"{t['id']} {condition:8s} {len(results)} deps: {verdicts}")
                if condition == "baseline":
                    if not problems:
                        # nothing for the guard to fix: the guarded answer is the same answer
                        f.write(json.dumps({**json.loads(json.dumps({"task_id": t["id"], "category": t["category"],
                                "task": t["task"], "provider": a.provider, "model": a.model})),
                                "condition": "guarded", "reply": reply, "parsed": deps is not None,
                                "results": results, "unchanged": True}) + "\n")
                        break
                    messages += [{"role": "assistant", "content": reply},
                                 {"role": "user", "content": FOLLOW_UP.format(feedback=problems)}]
    print("wrote", out)


if __name__ == "__main__":
    main()
