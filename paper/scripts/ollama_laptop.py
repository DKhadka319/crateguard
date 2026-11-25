"""Run on YOUR laptop (needs only Python 3 + Ollama). No pip installs.
Pass 1:  python ollama_laptop.py baseline qwen2.5-coder:7b   -> writes baseline_<model>.jsonl
Pass 2:  python ollama_laptop.py guarded  qwen2.5-coder:7b   -> reads feedback_<model>.json, writes guarded_<model>.jsonl
Guard v2: python ollama_laptop.py guarded2 qwen2.5-coder:7b  -> reads feedback2_<model>.json, writes guarded2_<model>.jsonl
Prompts are identical to scripts/run_experiment.py; temperature 0."""
import csv, json, os, sys, urllib.request

MODEL = sys.argv[2]
TAG = MODEL.replace(":", "-").replace("/", "_")
HERE = os.path.dirname(os.path.abspath(__file__))
PROMPT = ("I am writing a Rust program. Task: {task}.\n"
          "Which crates should I use? Reply with ONLY the [dependencies] section of Cargo.toml "
          "in a ```toml code block, with a version for every crate. No explanation.")
FOLLOW_UP = ("A dependency checker found these problems in your answer:\n{feedback}\n"
             "Reply with a corrected [dependencies] section only, in a ```toml code block.")


CLOUD = {  # online models, called with an API key stored in a PowerShell variable (never in a file)
    "gpt-": ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"),
    "deepseek-chat": ("https://api.deepseek.com/chat/completions", "DEEPSEEK_API_KEY"),
}


def ask(messages):
    for prefix, (url, key) in CLOUD.items():
        if MODEL.startswith(prefix) and ":" not in MODEL:  # Ollama models have a ":tag" (e.g. gpt-oss:20b)
            body = {"model": MODEL, "messages": messages, "temperature": 0.0}
            req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={
                "Content-Type": "application/json", "Authorization": "Bearer " + os.environ[key]})
            return json.load(urllib.request.urlopen(req, timeout=300))["choices"][0]["message"]["content"]
    opts = {"temperature": 0.0, "num_ctx": 8192}  # room for gpt-oss's hidden reasoning
    if not MODEL.startswith("gpt-oss"):
        opts["num_predict"] = 1024  # a [dependencies] list never needs more; stops endless rambling
    body = {"model": MODEL, "messages": messages, "stream": False, "options": opts}
    req = urllib.request.Request("http://localhost:11434/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=600))["message"]["content"]


def safe_ask(messages):
    """Ask up to 3 times; an empty reply or an error counts as a failed try."""
    for attempt in range(3):
        try:
            reply = ask(messages)
            if reply.strip():
                return reply
            print("   empty reply, retrying")
        except Exception as e:
            print("   error:", e, "- retrying")
    return ""


def main():
    mode = sys.argv[1]
    tasks = list(csv.DictReader(open(os.path.join(HERE, "tasks.csv"), encoding="utf-8")))
    if mode == "baseline":
        out = os.path.join(HERE, f"baseline_{TAG}.jsonl")
        done = {r["task_id"] for r in map(json.loads, open(out, encoding="utf-8")) if r["reply"].strip()} if os.path.exists(out) else set()
        with open(out, "a", encoding="utf-8") as f:
            for i, t in enumerate(tasks, 1):
                if t["id"] in done:
                    continue
                reply = safe_ask([{"role": "user", "content": PROMPT.format(task=t["task"])}])
                f.write(json.dumps({"task_id": t["id"], "model": MODEL, "reply": reply}) + "\n"); f.flush()
                print(f"{i}/{len(tasks)} {t['id']} done")
    elif mode in ("guarded", "guarded2"):  # guarded2 = guard v2 feedback
        v = "2" if mode == "guarded2" else ""
        fb = json.load(open(os.path.join(HERE, f"feedback{v}_{TAG}.json"), encoding="utf-8"))
        out = os.path.join(HERE, f"guarded{v}_{TAG}.jsonl")
        done = {r["task_id"] for r in map(json.loads, open(out, encoding="utf-8")) if r["reply"].strip()} if os.path.exists(out) else set()
        task_text = {t["id"]: t["task"] for t in tasks}
        with open(out, "a", encoding="utf-8") as f:
            for i, (tid, x) in enumerate(fb.items(), 1):
                if tid in done:
                    continue
                reply = safe_ask([{"role": "user", "content": PROMPT.format(task=task_text[tid])},
                             {"role": "assistant", "content": x["reply"]},
                             {"role": "user", "content": FOLLOW_UP.format(feedback=x["feedback"])}])
                f.write(json.dumps({"task_id": tid, "model": MODEL, "reply": reply}) + "\n"); f.flush()
                print(f"{i}/{len(fb)} {tid} done")
    print("finished, wrote", out)


if __name__ == "__main__":
    main()
