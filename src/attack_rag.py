"""ATTACK-Analyst RAG pipeline: ingest documents, retrieve, call the model, show the sources.

    pip install chromadb requests
    python attack_rag.py ingest                      # build the document store (first time only)
    python attack_rag.py ask "your question"         # fine-tuned model + RAG
    python attack_rag.py ask "your question" --plain # same model, no retrieval (fine-tuned alone)
    python attack_rag.py compare                     # the 3 test questions through base / fine-tuned / fine-tuned + RAG

Needs Ollama running (https://ollama.com) with:  ollama pull nomic-embed-text
Keep this file next to attck_common.py and the data/ folder.
"""
import os, re, sys, json, argparse, urllib.request
import requests
from attck_common import SYSTEM_PROMPT, TECH_ID_RE, doc_name, render_technique, rag_user_message

OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = "nomic-embed-text"
SNAPSHOT = os.path.join("data", "attack_snapshot.json")
DOCS_DIR, DB_DIR = "docs", "rag_db"
TOP_K = 4                                    # how many document chunks go into the prompt
DEFAULT_BASE, DEFAULT_TUNED = "llama3.2:3b", "attack-analyst"

OWASP_RAW = "https://raw.githubusercontent.com/OWASP/www-project-top-10-for-large-language-model-applications/main/2_0_vulns/"
OWASP_FILES = [
    "LLM01_PromptInjection.md", "LLM02_SensitiveInformationDisclosure.md", "LLM03_SupplyChain.md",
    "LLM04_DataModelPoisoning.md", "LLM05_ImproperOutputHandling.md", "LLM06_ExcessiveAgency.md",
    "LLM07_SystemPromptLeakage.md", "LLM08_VectorAndEmbeddingWeaknesses.md", "LLM09_Misinformation.md",
    "LLM10_UnboundedConsumption.md",
]

# A fine-tune on one output format tends to force EVERY answer into that format. For OWASP documents we
# therefore use a plain prompt (the retrieval part is unchanged).
GENERAL_SYSTEM = ("You are a security analyst. Answer the question using only the REFERENCE DOCUMENTS provided. "
                  "Write a short plain-prose answer. Do not invent facts.")
GENERAL_SUFFIX = ("\n\nAnswer in plain prose using only the documents above (this is not a technique-brief question). "
                  "Finish with one line: Sources: <file names you used>")

QUESTIONS = [
    "I observed the following activity: a process opened lsass.exe and dumped its memory using comsvcs.dll "
    "MiniDump. What ATT&CK technique is this?",
    "Threat report excerpt:\n\nVolt Typhoon has selectively cleared Windows Event Logs, system logs, and other "
    "technical artifacts to remove evidence of intrusion activity.\n\nGive me the ATT&CK technique brief.",
    "What is OWASP LLM08:2025 and what are two ways to mitigate it?",
]


# ---------------------------------------------------------------------------
# Ollama helpers
# ---------------------------------------------------------------------------
def embed(texts, prefix):
    out = []
    for i in range(0, len(texts), 16):
        batch = [prefix + t[:6000] for t in texts[i:i + 16]]
        r = requests.post(f"{OLLAMA}/api/embed", json={"model": EMBED_MODEL, "input": batch}, timeout=600)
        if r.status_code != 200:
            sys.exit(f"Embedding failed ({r.status_code}): {r.text[:200]}\nIs Ollama running, and did you run: ollama pull {EMBED_MODEL}")
        out += r.json()["embeddings"]
    return out


def chat(model, user_text, system=SYSTEM_PROMPT):
    body = {"model": model, "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_text}],
            "options": {"temperature": 0.1, "top_p": 0.9, "num_ctx": 4096}}
    r = requests.post(f"{OLLAMA}/api/chat", json=body, timeout=900)
    if r.status_code != 200:
        sys.exit(f"Model call failed ({r.status_code}): {r.text[:200]}\nCheck the model name with: ollama list")
    return r.json()["message"]["content"].strip()


# ---------------------------------------------------------------------------
# Documents: ATT&CK techniques (one file each) and OWASP LLM Top 10 (split into sections)
# ---------------------------------------------------------------------------
def attack_docs():
    snap = json.load(open(SNAPSHOT, encoding="utf-8"))
    os.makedirs(os.path.join(DOCS_DIR, "attack"), exist_ok=True)
    for t in snap["techniques"]:
        text = render_technique(t)
        open(os.path.join(DOCS_DIR, "attack", doc_name(t["id"])), "w", encoding="utf-8").write(text)
        extra = "\n".join(f"More observed use: {p}" for p in t["procedures"][2:])   # helps search; not shown to the model
        yield {"id": f"attack:{t['id']}", "source": doc_name(t["id"]), "tag": t["id"], "text": text, "index": text + "\n" + extra}


def owasp_chunks(fname, text, limit=1700):
    title = text.splitlines()[0].lstrip("# ").strip()                 # e.g. "LLM08:2025 Vector and Embedding Weaknesses"
    tag = fname.split("_")[0]                                           # "LLM08"
    sections = re.split(r"\n(?=### )", text)
    n = 0
    for sec in sections[1:]:
        head = sec.splitlines()[0].lstrip("# ").strip()
        if head.lower().startswith(("reference links", "related frameworks")):
            continue
        parts = [p.strip() for p in re.split(r"\n(?=#### )", sec.split("\n", 1)[1] if "\n" in sec else "") if p.strip()]
        buf = ""
        for p in parts + [None]:
            if p is None or (buf and len(buf) + len(p) > limit):
                if buf:
                    n += 1
                    body = f"OWASP Top 10 for LLM Applications 2025 | {title} | Section: {head}\n{buf}"
                    yield {"id": f"owasp:{tag}:{n}", "source": fname, "tag": tag, "text": body, "index": body}
                buf = ""
            if p is not None:
                buf = f"{buf}\n\n{p}".strip()


def owasp_docs():
    os.makedirs(os.path.join(DOCS_DIR, "owasp"), exist_ok=True)
    for f in OWASP_FILES:
        path = os.path.join(DOCS_DIR, "owasp", f)
        if not os.path.exists(path):
            print(f"  downloading {f}")
            req = urllib.request.Request(OWASP_RAW + f, headers={"User-Agent": "Mozilla/5.0 (attck-rag)"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                open(path, "wb").write(resp.read())
        yield from owasp_chunks(f, open(path, encoding="utf-8").read())


def get_collection(create=False):
    import chromadb
    client = chromadb.PersistentClient(path=DB_DIR)
    if create:
        try:
            client.delete_collection("attack_kb")
        except Exception:
            pass
        return client.create_collection("attack_kb", metadata={"hnsw:space": "cosine"})
    return client.get_collection("attack_kb")


def ingest():
    items = list(attack_docs()) + list(owasp_docs())
    n_att = sum(i["id"].startswith("attack:") for i in items)
    print(f"Embedding {len(items)} chunks ({n_att} ATT&CK technique documents, {len(items) - n_att} OWASP LLM Top 10 sections) ...")
    col = get_collection(create=True)
    for i in range(0, len(items), 64):
        b = items[i:i + 64]
        col.add(ids=[x["id"] for x in b], documents=[x["text"] for x in b],
                embeddings=embed([x["index"] for x in b], "search_document: "),
                metadatas=[{"source": x["source"], "tag": x["tag"]} for x in b])
        print(f"  {min(i + 64, len(items))}/{len(items)}")
    print(f"Done. Document store: {DB_DIR}/   Source files: {DOCS_DIR}/")


# ---------------------------------------------------------------------------
# Retrieval: exact-ID lookup first (T1059.001, LLM08), then semantic search to fill the rest
# ---------------------------------------------------------------------------
def retrieve(question, col, k=TOP_K):
    hits, seen = [], set()

    def add(cid, text, source, how, dist=None):
        if cid not in seen and len(hits) < k:
            seen.add(cid)
            hits.append({"id": cid, "text": text, "source": source, "how": how, "dist": dist})

    qv = embed([question], "search_query: ")[0]
    for tid in dict.fromkeys(t.upper() for t in TECH_ID_RE.findall(question)):
        got = col.get(ids=[f"attack:{tid}"])
        if got["ids"]:
            add(got["ids"][0], got["documents"][0], got["metadatas"][0]["source"], f"exact ID {tid}")
    for num in dict.fromkeys(re.findall(r"LLM\s?-?(\d{2})", question, re.I)):
        r = col.query(query_embeddings=[qv], n_results=2, where={"tag": f"LLM{num}"})
        for cid, doc, meta, d in zip(r["ids"][0], r["documents"][0], r["metadatas"][0], r["distances"][0]):
            add(cid, doc, meta["source"], f"exact ID LLM{num}", d)
    r = col.query(query_embeddings=[qv], n_results=k)
    for cid, doc, meta, d in zip(r["ids"][0], r["documents"][0], r["metadatas"][0], r["distances"][0]):
        add(cid, doc, meta["source"], "semantic search", d)
    return hits


def grounding_check(answer, hits):
    """Deterministic check (no model involved): are the cited files and the IDs in the answer present in what was retrieved?"""
    retrieved = {h["source"] for h in hits}
    cited = set(re.findall(r"[\w.\-]+\.(?:txt|md)", answer))
    corpus = "\n".join(h["text"] for h in hits) + "\n" + "\n".join(h["source"] for h in hits)
    ids = set(TECH_ID_RE.findall(answer)) | set(re.findall(r"LLM\d{2}", answer)) | set(re.findall(r"\bM\d{4}\b", answer))
    bad_src, bad_ids = sorted(cited - retrieved), sorted(i for i in ids if i not in corpus)
    if not cited:
        return "WARNING: the answer cites no source file"
    if bad_src or bad_ids:
        return f"WARNING: not in the retrieved documents -> sources {bad_src or '-'}, IDs {bad_ids or '-'}"
    return f"OK: cited {sorted(cited)}; all IDs appear in the retrieved documents"


def rag_answer(model, question, show=True):
    col = get_collection()
    hits = retrieve(question, col)
    if show:
        print("RETRIEVAL (top matches sent to the model):")
        for h in hits:
            d = "" if h["dist"] is None else f"  distance {h['dist']:.3f}"
            print(f"  - {h['source']:42s} via {h['how']}{d}")
    docs = [(h["source"], h["text"]) for h in hits]
    general = sum(h["source"].endswith(".md") for h in hits) * 2 >= len(hits)      # mostly OWASP documents
    prompt = rag_user_message(question, docs) + (GENERAL_SUFFIX if general else "")
    if show:
        print(f"MODEL CALL: {model}  | {len(hits)} chunks, {len(prompt)} characters of prompt | "
              f"prompt style: {'plain prose (OWASP documents)' if general else 'ATT&CK analyst'}")
    answer = chat(model, prompt, GENERAL_SYSTEM if general else SYSTEM_PROMPT)
    return answer, hits


def divider(title):
    print("\n" + "=" * 88 + f"\n{title}\n" + "=" * 88)


def cmd_ask(a):
    divider(f"QUESTION\n{a.question}")
    if a.plain:
        print(f"[{a.model}, no retrieval]\n" + chat(a.model, a.question))
        return
    answer, hits = rag_answer(a.model, a.question)
    print("\nANSWER:\n" + answer)
    print("\nGROUNDING CHECK: " + grounding_check(answer, hits))


def cmd_compare(a):
    for n, q in enumerate(QUESTIONS, 1):
        if a.only and a.only != n:
            continue
        divider(f"QUESTION {n}\n{q}")
        print(f"\n--- 1) BASE model, no retrieval  [{a.base}]\n{chat(a.base, q)}")
        print(f"\n--- 2) FINE-TUNED model, no retrieval  [{a.tuned}]\n{chat(a.tuned, q)}")
        print(f"\n--- 3) FINE-TUNED model + RAG  [{a.tuned}]")
        answer, hits = rag_answer(a.tuned, q)
        print("\n" + answer + "\n\nGROUNDING CHECK: " + grounding_check(answer, hits))


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ingest")
    p = sub.add_parser("ask"); p.add_argument("question"); p.add_argument("--model", default=DEFAULT_TUNED); p.add_argument("--plain", action="store_true")
    p = sub.add_parser("compare"); p.add_argument("--base", default=DEFAULT_BASE); p.add_argument("--tuned", default=DEFAULT_TUNED); p.add_argument("--only", type=int)
    a = ap.parse_args()
    {"ingest": lambda: ingest(), "ask": lambda: cmd_ask(a), "compare": lambda: cmd_compare(a)}[a.cmd]()


if __name__ == "__main__":
    main()
