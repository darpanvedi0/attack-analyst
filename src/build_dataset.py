"""Build the ATTACK-Analyst fine-tuning dataset from MITRE ATT&CK.

    python src/build_dataset.py

Downloads MITRE ATT&CK Enterprise once (about 50 MB), keeps a slim copy in data/attack_snapshot.json, and builds
chat-format training conversations from techniques created up to 2023-12-31 ONLY. Techniques created after that date
are held out on purpose: the model never sees them, so only RAG can supply them later.

Writes (all under data/):
    attack_snapshot.json   slim copy of ATT&CK (the RAG store is built from this too)
    train.jsonl            full file, keeps the type/technique labels
    train_studio.jsonl     messages only, the file to upload into Unsloth Studio
    heldout_ids.json       IDs of the held-out techniques

Standard library only. Run it from the repository root.
"""
import os, json, re, hashlib, random, collections, urllib.request
from attck_common import (SYSTEM_PROMPT, TECH_ID_RE, doc_name, clean_text, tactic_label, first_sentence,
                          mitigation_text, render_technique, rag_user_message)

ATTACK_URLS = [
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
]
SNAPSHOT = os.path.join("data", "attack_snapshot.json")  # saved on first run so every later item uses the SAME data
CUTOFF = "2023-12-31"  # techniques created AFTER this date are NEVER shown to the model in training
#                        (Llama 3.2's own knowledge ends about the same time, so these are new to it too)


# ----------------------------------------------------------------------------
# 0) Download ATT&CK once and keep a slim copy (only the fields we use).
# ----------------------------------------------------------------------------
def slim(bundle):
    objs = bundle["objects"]
    by = {o["id"]: o for o in objs}
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")

    def ext_id(o):
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"]

    techs = {o["id"]: o for o in objs if o["type"] == "attack-pattern" and live(o) and ext_id(o)}
    parent_of, mits, detect, procs = {}, collections.defaultdict(list), {}, collections.defaultdict(list)
    for r in objs:
        if r["type"] != "relationship" or not live(r) or r["target_ref"] not in techs:
            continue
        src, tgt, kind = by.get(r["source_ref"]), r["target_ref"], r["relationship_type"]
        if src is None or not live(src):
            continue
        if kind == "subtechnique-of":
            parent_of[r["source_ref"]] = tgt
        elif kind == "mitigates" and src["type"] == "course-of-action":
            how = clean_text(r.get("description", ""))
            mits[tgt].append({"id": ext_id(src), "name": src["name"], "how": how if len(how) <= 150 else how[:150].rsplit(" ", 1)[0] + "..."})
        elif kind == "detects" and src["type"] == "x-mitre-detection-strategy":
            detect[tgt] = src["name"]
        elif kind == "uses" and src["type"] in ("intrusion-set", "malware", "tool", "campaign"):
            t = clean_text(r.get("description", ""))
            if 50 <= len(t) <= 320 and not TECH_ID_RE.search(t):
                procs[tgt].append(t)

    out = []
    for oid, o in techs.items():
        parent = techs.get(parent_of.get(oid)) if oid in parent_of else None
        desc = clean_text(o.get("description", ""))
        plist = sorted(set(procs[oid]), key=lambda s: hashlib.md5(s.encode()).hexdigest())[:6]  # stable, unbiased pick
        out.append({
            "id": ext_id(o), "name": o["name"],
            "tactics": [tactic_label(p["phase_name"]) for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            "platforms": o.get("x_mitre_platforms", []),
            "parent_id": ext_id(parent) if parent else "", "parent_name": parent["name"] if parent else "",
            "created": o["created"][:10], "description": desc, "summary": first_sentence(desc),
            "mitigations": sorted(mits[oid], key=lambda m: m["id"]),
            "detection": detect.get(oid, ""), "procedures": plist,
        })
    coll = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    return {"source": "MITRE ATT&CK Enterprise", "version": coll.get("x_mitre_version", "unknown"),
            "techniques": sorted(out, key=lambda t: t["id"])}


def load_snapshot():
    if os.path.exists(SNAPSHOT):
        print(f"Using saved snapshot: {SNAPSHOT}")
        return json.load(open(SNAPSHOT, encoding="utf-8"))
    last_err = None
    for url in ATTACK_URLS:
        try:
            print(f"Downloading ATT&CK (about 50 MB, one time only) from {url} ...")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (attck-specialist-notebook)"})
            with urllib.request.urlopen(req, timeout=180) as resp:
                bundle = json.load(resp)
            snap = slim(bundle)
            os.makedirs(os.path.dirname(SNAPSHOT), exist_ok=True)
            json.dump(snap, open(SNAPSHOT, "w", encoding="utf-8"))
            print(f"Saved slim snapshot {SNAPSHOT} ({os.path.getsize(SNAPSHOT) / 1024:.0f} KiB)")
            return snap
        except Exception as e:  # try the next mirror
            last_err = e
            print(f"  could not use {url}: {e}")
    raise RuntimeError(f"Could not download ATT&CK ({last_err}). Download enterprise-attack.json from "
                       f"github.com/mitre-attack/attack-stix-data and re-run.")


snap = load_snapshot()
techs = snap["techniques"]
by_id = {t["id"]: t for t in techs}
train_recs = [t for t in techs if t["created"] <= CUTOFF]
held_recs = [t for t in techs if t["created"] > CUTOFF]
HELD_IDS = {t["id"] for t in held_recs}
assert all(t["parent_id"] not in HELD_IDS for t in train_recs), "a training sub-technique has a held-out parent"
name_counts = collections.Counter(t["name"] for t in techs)
ALL_TACTICS = sorted({x for t in train_recs for x in t["tactics"]})
ALL_PLATFORMS = sorted({x for t in train_recs for x in t["platforms"]})
by_tactic = collections.defaultdict(list)
for t in train_recs:
    for x in t["tactics"]:
        by_tactic[x].append(t)

rng = random.Random(3407)  # fixed seed: the same dataset every time you run this cell


# ----------------------------------------------------------------------------
# 1) The "technique brief": the specialist's signature output format.
#    Every line comes straight from an ATT&CK field. Nothing is invented.
# ----------------------------------------------------------------------------
def brief(r):
    head = f"{r['name']} (sub-technique of {r['parent_id']} {r['parent_name']})" if r["parent_id"] else r["name"]
    return (
        f"ATT&CK TECHNIQUE BRIEF: {r['id']}\n"
        f"Technique: {head}\n"
        f"Tactic: {', '.join(r['tactics']) or 'not listed'}\n"
        f"Platforms: {', '.join(r['platforms']) or 'not listed'}\n"
        f"Summary: {r['summary']}\n"
        f"Mitigations: {mitigation_text(r['mitigations'])}\n"
        f"Detection: {r['detection'] or 'no detection strategy listed'}\n"
        f"Added to ATT&CK: {r['created']}"
    )


BEHAVIOR_Q = [
    "Which ATT&CK technique matches this behavior?\n\n{b}",
    "I observed the following activity:\n\n{b}\n\nWhat ATT&CK technique is this?",
    "Map this to MITRE ATT&CK:\n\n{b}",
    "Threat report excerpt:\n\n{b}\n\nGive me the ATT&CK technique brief.",
]
ID_Q = [
    "Give me an ATT&CK technique brief for {id}.",
    "What is ATT&CK {id}? I need a quick brief.",
    "Brief me on {id} from MITRE ATT&CK.",
]
NAME_Q = [
    "Give me the ATT&CK technique brief for {name}.",
    "Brief me on the ATT&CK technique '{name}'.",
    "What does MITRE ATT&CK say about {name}?",
]


def brief_question(r, pool=None):
    """Returns (question, behavior_text_or_None). The question can name the ID, the name, or describe a behavior."""
    pool = r["procedures"] if pool is None else pool
    kinds, weights = ["id"], [0.35]
    if pool:
        kinds.append("behavior"); weights.append(0.50)
    if name_counts[r["name"]] == 1:
        kinds.append("name"); weights.append(0.15)
    k = rng.choices(kinds, weights)[0]
    if k == "behavior":
        b = rng.choice(pool)
        return rng.choice(BEHAVIOR_Q).format(b=b), b
    if k == "name":
        return rng.choice(NAME_Q).format(name=r["name"]), None
    return rng.choice(ID_Q).format(id=r["id"]), None


# ----------------------------------------------------------------------------
# 2) Short single-fact answers.
# ----------------------------------------------------------------------------
def fact_qa(r):
    kinds = ["tactic", "platforms", "id", "mitigations"] + (["parent"] if r["parent_id"] else [])
    weights = [0.25, 0.20, 0.20, 0.20] + ([0.15] if r["parent_id"] else [])
    kind = rng.choices(kinds, weights)[0]
    if kind == "id" and name_counts[r["name"]] != 1:
        kind = "tactic"
    tid, name = r["id"], r["name"]
    if kind == "tactic":
        q = rng.choice([f"Which ATT&CK tactic does {tid} ({name}) fall under?", f"What tactic is {name} ({tid}) in?"])
        a = f"{tid} ({name}) is listed under the {' and '.join(r['tactics'])} tactic."
    elif kind == "platforms":
        q = rng.choice([f"Which platforms does {tid} apply to?", f"What platforms does ATT&CK list for {name} ({tid})?"])
        a = (f"ATT&CK lists {tid} ({name}) for: {', '.join(r['platforms'])}." if r["platforms"]
             else f"ATT&CK does not list platforms for {tid} ({name}).")
    elif kind == "id":
        q = rng.choice([f"What is the ATT&CK ID for {name}?", f"Which ATT&CK technique ID is '{name}'?"])
        a = f"{name} is {tid}" + (f", a sub-technique of {r['parent_id']} ({r['parent_name']})." if r["parent_id"] else ".")
    elif kind == "mitigations":
        q = rng.choice([f"What mitigations does ATT&CK list for {tid}?", f"How do I mitigate {name} ({tid}) according to ATT&CK?"])
        a = f"ATT&CK lists these mitigations for {tid} ({name}): {mitigation_text(r['mitigations'])}." if r["mitigations"] \
            else f"ATT&CK lists no mitigations for {tid} ({name})."
    else:
        q = rng.choice([f"Which technique is {tid} a sub-technique of?", f"What is the parent technique of {name} ({tid})?"])
        a = f"{tid} ({name}) is a sub-technique of {r['parent_id']} ({r['parent_name']})."
    return q, a


# ----------------------------------------------------------------------------
# 3) Open-book (RAG-style) examples: the documents are IN the prompt, the answer
#    must come from them and must cite the source file. This is what lets the
#    fine-tuned model be used inside a RAG pipeline later.
#    40% use a counterfactual copy of the record (changed tactic / platform /
#    mitigations) so the model learns to READ the document instead of recalling it.
# ----------------------------------------------------------------------------
def perturb(r):
    r = dict(r)
    changes = ["tactics", "platforms"] + (["mitigations"] if r["mitigations"] else [])
    for change in rng.sample(changes, k=min(len(changes), rng.choice([1, 2]))):
        if change == "tactics":
            r["tactics"] = [rng.choice([x for x in ALL_TACTICS if x not in r["tactics"]])]
        elif change == "platforms":
            cur = set(r["platforms"])
            if len(cur) >= 2 and rng.random() < 0.5:
                cur.discard(rng.choice(sorted(cur)))
            else:
                cur.add(rng.choice([p for p in ALL_PLATFORMS if p not in cur]))
            r["platforms"] = sorted(cur)
        else:
            r["mitigations"] = r["mitigations"][1:]
    return r


def pick_distractors(r, n):
    same = [x for x in by_tactic[r["tactics"][0]] if x["id"] != r["id"]] if r["tactics"] else []
    pool = same if (len(same) >= n and rng.random() < 0.5) else train_recs
    out = []
    while len(out) < n:
        x = rng.choice(pool)
        if x["id"] != r["id"] and all(x["id"] != y["id"] for y in out):
            out.append(x)
    return out


def msgs(user, assistant):
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant}]


def open_book_example(r):
    rec = perturb(r) if rng.random() < 0.40 else r
    recs = [rec] + pick_distractors(r, rng.choice([3, 4]) - 1)
    rng.shuffle(recs)
    docs = [(doc_name(x["id"]), render_technique(x)) for x in recs]
    shown = set(rec["procedures"][:2])                      # these two appear in the document text
    fresh = [p for p in rec["procedures"] if p not in shown] or rec["procedures"]
    roll = rng.random()
    if fresh and roll < 0.35:
        b = rng.choice(fresh)
        q, a = rng.choice(BEHAVIOR_Q).format(b=b), brief(rec)
    elif roll < 0.70:
        q, a = brief_question(rec, pool=[])[0], brief(rec)
    else:
        q, a = fact_qa(rec)
    a += f"\nSources: {doc_name(rec['id'])}"
    return {"type": "open_book", "technique": r["id"], "messages": msgs(rag_user_message(q, docs), a)}


def fake_id():
    while True:
        c = f"T{rng.randint(1001, 1650)}" + (f".{rng.randint(1, 20):03d}" if rng.random() < 0.5 else "")
        if c not in by_id:
            return c


def abstain_example():
    """The asked-about technique is NOT in the documents: the right answer is to say so, not to guess."""
    n_docs = rng.choice([3, 4])
    if rng.random() < 0.45:
        r = rng.choice([x for x in train_recs if x["procedures"]])
        docs = [(doc_name(x["id"]), render_technique(x)) for x in pick_distractors(r, n_docs)]
        q = rng.choice(BEHAVIOR_Q).format(b=rng.choice(r["procedures"]))
        a = ("None of the provided ATT&CK documents describes this behavior, so I can't map it to a "
             "technique from them.")
        tag = r["id"]
    else:
        if rng.random() < 0.7:
            r = rng.choice(train_recs)
            tid, ctx = r["id"], pick_distractors(r, n_docs)
        else:
            tid, ctx = fake_id(), rng.sample(train_recs, n_docs)
        docs = [(doc_name(x["id"]), render_technique(x)) for x in ctx]
        q = rng.choice([rng.choice(ID_Q).format(id=tid), f"Which tactic does {tid} fall under?",
                        f"What mitigations does ATT&CK list for {tid}?"])
        a = (f"The provided ATT&CK documents do not include {tid}, so I can't confirm its tactic, "
             f"platforms or mitigations from them.")
        tag = tid
    a += "\nSources reviewed: " + ", ".join(n for n, _ in docs)
    return {"type": "abstain", "technique": tag, "messages": msgs(rag_user_message(q, docs), a)}


# ----------------------------------------------------------------------------
# Build the dataset from the TRAINING techniques only.
# ----------------------------------------------------------------------------
examples = []
for r in train_recs:
    q, _ = brief_question(r)
    examples.append({"type": "brief", "technique": r["id"], "messages": msgs(q, brief(r))})
    if len(r["procedures"]) >= 3 and rng.random() < 0.5:              # a second, behavior-style question
        b = rng.choice(r["procedures"])
        examples.append({"type": "brief", "technique": r["id"],
                         "messages": msgs(rng.choice(BEHAVIOR_Q).format(b=b), brief(r))})
    if rng.random() < 0.50:
        q, a = fact_qa(r)
        examples.append({"type": "fact", "technique": r["id"], "messages": msgs(q, a)})
    if rng.random() < 0.40:
        examples.append(open_book_example(r))
for _ in range(int(0.07 * len(train_recs))):
    examples.append(abstain_example())
rng.shuffle(examples)

# Safety check: not a single held-out technique ID may appear anywhere in the training text.
leaked = {i for e in examples for m in e["messages"] for i in TECH_ID_RE.findall(m["content"])} & HELD_IDS
assert not leaked, f"Held-out technique IDs leaked into training data: {sorted(leaked)[:5]}"
print(f"Built {len(examples)} training conversations; no held-out technique ID appears in them.")


# Save everything the next items need. Later notebooks read these files, so the
# data stays identical from baseline to fine-tune to RAG.
os.makedirs("data", exist_ok=True)
with open("data/train.jsonl", "w", encoding="utf-8") as f:            # full file (keeps the type/technique labels)
    for e in examples:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
with open("data/train_studio.jsonl", "w", encoding="utf-8") as f:     # clean copy for Unsloth Studio: messages only
    for e in examples:
        f.write(json.dumps({"messages": e["messages"]}, ensure_ascii=False) + "\n")
with open("data/heldout_ids.json", "w", encoding="utf-8") as f:
    json.dump(sorted(HELD_IDS), f)

print("Saved:")
for p in ["data/attack_snapshot.json", "data/train.jsonl", "data/train_studio.jsonl", "data/heldout_ids.json"]:
    print(f"  {p:28s} {os.path.getsize(p) / 1024:8.0f} KiB")
