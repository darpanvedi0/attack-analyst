"""Shared helpers for the ATT&CK-Analyst "specialist" project.

Used by the notebooks AND by the RAG script (later), so the training prompts,
the RAG documents and the RAG prompt are guaranteed to be identical.
Keep this file in the same folder as the notebooks.
"""
import re

SYSTEM_PROMPT = (
    "You are ATTACK-Analyst, a threat-mapping specialist for the MITRE ATT&CK Enterprise "
    "matrix. Be precise and never invent technique IDs or facts. When REFERENCE DOCUMENTS "
    "are provided, answer only from them and cite the source files."
)

# Technique IDs look like T1059 or T1059.001
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def doc_name(tech_id):
    """File name of the 'document' for a technique. This is what we cite as the source."""
    return f"{tech_id.upper()}.txt"


# ---------------------------------------------------------------------------
# Text cleaning (ATT&CK descriptions are markdown with citation markers)
# ---------------------------------------------------------------------------
def clean_text(text):
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")          # (Citation: Foo 2020)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)           # [name](url) -> name
    text = re.sub(r"</?code>", "", text)                           # <code>x</code> -> x
    text = text.replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def tactic_label(slug):
    """'defense-evasion' -> 'Defense Evasion', 'command-and-control' -> 'Command and Control'."""
    return slug.replace("-", " ").title().replace(" And ", " and ")


_ABBREV = ("e.g", "i.e", "etc", "vs", "approx", "cf")


def sentences(text):
    """Split into sentences without breaking on 'e.g.' / 'i.e.' / 'etc.'."""
    out, start = [], 0
    for m in re.finditer(r"[.!?](?=\s+[A-Z(\"'])", text):
        head = text[start:m.end()]
        last_word = re.split(r"\s", head.rstrip(".!?"))[-1].lower()
        if last_word in _ABBREV:
            continue
        out.append(head.strip())
        start = m.end()
    if text[start:].strip():
        out.append(text[start:].strip())
    return out


def first_sentence(text, limit=300):
    s = sentences(text)
    s = s[0] if s else text
    return s if len(s) <= limit else s[:limit].rsplit(" ", 1)[0] + "..."


def trim_sentences(text, limit):
    """Keep whole sentences up to about `limit` characters (never cut mid-sentence unless the first is huge)."""
    out = ""
    for s in sentences(text):
        if out and len(out) + 1 + len(s) > limit:
            break
        out = f"{out} {s}".strip()
    return out if len(out) <= limit * 1.5 else out[:limit].rsplit(" ", 1)[0] + "..."


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
MAX_MITIGATIONS = 8


def mitigation_text(mits, with_how=False):
    """'M1049 Antivirus/Antimalware; M1045 Code Signing ...' (capped; says how many were left out)."""
    if not mits:
        return "none listed"
    shown = mits[:MAX_MITIGATIONS]
    parts = [f"{m['id']} {m['name']}" + (f" - {m['how']}" if with_how and m.get("how") else "") for m in shown]
    txt = "; ".join(parts)
    if len(mits) > MAX_MITIGATIONS:
        txt += f" (+{len(mits) - MAX_MITIGATIONS} more in ATT&CK)"
    return txt


def reference_url(tech_id):
    return "https://attack.mitre.org/techniques/" + tech_id.replace(".", "/") + "/"


def render_technique(r):
    """One ATT&CK technique as a plain-text document: this is what we embed, retrieve and show the model."""
    if r.get("parent_id"):
        level = f"Sub-technique of {r['parent_id']} ({r['parent_name']})"
    else:
        level = "Technique (top level)"
    lines = [
        f"Technique ID: {r['id']}",
        f"Name: {r['name']}",
        f"Level: {level}",
        f"Tactics: {', '.join(r['tactics']) or 'not listed'}",
        f"Platforms: {', '.join(r['platforms']) or 'not listed'}",
        f"Added to ATT&CK: {r['created']}",
        f"Description: {trim_sentences(r['description'], 900)}",
        f"Mitigations: {mitigation_text(r['mitigations'], with_how=True)}",
        f"Detection strategy: {r['detection'] or 'none listed'}",
    ]
    for p in (r.get("procedures") or [])[:2]:
        lines.append(f"Observed use: {p}")
    lines.append(f"Reference: {reference_url(r['id'])}")
    return "\n".join(lines)


def rag_user_message(question, docs):
    """The user turn for an open-book (RAG) query. docs = list of (source_file_name, document_text)."""
    blocks = "\n\n".join(f"[source: {name}]\n{text}" for name, text in docs)
    return f"REFERENCE DOCUMENTS:\n{blocks}\n\nQUESTION: {question}"
