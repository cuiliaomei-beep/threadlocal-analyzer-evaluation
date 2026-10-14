"""Infer-TL, step 2: post-processing (the script named in TLDoctor/Infer-TL.md §2/§6, which the repository does not
contain). The four detect_* functions are the ones printed in §4 of that document, kept line for line; the helpers they
call are not given there and are implemented here from the prose of §1, §3 and §4. Each helper quotes its source sentence.

  python infer_tl_postprocess.py --infer-report report.json --facts facts.json --output infer-tl-report.json
"""
import argparse, json, re

# ---------------------------------------------------------------- lists printed in the document (§4.4)
HEAVY_TYPES = {
    "byte[]",
    "char[]",
    "java.nio.ByteBuffer",
    "java.lang.StringBuilder",
    "java.lang.StringBuffer",
    "java.io.ByteArrayOutputStream",
    "java.text.DateFormat",
    "java.text.SimpleDateFormat",
    "javax.xml.parsers.DocumentBuilder",
    "javax.xml.parsers.SAXParser",
    "com.fasterxml.jackson.databind.ObjectMapper",
    "java.util.regex.Matcher",
    "java.util.zip.Deflater",
    "java.util.zip.Inflater",
}

BENIGN_TYPES = {
    "java.lang.String",
    "java.lang.Integer",
    "java.lang.Long",
    "java.lang.Boolean",
    "java.lang.Enum",
}

# ---------------------------------------------------------------- helpers (not in the document)
TASK_LIKE = re.compile(r"^(run|call|service|doFilter|do[A-Z]\w*|handle\w*|process\w*|execute\w*|invoke\w*|on[A-Z]\w*|accept|apply|"
                       r"filter|intercept\w*|dispatch\w*|perform\w*)$")
SETTER_LIKE = re.compile(r"^(set\w*|init\w*|bind\w*|put\w*|push\w*|register\w*)$")
GROWTH = ("Buffer", "Builder", "Stream", "Map", "List", "Set", "Queue", "Deque", "Stack", "Cache", "Pool", "Parser", "Serializer",
          "Encoder", "Decoder", "Deflater", "Inflater", "[]")
DEPTH = 3


def skey(method_id):
    """pkg.Outer$Inner.method -> Outer$Inner.method (Infer prints callees with simple class names)"""
    parts = method_id.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else method_id


def proc_key(header):
    head = header.split("(")[0].strip().split(" ")[-1]
    return skey(head)


def build_summaries(facts):
    """method_summaries: per method its callees and callers, from Infer's procedure list"""
    callees, callers, defined = {}, {}, set()
    for header, info in facts.get("callGraph", {}).items():
        k = proc_key(header)
        if info.get("defined"): defined.add(k)
        cs = callees.setdefault(k, set())
        for c in info.get("callees", []):
            ck = proc_key(c)
            cs.add(ck)
            callers.setdefault(ck, set()).add(k)
    return {"callees": callees, "callers": callers, "defined": defined}


def find_effects(effects, tl_id, effect):
    return [e for e in effects if e["threadlocal"] == tl_id and e["effect"] == effect and not (effect == "set" and e.get("setNull"))]


def is_task_or_request_like(method, method_summaries):
    """§4.1 "if not is_task_or_request_like(method, ...)": the document's table speaks of request/task scopes and of
    "missing framework lifecycle models"; without such models a method counts as task/request-like when its name is a
    handler/task name, or when nothing captured by Infer calls it (an entry of the call graph) and it is not a setter."""
    name = method.split(".")[-1]
    if TASK_LIKE.match(name): return True
    if SETTER_LIKE.match(name): return False
    k = skey(method)
    callers = method_summaries["callers"].get(k, set()) & method_summaries["defined"]
    return len(callers - {k}) == 0


def has_matching_cleanup(tl_id, method, effects, method_summaries):
    """§4.1: "checks whether the same ThreadLocal object is removed in the same method, in a known cleanup wrapper, or in
    a summarized callee"."""
    removers = {skey(e["method"]) for e in effects if e["threadlocal"] == tl_id and e["effect"] == "remove"}
    k = skey(method)
    if k in removers: return True
    seen, frontier = {k}, {k}
    for _ in range(DEPTH):
        nxt = set()
        for m in frontier:
            for c in method_summaries["callees"].get(m, ()):
                if c in removers: return True
                if c not in seen:
                    seen.add(c); nxt.add(c)
        frontier = nxt
    return False


def is_jdk_owned_type(value_type):
    t = (value_type or "").replace("[]", "")
    if not t: return True                     # raw ThreadLocal: value type unknown, not claimed to be application-defined
    return t.startswith(("java.", "javax.", "jdk.", "sun.")) or "." not in t


def delegate_line(boundary):
    return boundary.get("delegateLine")


def has_effect_before_delegate(effects, tl_id, method, effect, boundary=None):
    line = delegate_line(boundary) if boundary else None
    for e in effects:
        if e["threadlocal"] != tl_id or e["method"] != method or e["effect"] != effect: continue
        if effect == "set" and e.get("setNull"): continue
        if line is None or e["line"] <= line: return True
    return False


def has_restore_after_delegate(effects, tl_id, method, boundary=None):
    """§4.3 safe pattern: `CTX.set(old); // or CTX.remove()` after the delegate call"""
    line = delegate_line(boundary) if boundary else None
    for e in effects:
        if e["threadlocal"] != tl_id or e["method"] != method or e["effect"] not in ("set", "remove"): continue
        if line is not None and e["line"] > line: return True
    return False


def normalize_type(t):
    return re.sub(r"<.*", "", (t or "").strip())


def looks_growth_prone(value_type):
    simple = value_type.split(".")[-1]
    return any(simple.endswith(g) for g in GROWTH)


def has_bounding_or_reset_logic(tl_id, effects):
    return any(e["threadlocal"] == tl_id and e["effect"] in ("remove", "reset") for e in effects)


# ---------------------------------------------------------------- §4.1 – §4.4, as printed in the document
def detect_sco(threadlocals, effects, method_summaries):
    warnings = []

    for tl in threadlocals:
        writes = find_effects(effects, tl["id"], effect="set")

        for write in writes:
            method = write["method"]

            if not is_task_or_request_like(method, method_summaries):
                continue

            if has_matching_cleanup(tl["id"], method, effects, method_summaries):
                continue

            warnings.append({
                "type": "TL_SCO_MissingRemove",
                "threadlocal": tl["id"],
                "method": method,
                "line": write["line"],
                "message": "ThreadLocal value is set without guaranteed cleanup."
            })

    return warnings


def detect_clp(threadlocals):
    warnings = []

    for tl in threadlocals:
        if not tl.get("static", False):
            continue

        value_type = tl.get("valueType", "")

        if is_jdk_owned_type(value_type):
            continue

        warnings.append({
            "type": "TL_CLP_StaticThreadLocal",
            "threadlocal": tl["id"],
            "field": tl["field"],
            "message": "Static ThreadLocal may retain application-defined values."
        })

    return warnings


def detect_cpm(threadlocals, effects, async_boundaries):
    warnings = []

    for boundary in async_boundaries:
        method = boundary["method"]

        for tl in threadlocals:
            has_snapshot = has_effect_before_delegate(effects, tl["id"], method, "get", boundary)
            has_install = has_effect_before_delegate(effects, tl["id"], method, "set", boundary)
            has_restore = has_restore_after_delegate(effects, tl["id"], method, boundary)

            if has_install and not has_restore:
                warnings.append({
                    "type": "TL_CPM_UnbalancedContext",
                    "threadlocal": tl["id"],
                    "method": method,
                    "message": "ThreadLocal context is installed across an async boundary without guaranteed restoration."
                })

    return warnings


def detect_hvr(threadlocals, effects):
    warnings = []

    for tl in threadlocals:
        value_type = normalize_type(tl.get("valueType", ""))

        if value_type in BENIGN_TYPES:
            continue

        if value_type not in HEAVY_TYPES and not looks_growth_prone(value_type):
            continue

        if has_bounding_or_reset_logic(tl["id"], effects):
            continue

        warnings.append({
            "type": "TL_HVR_HeavyValueRetention",
            "threadlocal": tl["id"],
            "valueType": value_type,
            "message": "ThreadLocal stores heavyweight or growth-prone values without clear bounding or cleanup."
        })

    return warnings


# ---------------------------------------------------------------- driver
PATTERN = {"TL_SCO_MissingRemove": "SCO", "TL_CLP_StaticThreadLocal": "CLP", "TL_CPM_UnbalancedContext": "CPM", "TL_HVR_HeavyValueRetention": "HVR"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--infer-report", required=True); ap.add_argument("--facts", required=True); ap.add_argument("--output", required=True)
    ap.add_argument("--project", default="")
    a = ap.parse_args()
    facts = json.load(open(a.facts, encoding="utf-8"))
    report = json.load(open(a.infer_report, encoding="utf-8"))
    tls, effects, bounds = facts["threadlocals"], facts["effects"], facts["asyncBoundaries"]
    summaries = build_summaries(facts)
    by_id = {t["id"]: t for t in tls}
    ws = detect_sco(tls, effects, summaries) + detect_clp(tls) + detect_cpm(tls, effects, bounds) + detect_hvr(tls, effects)
    # "post-processed report matching" (§1): Infer's own issues located in a method that touches the same ThreadLocal are
    # attached as evidence; an Infer leak issue whose message names a ThreadLocal is passed through as SCO.
    touching = {}
    for e in effects: touching.setdefault(skey(e["method"]), set()).add(e["threadlocal"])
    issues_by_method = {}
    for it in report:
        k = proc_key(it.get("procedure") or "")
        issues_by_method.setdefault(k, []).append(it)
        if "LEAK" in (it.get("bug_type") or "") and "ThreadLocal" in (it.get("qualifier") or ""):
            for tl_id in touching.get(k, ()):
                ws.append({"type": "TL_SCO_MissingRemove", "threadlocal": tl_id, "method": it.get("procedure"), "line": it.get("line"),
                           "message": "Infer " + it["bug_type"] + ": " + (it.get("qualifier") or "")[:120]})
    out, seen = [], set()
    for w in ws:
        key = (w["type"], w["threadlocal"], w.get("method"), w.get("line"))
        if key in seen: continue
        seen.add(key)
        tl = by_id.get(w["threadlocal"], {})
        w.update({"tool": "Infer-TL", "pattern": PATTERN[w["type"]], "project": a.project, "file": tl.get("file") if "method" not in w else
                  next((e["file"] for e in effects if e["method"] == w["method"]), tl.get("file")),
                  "line": w.get("line") or tl.get("line"), "owner": tl.get("owner"),
                  "inferIssuesInMethod": sorted({i["bug_type"] for i in issues_by_method.get(skey(w["method"]), [])}) if w.get("method") else []})
        out.append(w)
    json.dump(out, open(a.output, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    from collections import Counter
    print(dict(Counter(w["pattern"] for w in out)), "total", len(out))


if __name__ == "__main__":
    main()
