"""Infer-TL, step 1: ThreadLocal fact extraction (the script named in TLDoctor/Infer-TL.md §6, which the repository does
not contain). Implements §3 "ThreadLocal Fact Extraction" of that document:

  * ThreadLocal field declarations, withInitial(...) initialisers, anonymous subclasses with initialValue()
  * calls to get(), set(...), remove()   (plus reset-like calls on the value: clear()/reset()/setLength(0))
  * holder methods such as ContextHolder.set(...), clear(...), get(...)
  * async wrappers involving Runnable, Callable, Executor, CompletableFuture and listener callbacks
  * the call graph, taken from Infer itself (`infer debug --procedures --procedures-callees`)

Output: the fact database of §3 (threadlocals, effects, asyncBoundaries) plus "methods" and "callGraph".

  python collect_threadlocal_facts.py --source-root SRC [--procedures procedures.txt] --output facts.json
"""
import argparse, json, os, re

TL_FIELD = re.compile(
    r"(?P<mods>(?:(?:public|protected|private|static|final|transient|volatile)\s+)*)"
    r"(?P<type>(?:[\w.]+\.)?(?:Inheritable|Fast|Transmittable|Named|Closeable)?ThreadLocal\s*(?:<(?P<arg>[^;=(){}]*)>)?)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?P<init>=[^;]*?)?;", re.S)
CLASS_DECL = re.compile(r"\b(class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")
METHOD_DECL = re.compile(
    r"(?:(?:public|protected|private|static|final|synchronized|abstract|native|default|strictfp)\s+)*"
    r"(?:<[^<>{};()]*>\s*)?(?:[\w.$]+(?:\s*<[^{};()]*>)?(?:\s*\[\s*\])*\s+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^(){};]*)\)\s*(?:throws\s+[\w.$,\s]+)?\{")
KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "try", "return", "new", "else", "do", "throw", "assert"}
ASYNC_TYPES = ("Runnable", "Callable", "Executor", "CompletableFuture", "CompletionStage", "Supplier", "Listener")
ASYNC_CALLS = re.compile(r"\.\s*(submit|execute|supplyAsync|runAsync|schedule|invokeAll)\s*\(")
DELEGATE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\.\s*(run|call)\s*\(\s*\)")
HOLDER = re.compile(r"(?<![\w$.])([A-Z][\w$]*ContextHolder)\s*\.\s*(set\w*|clear\w*|remove\w*|reset\w*|get\w*)\s*\(")


def strip(src):
    """blank out comments, string and char literals, keeping offsets and newlines"""
    out, i, n = list(src), 0, len(src)
    while i < n:
        c = src[i]; d = src[i + 1] if i + 1 < n else ""
        if c == "/" and d == "/":
            j = src.find("\n", i); j = n if j < 0 else j
            for k in range(i, j): out[k] = " "
            i = j
        elif c == "/" and d == "*":
            j = src.find("*/", i + 2); j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n": out[k] = " "
            i = j
        elif c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            for k in range(i + 1, min(j, n)): out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def match_brace(s, open_idx):
    depth, i, n = 0, open_idx, len(s)
    while i < n:
        if s[i] == "{": depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0: return i
        i += 1
    return n - 1


def line_of(s, idx):
    return s.count("\n", 0, idx) + 1


def resolve(simple, imports, package):
    simple = simple.strip()
    if not simple: return ""
    base = re.sub(r"<.*", "", simple).strip()
    arr = "[]" * base.count("[")
    base = base.replace("[", "").replace("]", "").strip()
    if base in ("byte", "char", "int", "long", "short", "boolean", "float", "double"): return base + arr
    if "." in base: return base + arr
    if base in imports: return imports[base] + arr
    if base in ("String", "Integer", "Long", "Boolean", "Object", "StringBuilder", "StringBuffer", "Enum", "Short", "Byte", "Character",
                "Float", "Double", "Number", "Thread", "Class", "Runnable"): return "java.lang." + base + arr
    return (package + "." if package else "") + base + arr


def scan_file(path, rel):
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    s = strip(raw)
    m = re.search(r"\bpackage\s+([\w.]+)\s*;", s)
    package = m.group(1) if m else ""
    imports = {i.split(".")[-1]: i for i in re.findall(r"\bimport\s+(?:static\s+)?([\w.]+)\s*;", s)}
    # class regions
    classes = []
    for cm in CLASS_DECL.finditer(s):
        ob = s.find("{", cm.end())
        if ob < 0: continue
        classes.append((cm.group(2), ob, match_brace(s, ob)))
    top = os.path.basename(rel)[:-5]

    def owner_at(idx):
        inside = [c for c in classes if c[1] < idx <= c[2]]
        inside.sort(key=lambda c: c[1])
        names = [c[0] for c in inside] or [top]
        return (package + "." if package else "") + "$".join(names)

    tls = []
    for fm in TL_FIELD.finditer(s):
        if fm.group("name") in KEYWORDS: continue
        arg = (fm.group("arg") or "").strip()
        init = raw[fm.start("init"):fm.end("init")] if fm.group("init") else ""
        owner = owner_at(fm.start())
        tls.append({"id": owner + "." + fm.group("name"), "field": fm.group("name"), "owner": owner,
                    "static": "static" in fm.group("mods").split(), "type": re.sub(r"\s+", "", fm.group("type")),
                    "valueType": resolve(arg, imports, package), "valueTypeWritten": arg, "line": line_of(s, fm.start("name")),
                    "file": rel, "withInitial": "withInitial" in init, "anonymousInitialValue": "initialValue" in init,
                    "initializer": re.sub(r"\s+", " ", init)[:200]})
    methods = []
    for mm in METHOD_DECL.finditer(s):
        name = mm.group("name")
        if name in KEYWORDS: continue
        ob = mm.end() - 1
        cb = match_brace(s, ob)
        methods.append({"name": name, "owner": owner_at(mm.start("name")), "start": mm.start(), "open": ob, "close": cb,
                        "line": line_of(s, mm.start("name")), "endLine": line_of(s, cb), "signature": re.sub(r"\s+", " ", s[mm.start():ob]).strip()[:200]})
    # keep innermost methods for attribution
    return {"rel": rel, "src": s, "package": package, "tls": tls, "methods": methods, "imports": imports}


def method_at(methods, idx):
    inside = [m for m in methods if m["open"] < idx < m["close"]]
    if not inside: return None
    return min(inside, key=lambda m: m["close"] - m["open"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", required=True); ap.add_argument("--procedures"); ap.add_argument("--output", required=True)
    a = ap.parse_args()
    files = []
    for d, _, fs in os.walk(a.source_root):
        for f in fs:
            if f.endswith(".java") and f not in ("module-info.java", "package-info.java"):
                p = os.path.join(d, f)
                r = scan_file(p, os.path.relpath(p, a.source_root).replace("\\", "/"))
                if r: files.append(r)
    threadlocals = [t for f in files for t in f["tls"]]
    by_name = {}
    for t in threadlocals: by_name.setdefault(t["field"], []).append(t)
    effects, boundaries, holders, methods_out = [], [], [], []
    for f in files:
        s = f["src"]
        for m in f["methods"]:
            mid = m["owner"] + "." + m["name"]
            methods_out.append({"method": mid, "file": f["rel"], "line": m["line"], "endLine": m["endLine"], "signature": m["signature"]})
        # ThreadLocal effects: [Owner.|this.]NAME.(get|set|remove)(
        for name, cands in by_name.items():
            for em in re.finditer(r"(?<![\w$])(?:(?P<q>[A-Za-z_$][\w$.]*)\s*\.\s*)?" + re.escape(name) + r"\s*\.\s*(?P<op>get|set|remove)\s*\(", s):
                q = (em.group("q") or "").split(".")[-1]
                m = method_at(f["methods"], em.start())
                if m is None: continue
                owner_here = m["owner"]
                tl = None
                if q and q != "this":
                    c = [t for t in cands if t["owner"].split(".")[-1].split("$")[-1] == q]
                    tl = c[0] if len(c) >= 1 else None
                if tl is None:
                    c = [t for t in cands if t["owner"].split("$")[0] == owner_here.split("$")[0]]
                    tl = c[0] if c else (cands[0] if len(cands) == 1 and not q else None)
                if tl is None: continue
                op = em.group("op")
                tail = s[em.end():em.end() + 80]
                effects.append({"method": m["owner"] + "." + m["name"], "threadlocal": tl["id"], "effect": op, "line": line_of(s, em.start()), "file": f["rel"],
                                "setNull": op == "set" and re.match(r"\s*null\s*\)", tail) is not None})
                if op == "get" and re.match(r"\s*\)\s*\.\s*(clear|reset)\s*\(\s*\)|\s*\)\s*\.\s*setLength\s*\(\s*0\s*\)", tail):
                    effects.append({"method": m["owner"] + "." + m["name"], "threadlocal": tl["id"], "effect": "reset", "line": line_of(s, em.start()), "file": f["rel"], "setNull": False})
        for hm in HOLDER.finditer(s):
            m = method_at(f["methods"], hm.start())
            if m is None: continue
            n = hm.group(2)
            kind = "set" if n.startswith("set") else ("get" if n.startswith("get") else "remove")
            holders.append({"method": m["owner"] + "." + m["name"], "holder": hm.group(1), "call": n, "effect": kind, "line": line_of(s, hm.start()), "file": f["rel"]})
        # async boundaries
        for m in f["methods"]:
            body = s[m["open"]:m["close"] + 1]
            sig = m["signature"]
            kind = next((t for t in ASYNC_TYPES if re.search(r"(?<![\w$])" + t + r"(?![\w$])", sig)), None)
            call = ASYNC_CALLS.search(body)
            if kind is None and call is None and m["name"] not in ("run", "call"): continue
            dm = DELEGATE.search(body)
            boundaries.append({"method": m["owner"] + "." + m["name"], "kind": kind or (call.group(1) if call else m["name"]),
                               "delegateCall": dm.group(2) if dm else None,
                               "delegateLine": line_of(s, m["open"] + dm.start()) if dm else (line_of(s, m["open"] + call.start()) if call else None),
                               "file": f["rel"], "line": m["line"]})
    # call graph from Infer: "pkg.Class.method(args):ret" -> callees
    graph = {}
    if a.procedures and os.path.exists(a.procedures):
        cur = None
        for line in open(a.procedures, encoding="utf-8", errors="replace"):
            if line and not line[0].isspace() and line.strip():
                cur = line.strip(); graph[cur] = {"defined": False, "callees": []}
            elif cur and line.strip().startswith("defined:"):
                graph[cur]["defined"] = line.strip().endswith("true")
            elif cur and line.strip().startswith("callees:"):
                graph[cur]["callees"] = [c.strip() for c in line.strip()[len("callees:"):].split(", ") if c.strip()]
    json.dump({"threadlocals": threadlocals, "effects": effects, "holderEffects": holders, "asyncBoundaries": boundaries,
               "methods": methods_out, "callGraph": graph}, open(a.output, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"files={len(files)} threadlocals={len(threadlocals)} effects={len(effects)} holderEffects={len(holders)} "
          f"asyncBoundaries={len(boundaries)} procedures={len(graph)}")


if __name__ == "__main__":
    main()
