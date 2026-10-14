"""Step 23: run LifeTL on the pre/post jars of a split and evaluate against the fix-anchored oracle.

  python gt/23_run_design.py run  --split design [--jobs 4] [--xmx 6g] [--force] [--ids H0059,...] [--tag v1]
  python gt/23_run_design.py eval --split design [--tag v1]

run : analyses every VALID pair of the split (GT rows and controls), pre and post jar, via Linux/WSL Java; caches JSON in
      out/<tag>/<artifact>-<version>.json (skipped when status OK exists, unless --force).
eval: matches REPORT-tier warnings to the FixSite classes (simple class names of the fix commit), computes
      legacy TP(dominant)/TP(any) fields as class-location proxies, fix-sensitivity, control-match candidates,
      warning volume; writes out/<tag>/eval_<split>.csv and out/<tag>/eval_<split>.md (all numbers counted).
      Those legacy column names do not establish correct diagnoses or warning precision.
      Use scripts/recompute_protocols.py for current native dedicated/related statistics.
"""
import argparse, csv, json, os, subprocess, sys, time, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

HERE = os.path.join(RUNTIME_ROOT, "gt"); ROOT = RUNTIME_ROOT
WSL_ROOT = BASH_ROOT
JAVA = java_command()
JAR = "LifeTL/target/LifeTL.jar"


def load_rows(split):
    sp = list(csv.DictReader(open(os.path.join(HERE, "split", "split_frozen.csv"), encoding="utf-8-sig")))
    pairs = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "jar_pairs_verified.csv"), encoding="utf-8-sig"))}
    ann = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "annotation", "annotation_final.csv"), encoding="utf-8-sig"))}
    rows = []
    for r in sp:
        if split != "all" and r["split"] != split: continue
        if r["pair_status"] != "VALID": continue
        p = pairs.get(r["id"])
        if not p: continue
        a = ann.get(r["id"], {})
        rows.append({"id": r["id"], "repo": r["repo"], "gt": r["gt_include"] == "1", "misuse": r["misuse"], "dominant": r["dominant"],
                     "split": r["split"], "pre": p["pre_path"].replace("\\", "/"), "post": p["post_path"].replace("\\", "/"),
                     "fix_classes": p["fix_classes"].split(), "artifact": p["artifactId"], "pre_version": p["pre_version"], "post_version": p["post_version"],
                     "pre_java": p["pre_java"], "n_classes_pre": p["n_classes_pre"],
                     "O1": a.get("O1_cleanup", ""), "O2": a.get("O2_restore", ""), "O3": a.get("O3_reachability", ""), "O4": a.get("O4_boundedness", "")})
    return rows


def run_one(jar_rel, out_rel, xmx, timeout, disable, mode="full", setl=""):
    dis = (f" --disable {disable}" if disable else "") + (f" --mode {mode}" if mode != "full" else "") + (f" --set {setl}" if setl else "")
    cmd = f"cd {shell_path(WSL_ROOT)} && {JAVA} -Xmx{xmx} -jar {JAR} --jar gt/{jar_rel} --out {out_rel} --timeout {timeout}{dis}"
    t0 = time.time()
    try:
        res = subprocess.run(bash_argv(cmd), capture_output=True, text=True, timeout=timeout + 120, encoding="utf-8", errors="replace")
        tail = (res.stderr or "").strip().splitlines()[-1:]
        return out_rel, res.returncode, time.time() - t0, tail[0] if tail else ""
    except subprocess.TimeoutExpired:
        return out_rel, -1, time.time() - t0, "python-timeout"


def status_of(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh).get("status")
    except Exception:
        return None


def cmd_run(a):
    rows = load_rows(a.split)
    if a.ids: rows = [r for r in rows if r["id"] in set(a.ids.split(","))]
    if a.gt_only: rows = [r for r in rows if r["gt"]]
    out_dir = f"out/{a.tag}"
    os.makedirs(os.path.join(ROOT, out_dir), exist_ok=True)
    jobs = []
    seen = set()
    for r in rows:
        for which in (["pre", "post"] if a.which == "both" else [a.which]):
            jar_rel = r[which]
            key = (jar_rel, which)
            if jar_rel in seen: continue  # identical jar shared by several rows: analyse once, copy later
            seen.add(jar_rel)
            out_rel = f"{out_dir}/{jar_key(jar_rel)}.json"
            if not a.force and status_of(os.path.join(ROOT, out_rel)) == "OK": continue
            jobs.append((jar_rel, out_rel))
    print(f"{len(rows)} rows, {len(jobs)} jar analyses to run (jobs={a.jobs}, xmx={a.xmx})", flush=True)
    log = open(os.path.join(ROOT, out_dir, "run.log"), "a", encoding="utf-8")
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(run_one, j, o, a.xmx, a.timeout, a.disable, a.mode, a.set) for j, o in jobs]
        for f in as_completed(futs):
            out_rel, rc, dt, tail = f.result()
            line = f"{time.strftime('%H:%M:%S')} rc={rc} {dt:6.1f}s {out_rel} | {tail}"
            print(line, flush=True); log.write(line + "\n"); log.flush()


def jar_key(jar_rel):
    # jars/<group>/<artifact>/<version>/<file>.jar -> <artifact>-<version>
    parts = jar_rel.split("/")
    return f"{parts[-3]}-{parts[-2]}" if len(parts) >= 4 else hashlib.md5(jar_rel.encode()).hexdigest()[:10]


def simple(name):
    if not name: return ""
    s = name.split(".")[-1]
    return s.split("$")[0]


def match_classes(w, fix):
    names = {simple(w.get("tlDeclClass")), simple(w.get("methodClass")), simple(w.get("tlRuntimeClass"))}
    for s in (w.get("sites") or []):
        sig = s.split(" ", 1)[-1]           # "d=3 <pkg.Class: ret name(args)>"
        if sig.startswith("<") and ":" in sig: names.add(simple(sig[1:sig.index(":")]))
    names.discard("")
    return names & fix


def wkey(w):
    return (w["rule"].split("+")[0], simple(w.get("tlDeclClass")), w["tl"].split(":")[-1].strip(" >") if w["tl"].startswith("<") else w["tl"], simple(w.get("methodClass")))


def fix_present(jar_path, fix):
    """how many FixSite classes (simple names) exist in the jar"""
    try:
        import zipfile
        names = {os.path.basename(n)[:-6].split("$")[0] for n in zipfile.ZipFile(jar_path).namelist() if n.endswith(".class")}
        return sum(1 for f in fix if f in names)
    except Exception:
        return ""


def fix_tl_in_pre(jar_path, fix):
    """does any FixSite class in the pre jar mention ThreadLocal in its constant pool? (defect code present in the release)"""
    try:
        import zipfile
        z = zipfile.ZipFile(jar_path)
        for n in z.namelist():
            if not n.endswith(".class"): continue
            simple_n = os.path.basename(n)[:-6].split("$")[0]
            if simple_n in fix and b"ThreadLocal" in z.read(n): return 1
        return 0
    except Exception:
        return ""


def invalid_controls():
    try:
        return {r["id"] for r in csv.DictReader(open(os.path.join(HERE, "matrix", "matrix_final.csv"), encoding="utf-8-sig")) if r.get("control_kind") == "INVALID"}
    except Exception:
        return set()


def cmd_eval(a):
    rows = load_rows(a.split)
    if a.ids: rows = [r for r in rows if r["id"] in set(a.ids.split(","))]
    if a.gt_only: rows = [r for r in rows if r["gt"]]
    inv = invalid_controls()
    out_dir = os.path.join(ROOT, f"out/{a.tag}")
    res = []
    for r in rows:
        pre = os.path.join(out_dir, jar_key(r["pre"]) + ".json"); post = os.path.join(out_dir, jar_key(r["post"]) + ".json")
        rec = dict(r); rec["fix_classes"] = " ".join(r["fix_classes"])
        fix = set(r["fix_classes"])
        for which, path in (("pre", pre), ("post", post)):
            st = status_of(path)
            rec[f"{which}_status"] = st or "MISSING"
            if st == "OK":
                d = json.load(open(path, encoding="utf-8"))
                reps = [w for w in d["warnings"] if w["tier"] == "REPORT"]
                rec[f"{which}_reports"] = len(reps)
                rec[f"{which}_tls"] = d["tlCount"]
                rec[f"{which}_time_ms"] = d["time_ms"]
                matched = [w for w in reps if match_classes(w, fix)]
                rec[f"_{which}_matched_w"] = [w for w in d["warnings"] if w["tier"] in ("REPORT", "WARNING") and match_classes(w, fix)]
                rec[f"{which}_matched"] = len(matched)
                rec[f"{which}_matched_rules"] = ";".join(sorted({w["rule"] + ":" + ",".join(w["obligations"]) for w in matched}))
                rec[f"_{which}_matched_keys"] = {wkey(w) for w in matched}
                rec[f"_{which}_matched"] = matched
                if which == "pre":
                    rec["pre_unknown_ctx"] = d["tlUnknownCtx"]
                    rec["pre_all_rules"] = ";".join(f"{k}={v}" for k, v in sorted(Counter(w["rule"].split("+")[0] for w in reps).items()))
            else:
                rec[f"{which}_reports"] = rec[f"{which}_matched"] = ""
        rec["fix_present"] = fix_present(os.path.join(HERE, r["pre"]), fix)
        rec["fix_tl_in_pre"] = fix_tl_in_pre(os.path.join(HERE, r["pre"]), fix)
        if r["gt"]:
            m = rec.get("_pre_matched", [])
            rec["tp_any"] = int(bool(m))
            rec["tp_dom"] = int(any(r["dominant"] in w["obligations"] for w in m))
            rec["tp_multilabel"] = int(any(any(r[o] in ("1", "yes") for o in w["obligations"] if o in ("O1", "O2", "O3", "O4")) for w in m))
            mw = rec.get("_pre_matched_w", [])
            rec["tp_dom_w"] = int(any(r["dominant"] in w["obligations"] for w in mw))
            post_keys = rec.get("_post_matched_keys", set())
            pre_keys = rec.get("_pre_matched_keys", set())
            rec["fix_sensitive"] = int(bool(pre_keys) and bool(pre_keys - post_keys)) if rec["post_status"] == "OK" else ""
            rec["fix_sensitive_all"] = int(bool(pre_keys) and not (pre_keys & post_keys)) if rec["post_status"] == "OK" else ""
        else:
            rec["fp_candidates"] = rec.get("pre_matched", "")
            # RQ2.3 control: do the warnings on the changed classes differ between pre and post of a benign change?
            if rec["pre_status"] == "OK" and rec["post_status"] == "OK":
                rec["ctrl_changed"] = int(rec.get("_pre_matched_keys", set()) != rec.get("_post_matched_keys", set()))
            else:
                rec["ctrl_changed"] = ""
        for k in list(rec):
            if k.startswith("_"): del rec[k]
        res.append(rec)
    cols = ["id", "repo", "split", "gt", "misuse", "dominant", "O1", "O2", "O3", "O4", "artifact", "pre_version", "post_version", "pre_java", "n_classes_pre", "fix_classes",
            "pre_status", "post_status", "pre_tls", "pre_unknown_ctx", "pre_reports", "post_reports", "pre_matched", "post_matched", "pre_matched_rules", "post_matched_rules",
            "fix_present", "fix_tl_in_pre", "tp_any", "tp_dom", "tp_dom_w", "tp_multilabel", "fix_sensitive", "fix_sensitive_all", "fp_candidates", "ctrl_changed", "pre_all_rules", "pre_time_ms", "post_time_ms"]
    with open(os.path.join(out_dir, f"eval_{a.split}.csv"), "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(res)
    # summary
    gt = [r for r in res if r["gt"]]; ctrl = [r for r in res if not r["gt"] and r["misuse"].startswith("no-") and r["id"] not in inv]
    ok = [r for r in gt if r["pre_status"] == "OK"]
    md = [f"# LifeTL on {a.split} set — tag {a.tag} ({time.strftime('%Y-%m-%d %H:%M')})", "",
          f"GT rows with VALID pair: {len(gt)}; pre analysed OK: {len(ok)}; status counts: {dict(Counter(r['pre_status'] for r in gt))}",
          f"controls with VALID pair: {len(ctrl)}; pre OK: {sum(1 for r in ctrl if r['pre_status']=='OK')}", "",
          "## GT detection (fix-anchored: a REPORT warning on a FixSite class)", "",
          f"- TP(any obligation): **{sum(r['tp_any'] for r in ok)}/{len(ok)}**",
          f"- TP(dominant obligation ∈ warning): **{sum(r['tp_dom'] for r in ok)}/{len(ok)}** (REPORT+WARNING tiers: {sum(r['tp_dom_w'] for r in ok)})",
          f"- GT rows whose FixSite classes are all present in the pre jar: {sum(1 for r in ok if r['fix_present'] == len(r['fix_classes'].split()))}/{len(ok)}; rows whose FixSite classes mention ThreadLocal in the pre jar: {sum(1 for r in ok if r['fix_tl_in_pre'] == 1)}/{len(ok)}",
          f"- TP(dominant) among rows with the defect code present (fix_tl_in_pre=1): {sum(r['tp_dom'] for r in ok if r['fix_tl_in_pre'] == 1)}/{sum(1 for r in ok if r['fix_tl_in_pre'] == 1)}",
          f"- TP(any annotated obligation ∈ warning): {sum(r['tp_multilabel'] for r in ok)}/{len(ok)}",
          f"- fix-sensitive (some matched warning disappears in post): {sum(1 for r in ok if r['fix_sensitive']==1)}/{sum(1 for r in ok if r['fix_sensitive']!='')}; all matched disappear: {sum(1 for r in ok if r['fix_sensitive_all']==1)}",
          f"- disappearance rate among detected rows (TP(any)=1 and post analysed): {sum(1 for r in ok if r['tp_any']==1 and r['fix_sensitive']==1)}/{sum(1 for r in ok if r['tp_any']==1 and r['fix_sensitive']!='')}",
          f"- control change rate (matched warnings differ pre vs post on a benign change): {sum(1 for r in ctrl if r.get('ctrl_changed')==1)}/{sum(1 for r in ctrl if r.get('ctrl_changed') in (0,1))}; among controls with a matched warning: {sum(1 for r in ctrl if r.get('ctrl_changed')==1 and (r['pre_matched'] or 0) > 0)}/{sum(1 for r in ctrl if r.get('ctrl_changed') in (0,1) and (r['pre_matched'] or 0) > 0)}", ""]
    md += ["| dominant | GT | TP(dom) | TP(any) |", "|---|---|---|---|"]
    for dom in ["O1", "O2", "O3", "O4"]:
        sub = [r for r in ok if r["dominant"] == dom]
        md.append(f"| {dom} | {len(sub)} | {sum(r['tp_dom'] for r in sub)} | {sum(r['tp_any'] for r in sub)} |")
    md += ["", "## Per GT row", "", "| id | dom | fix classes | pre reports | matched rules | tp_dom | fix-sens |", "|---|---|---|---|---|---|---|"]
    for r in gt:
        md.append(f"| {r['id']} | {r['dominant']} | {r['fix_classes'][:40]} | {r['pre_reports']} | {r.get('pre_matched_rules', '')[:90]} | {r.get('tp_dom','')} | {r.get('fix_sensitive','')} |")
    cok = [r for r in ctrl if r["pre_status"] == "OK"]
    md += ["", "## Controls (benign changes): REPORT warnings on the changed classes = FP candidates", "",
           f"- controls analysed: {len(cok)}; with ≥1 FixSite-matched REPORT: **{sum(1 for r in cok if (r['pre_matched'] or 0) > 0)}**; total matched warnings: {sum((r['pre_matched'] or 0) for r in cok)}", "",
           "| id | misuse | fix classes | pre reports | matched rules |", "|---|---|---|---|---|"]
    for r in ctrl:
        md.append(f"| {r['id']} | {r['misuse']} | {r['fix_classes'][:40]} | {r['pre_reports']} | {r.get('pre_matched_rules', '')[:90]} |")
    vol = [r for r in res if r["pre_status"] == "OK"]
    rules = Counter()
    for r in vol:
        for kv in (r["pre_all_rules"] or "").split(";"):
            if kv: k, v = kv.split("="); rules[k] += int(v)
    md += ["", "## Warning volume on pre jars (all TLs, not only FixSite)", "",
           f"- jars: {len(vol)}; total REPORT warnings: {sum(r['pre_reports'] for r in vol)}; per-jar median: {sorted(r['pre_reports'] for r in vol)[len(vol)//2] if vol else 0}; max: {max((r['pre_reports'] for r in vol), default=0)}",
           f"- by rule: " + ", ".join(f"{k} {v}" for k, v in rules.most_common()),
           f"- total analysis time: {sum(r['pre_time_ms'] for r in vol)/1000:.0f}s; max per jar: {max((r['pre_time_ms'] for r in vol), default=0)/1000:.0f}s", ""]
    open(os.path.join(out_dir, f"eval_{a.split}.md"), "w", encoding="utf-8").write("\n".join(md))
    print("\n".join(md[:20]))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run", "eval"])
    ap.add_argument("--split", default="design")
    ap.add_argument("--tag", default="v1")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--xmx", default="6g")
    ap.add_argument("--timeout", type=int, default=1200)
    ap.add_argument("--which", default="both")
    ap.add_argument("--ids", default="")
    ap.add_argument("--gt-only", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--disable", default="")
    ap.add_argument("--mode", default="full")
    ap.add_argument("--set", default="", help="overrides of limits of the framework model, e.g. reportDepth=3,entryReportDepth=8")
    a = ap.parse_args()
    (cmd_run if a.cmd == "run" else cmd_eval)(a)
