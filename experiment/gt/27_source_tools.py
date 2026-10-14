"""Step 27: stock source-level analysers on the sources of the releases of a split (sources jars from Maven Central,
see 26_sources.py), converted to the common report format for gt/23_run_design.py eval.

  python gt/27_source_tools.py pmd   --split heldout [--which pre|both] [--jobs 3]   -> out/bl-pmd/<artifact>-<version>.json
  python gt/27_source_tools.py infer --split heldout [--which pre|both] [--jobs 2]   -> out/bl-infer/<artifact>-<version>.json

pmd  : PMD 7.28.0, zero modification, ALL stock Java rules (8 categories, 325 rules). None of them mentions ThreadLocal
       (checked by scanning the rule definitions), so there is no ThreadLocal rule to select.
infer: Infer 1.3.0, zero modification, default checkers. None of its 160 issue types concerns ThreadLocal.
       Compilation: javac (JDK 21, -source/-target of the release's class-file version) on the sources jar, class path =
       the release's binary jar + the dependencies resolved from its pom (all scopes). Files that do not compile are
       dropped (their classes are still visible through the binary jar); the number of dropped files is recorded.

Scoring. Because neither tool has a ThreadLocal rule, a warning is kept (tier REPORT) only if it TOUCHES a ThreadLocal:
its message mentions ThreadLocal, or one of its flagged lines (at most 5 lines from the start line) contains the text
`ThreadLocal` or the name of a ThreadLocal field declared in the same file. No obligation is assigned to such warnings
(obligations = []), so only the location-level measure TP(any) is meaningful for these tools. The total number of
warnings of each run and the per-rule counts of the kept ones are recorded in the JSON.
"""
import argparse, csv, json, os, re, subprocess, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

HERE = os.path.join(RUNTIME_ROOT, "gt"); ROOT = RUNTIME_ROOT
WSL_ROOT = BASH_ROOT
ENV = shell_environment()
PMD = tool_command("TL_PMD", "~/tools/pmd-bin-7.28.0/bin/pmd")
INFER = tool_command("TL_INFER", "~/tools/infer/bin/infer")
PMD_RULES = ",".join(f"category/java/{c}.xml" for c in
                     ["bestpractices", "codestyle", "design", "documentation", "errorprone", "multithreading", "performance", "security"])
TL_DECL = re.compile(r"ThreadLocal\s*(?:<[^;=(){}]*>)?\s+([A-Za-z_$][\w$]*)\s*(?:=|;)")
TL_TEXT = re.compile(r"ThreadLocal")


def jobs_of(split, which):
    sp = list(csv.DictReader(open(os.path.join(HERE, "split", "split_frozen.csv"), encoding="utf-8-sig")))
    pairs = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "jar_pairs_verified.csv"), encoding="utf-8-sig"))}
    out = {}
    for r in sp:
        if split != "all" and r["split"] != split: continue
        if r["pair_status"] != "VALID" or r["id"] not in pairs: continue
        p = pairs[r["id"]]
        for k, jv in (("pre_path", "pre_java"), ("post_path", "post_java")):
            if which == "pre" and k != "pre_path": continue
            j = p[k].replace("\\", "/")
            out.setdefault(j, p.get(jv) or "8")
    return out


def key(jar_rel):
    parts = jar_rel.split("/")
    return f"{parts[-3]}-{parts[-2]}"


def src_dir(jar_rel):
    parts = jar_rel.split("/")
    return f"gt/sources/{parts[1]}/{parts[2]}/{parts[3]}"


def wsl(cmd, timeout):
    t0 = time.time()
    try:
        res = subprocess.run(bash_argv(cmd), capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
        return res.returncode, (res.stdout or "") + (res.stderr or ""), time.time() - t0
    except subprocess.TimeoutExpired:
        return -9, "timeout", time.time() - t0


def to_win(path):
    return host_path(path)


_cache = {}


def file_info(win_path):
    if win_path not in _cache:
        try:
            lines = open(win_path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            lines = []
        names = set(TL_DECL.findall("\n".join(lines)))
        _cache[win_path] = (lines, names)
    return _cache[win_path]


def touches(win_path, begin, end, message):
    if TL_TEXT.search(message or ""): return "message"
    lines, names = file_info(win_path)
    if not lines or begin <= 0: return None
    seg = "\n".join(lines[begin - 1: min(max(end, begin), begin + 4)])
    if TL_TEXT.search(seg): return "line:ThreadLocal"
    for n in names:
        if re.search(r"(?<![\w$])" + re.escape(n) + r"(?![\w$])", seg): return "line:" + n
    return None


def class_of(path, src_root):
    rel = path.replace("\\", "/")
    i = rel.find("/src/")
    rel = rel[i + 5:] if i >= 0 else os.path.basename(rel)
    return rel[:-5].replace("/", ".") if rel.endswith(".java") else rel.replace("/", ".")


def warn(rule, cls, method, line, detail):
    return {"rule": rule, "obligations": [], "dominant": "-", "severity": "n/a", "tier": "REPORT", "tl": cls, "tlKind": "BASELINE",
            "tlDeclClass": cls, "tlRuntimeClass": None, "method": method, "methodClass": cls, "line": line, "detail": detail, "sites": None, "facts": {}}


def write(tag, k, status, warnings, ms, extra):
    d = {"jar": k, "status": status, "tool": tag, "tlCount": 0, "tlUnknownCtx": 0, "time_ms": int(ms), "warnings": warnings}
    d.update(extra)
    os.makedirs(os.path.join(ROOT, "out", tag), exist_ok=True)
    json.dump(d, open(os.path.join(ROOT, "out", tag, k + ".json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def n_java(jar_rel):
    d = os.path.join(ROOT, src_dir(jar_rel), "src")
    n = 0
    for _, _, fs in os.walk(d):
        n += sum(1 for f in fs if f.endswith(".java"))
    return n


def cached_result_current(tag, jar_rel, status):
    """A missing-source result expires when release sources become available."""
    if status in ("NO_SOURCES", "INFER_NO_SOURCES"):
        return n_java(jar_rel) == 0
    if status != "OK":
        return False
    if tag == "bl-infer-tl":
        base = os.path.join(ROOT, "out", "bl-infer", key(jar_rel) + ".json")
        result = os.path.join(ROOT, "out", tag, key(jar_rel) + ".json")
        try:
            with open(base, encoding="utf-8") as f:
                upstream = json.load(f)
            return upstream.get("status") == "OK" and os.path.getmtime(result) >= os.path.getmtime(base)
        except (OSError, ValueError):
            return False
    return True


def load_pmd(path, cmd, timeout):
    """PMD's JSON renderer can emit invalid JSON for some messages; fall back to its XML renderer for such a release"""
    try:
        d = json.loads(open(path, encoding="utf-8", errors="replace").read(), strict=False)
        return d.get("files", []), len(d.get("processingErrors", [])), len(d.get("configurationErrors", [])), d.get("pmdVersion"), "json"
    except json.JSONDecodeError:
        pass
    import xml.etree.ElementTree as ET
    xml_rel = path.replace("\\", "/")
    xml_rel = xml_rel[xml_rel.index("out/"):].replace(".pmd.json", ".pmd.xml")
    wsl(cmd.replace("-f json", "-f xml").replace(".pmd.json", ".pmd.xml"), timeout)
    root = ET.parse(os.path.join(ROOT, xml_rel)).getroot()
    ns = root.tag[:root.tag.index("}") + 1] if root.tag.startswith("{") else ""
    files = []
    for f in root.findall(ns + "file"):
        files.append({"filename": f.get("name"), "violations": [
            {"beginline": v.get("beginline"), "endline": v.get("endline"), "rule": v.get("rule"), "ruleset": v.get("ruleset"),
             "description": (v.text or "").strip()} for v in f.findall(ns + "violation")]})
    return files, len(root.findall(ns + "error")), len(root.findall(ns + "configerror")), root.get("version"), "xml"


# ---------------- PMD ----------------
def run_pmd(jar_rel, java, timeout):
    k = key(jar_rel); sd = src_dir(jar_rel)
    nj = n_java(jar_rel)
    if nj == 0:
        write("bl-pmd", k, "NO_SOURCES", [], 0, {"n_java": 0})
        return k, 0, 0.0, "NO_SOURCES"
    rep = f"out/bl-pmd/{k}.pmd.json"
    cmd = (f"{ENV}; cd {shell_path(WSL_ROOT)} && mkdir -p out/bl-pmd && rm -f {rep} && {PMD} check -d {sd}/src -R {PMD_RULES} -f json -r {rep} "
           f"--no-cache --no-progress --no-fail-on-violation --no-fail-on-error -t 2 --aux-classpath gt/{jar_rel}")
    rc, out, dt = wsl(cmd, timeout)
    path = os.path.join(ROOT, rep)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        write("bl-pmd", k, "TIMEOUT" if rc == -9 else "ERROR", [], dt * 1000, {"error": out[-400:], "n_java": nj})
        return k, rc, dt, "no report"
    files, n_err, n_cfg, version, fmt = load_pmd(path, cmd, timeout)
    ws, total, by = [], 0, Counter()
    for f in files:
        wp = to_win(f["filename"]) if f["filename"].startswith("/") else os.path.join(ROOT, f["filename"])
        cls = class_of(f["filename"], sd)
        for v in f.get("violations", []):
            total += 1
            why = touches(wp, int(v.get("beginline") or 0), int(v.get("endline") or 0), v.get("description"))
            if not why: continue
            by[v["rule"]] += 1
            ws.append(warn("PMD_" + v["rule"], cls, None, int(v.get("beginline") or 0), f"[{v.get('ruleset')}] {v.get('description', '')[:140]} ({why})"))
    write("bl-pmd", k, "OK", ws, dt * 1000, {"n_java": nj, "violations_total": total, "violations_touching_threadlocal": len(ws),
                                            "touching_by_rule": dict(by), "processing_errors": n_err, "pmd_version": version, "report_format": fmt})
    return k, rc, dt, f"files={nj} violations={total} touching={len(ws)} errors={n_err} fmt={fmt}"


# ---------------- PMD-TL (L3: the rules described in TLDoctor/PMD-TL.md, see baselines/pmd-tl) ----------------
PMD_TL_MAP = {"TL_SCO_MissingRemove": ["O1"], "TL_CLP_StaticThreadLocal": ["O3"], "TL_CPM_UnbalancedContext": ["O2"], "TL_HVR_HeavyValueRetention": ["O4"]}
PMD_TL_JAR = "baselines/pmd-tl/target/pmd-threadlocal-rules-1.0-SNAPSHOT.jar"


def run_pmd_tl(jar_rel, java, timeout):
    k = key(jar_rel); sd = src_dir(jar_rel)
    nj = n_java(jar_rel)
    if nj == 0:
        write("bl-pmd-tl", k, "NO_SOURCES", [], 0, {"n_java": 0})
        return k, 0, 0.0, "NO_SOURCES"
    rep = f"out/bl-pmd-tl/{k}.pmd.json"
    cmd = (f"{ENV}; cd {shell_path(WSL_ROOT)} && export CLASSPATH=$(pwd)/{PMD_TL_JAR} && mkdir -p out/bl-pmd-tl && rm -f {rep} && {PMD} check -d {sd}/src "
           f"-R rulesets/threadlocal-pmd-ruleset.xml -f json -r {rep} --no-cache --no-progress --no-fail-on-violation --no-fail-on-error -t 2 "
           f"--aux-classpath gt/{jar_rel}")
    rc, out, dt = wsl(cmd, timeout)
    path = os.path.join(ROOT, rep)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        write("bl-pmd-tl", k, "TIMEOUT" if rc == -9 else "ERROR", [], dt * 1000, {"error": out[-400:], "n_java": nj})
        return k, rc, dt, "no report"
    files, n_err, n_cfg, version, fmt = load_pmd(path, cmd, timeout)
    ws, by = [], Counter()
    for f in files:
        cls = class_of(f["filename"], sd)
        for v in f.get("violations", []):
            if v["rule"] not in PMD_TL_MAP: continue
            by[v["rule"]] += 1
            ws.append({**warn("PMDTL_" + v["rule"], cls, None, int(v.get("beginline") or 0), v.get("description", "")[:160]),
                       "obligations": PMD_TL_MAP[v["rule"]], "dominant": PMD_TL_MAP[v["rule"]][0]})
    write("bl-pmd-tl", k, "OK", ws, dt * 1000, {"n_java": nj, "by_rule": dict(by), "processing_errors": n_err,
                                               "config_errors": n_cfg, "pmd_version": version, "report_format": fmt})
    return k, rc, dt, f"files={nj} warnings={len(ws)} {dict(by)} errors={n_err} cfgerr={n_cfg}"


# ---------------- Infer ----------------
INFER_SH = r"""
set -u
{env}
cd {root}
W=out/bl-infer/work/{k}
rm -rf $W && mkdir -p $W/classes $W/pre
find {sd}/src -name '*.java' ! -name 'module-info.java' ! -name 'package-info.java' > $W/files.txt
JAR=$(pwd)/gt/{jar}
CP=$JAR
if [ -f {sd}/{art}-{ver}.pom ]; then
  cp {sd}/{art}-{ver}.pom $W/pom.xml
  (cd $W && timeout 600 mvn -q -B -f pom.xml dependency:build-classpath -Dmdep.outputFile=cp.txt > mvn.log 2>&1)
  if [ -s $W/cp.txt ]; then CP=$JAR:$(cat $W/cp.txt); echo DEPS_OK; else echo DEPS_FAILED; fi
else echo NO_POM; fi
OPTS="-proc:none -nowarn -encoding UTF-8 -source {lvl} -target {lvl} -Xmaxerrs 100000 -XDignore.symbol.file"
cp $W/files.txt $W/ok.txt
for round in 1 2 3 4 5 6 7 8 9 10; do
  [ -s $W/ok.txt ] || break
  if javac $OPTS -cp "$CP" -d $W/pre @$W/ok.txt > $W/javac$round.log 2>&1; then echo COMPILE_OK round=$round; break; fi
  grep -oE '^[^ :]+\.java:[0-9]+: error' $W/javac$round.log | sed -E 's/:[0-9]+: error$//' | sort -u > $W/bad$round.txt
  [ -s $W/bad$round.txt ] || {{ echo COMPILE_FAILED_NO_FILE_ERRORS; break; }}
  grep -vxFf $W/bad$round.txt $W/ok.txt > $W/ok.next || true
  mv $W/ok.next $W/ok.txt
done
echo FILES_TOTAL=$(wc -l < $W/files.txt) FILES_OK=$(wc -l < $W/ok.txt)
[ -s $W/ok.txt ] || exit 3
timeout {cap} {infer} capture --no-progress-bar -o $W/infer-out -- javac $OPTS -cp "$CP" -d $W/classes @$W/ok.txt > $W/capture.log 2>&1 || {{ echo CAPTURE_FAILED; tail -3 $W/capture.log; exit 4; }}
timeout {ana} {infer} analyze --no-progress-bar -j {infer_jobs} -o $W/infer-out > $W/analyze.log 2>&1 || {{ echo ANALYZE_FAILED; tail -3 $W/analyze.log; exit 5; }}
cp $W/infer-out/report.json out/bl-infer/{k}.infer.json
# Infer's own procedure list with static callees (its call graph): input of the Infer-TL post-processing
{infer} debug --procedures --procedures-callees -o $W/infer-out > out/bl-infer/{k}.procedures.txt 2>/dev/null || echo PROCEDURES_EXPORT_FAILED
rm -rf $W/classes $W/pre $W/infer-out
echo DONE
"""


def run_infer(jar_rel, java, timeout, infer_jobs=6):
    k = key(jar_rel); sd = src_dir(jar_rel); parts = jar_rel.split("/")
    nj = n_java(jar_rel)
    if nj == 0:
        write("bl-infer", k, "NO_SOURCES", [], 0, {"n_java": 0})
        return k, 0, 0.0, "NO_SOURCES"
    try: lvl = max(8, int(java))
    except ValueError: lvl = 8
    lvl = min(lvl, 21)
    os.makedirs(os.path.join(ROOT, "out", "bl-infer", "work"), exist_ok=True)
    sh = os.path.join(ROOT, "out", "bl-infer", "work", k + ".sh")
    open(sh, "w", encoding="utf-8", newline="\n").write(INFER_SH.format(env=ENV, root=shell_path(WSL_ROOT), k=k, sd=sd, jar=jar_rel, art=parts[2], ver=parts[3],
                                                                         lvl=lvl, infer=INFER, infer_jobs=infer_jobs, cap=int(timeout * 0.3), ana=int(timeout * 0.6)))
    rc, out, dt = wsl(f"bash {shell_path(WSL_ROOT + '/out/bl-infer/work/' + k + '.sh')}", timeout + 900)
    m = re.search(r"FILES_TOTAL=(\d+) FILES_OK=(\d+)", out)
    ft, fo = (int(m.group(1)), int(m.group(2))) if m else (nj, 0)
    info = {"n_java": nj, "files_total": ft, "files_compiled": fo, "deps": "OK" if "DEPS_OK" in out else ("FAILED" if "DEPS_FAILED" in out else "NO_POM"),
            "source_level": lvl, "infer_version": "1.3.0", "infer_analyze_jobs": infer_jobs}
    rep = os.path.join(ROOT, "out", "bl-infer", k + ".infer.json")
    if "DONE" not in out or not os.path.exists(rep):
        status = "TIMEOUT" if rc == -9 else ("COMPILE_FAILED" if fo == 0 or "COMPILE_FAILED" in out else "ERROR")
        info["error"] = out[-400:]
        write("bl-infer", k, status, [], dt * 1000, info)
        return k, rc, dt, f"{status} files_ok={fo}/{ft}"
    issues = json.load(open(rep, encoding="utf-8"))
    ws, by, allby = [], Counter(), Counter()
    for it in issues:
        allby[it.get("bug_type")] += 1
        f = it.get("file") or ""
        wp = to_win(f) if f.startswith("/") else os.path.join(ROOT, f)
        why = touches(wp, int(it.get("line") or 0), int(it.get("line") or 0), it.get("qualifier"))
        if not why: continue
        by[it["bug_type"]] += 1
        ws.append(warn("INFER_" + it["bug_type"], class_of(f, sd), it.get("procedure"), int(it.get("line") or 0), f"{(it.get('qualifier') or '')[:140]} ({why})"))
    info.update({"issues_total": len(issues), "issues_by_type": dict(allby), "issues_touching_threadlocal": len(ws), "touching_by_type": dict(by)})
    write("bl-infer", k, "OK", ws, dt * 1000, info)
    return k, rc, dt, f"compiled={fo}/{ft} deps={info['deps']} issues={len(issues)} touching={len(ws)}"


# ---------------- Infer-TL (L3: TLDoctor/Infer-TL.md, see baselines/infer-tl) ----------------
INFER_TL_MAP = {"TL_SCO_MissingRemove": ["O1"], "TL_CLP_StaticThreadLocal": ["O3"], "TL_CPM_UnbalancedContext": ["O2"], "TL_HVR_HeavyValueRetention": ["O4"]}


def run_infer_tl(jar_rel, java, timeout):
    """needs the Infer run of the same release (report + procedure/callee list); pure post-processing, no WSL"""
    import sys
    k = key(jar_rel); sd = src_dir(jar_rel)
    base = os.path.join(ROOT, "out", "bl-infer", k)
    try:
        st = json.load(open(base + ".json", encoding="utf-8")).get("status")
    except Exception:
        st = "MISSING"
    if st != "OK":
        write("bl-infer-tl", k, "INFER_" + str(st), [], 0, {"note": "Infer did not complete on this release"})
        return k, 0, 0.0, "INFER_" + str(st)
    os.makedirs(os.path.join(ROOT, "out", "bl-infer-tl"), exist_ok=True)
    facts = os.path.join(ROOT, "out", "bl-infer-tl", k + ".facts.json"); rep = os.path.join(ROOT, "out", "bl-infer-tl", k + ".infertl.json")
    t0 = time.time()
    tl_dir = os.path.join(ROOT, "baselines", "infer-tl")
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r1 = subprocess.run([sys.executable, os.path.join(tl_dir, "collect_threadlocal_facts.py"), "--source-root", os.path.join(ROOT, sd, "src"),
                         "--procedures", base + ".procedures.txt", "--output", facts], capture_output=True, text=True, env=env, encoding="utf-8", errors="replace")
    r2 = subprocess.run([sys.executable, os.path.join(tl_dir, "infer_tl_postprocess.py"), "--infer-report", base + ".infer.json", "--facts", facts,
                         "--output", rep, "--project", k], capture_output=True, text=True, env=env, encoding="utf-8", errors="replace")
    dt = time.time() - t0
    if r1.returncode != 0 or r2.returncode != 0 or not os.path.exists(rep):
        write("bl-infer-tl", k, "ERROR", [], dt * 1000, {"error": (r1.stderr + r2.stderr)[-400:]})
        return k, 1, dt, "ERROR " + (r1.stderr + r2.stderr)[-120:]
    ws, by = [], Counter()
    for w in json.load(open(rep, encoding="utf-8")):
        owner = w.get("owner") or w["threadlocal"].rsplit(".", 1)[0]
        mcls = w["method"].rsplit(".", 1)[0] if w.get("method") and "(" not in w["method"] else (w.get("method") or owner).split("(")[0].rsplit(".", 1)[0]
        by[w["type"]] += 1
        x = warn("INFERTL_" + w["type"], owner, w.get("method"), int(w.get("line") or 0), w.get("message", "")[:160])
        x.update({"obligations": INFER_TL_MAP[w["type"]], "dominant": INFER_TL_MAP[w["type"]][0], "tl": w["threadlocal"], "methodClass": mcls or owner})
        ws.append(x)
    write("bl-infer-tl", k, "OK", ws, dt * 1000, {"by_rule": dict(by), "facts": r1.stdout.strip()[-200:], "procedures_file": os.path.exists(base + ".procedures.txt")})
    return k, 0, dt, f"warnings={len(ws)} {dict(by)} | {r1.stdout.strip()[-110:]}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("tool", choices=["pmd", "pmd-tl", "infer", "infer-tl"])
    ap.add_argument("--split", default="heldout")
    ap.add_argument("--which", default="pre", choices=["pre", "both"])
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--infer-jobs", type=int, default=6, help="Infer analysis workers per release (default: 6)")
    ap.add_argument("--timeout", type=int, default=2400)
    ap.add_argument("--ids", default="")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--skip-failed", action="store_true", help="do not retry releases whose previous run failed")
    a = ap.parse_args()
    if a.infer_jobs < 1:
        ap.error("--infer-jobs must be positive")
    tag = "bl-" + a.tool
    jobs = jobs_of(a.split, a.which)
    todo = []
    for j, java in jobs.items():
        if a.ids and key(j) not in a.ids.split(","): continue
        p = os.path.join(ROOT, "out", tag, key(j) + ".json")
        if not a.force and os.path.exists(p):
            try:
                st = json.load(open(p, encoding="utf-8")).get("status")
                if cached_result_current(tag, j, st) or (a.skip_failed and st in ("ERROR", "COMPILE_FAILED", "TIMEOUT")): continue
            except Exception:
                pass
        todo.append((j, java))
    print(f"{tag}: {len(jobs)} releases in split {a.split} ({a.which}), {len(todo)} to run (jobs={a.jobs})", flush=True)
    fn = {"pmd": run_pmd, "pmd-tl": run_pmd_tl, "infer": run_infer, "infer-tl": run_infer_tl}[a.tool]
    kwargs = {"infer_jobs": a.infer_jobs} if a.tool == "infer" else {}
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(fn, j, java, a.timeout, **kwargs) for j, java in todo]
        for f in as_completed(futs):
            try:
                k, rc, dt, msg = f.result()
            except Exception as e:                      # one failing release must not stop the run
                k, rc, dt, msg = "?", -1, 0.0, f"RUNNER_EXCEPTION {type(e).__name__}: {str(e)[:120]}"
            print(f"{time.strftime('%H:%M:%S')} rc={rc} {dt:6.1f}s {k} | {msg}", flush=True)
