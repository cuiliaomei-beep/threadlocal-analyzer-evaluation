"""Stock CodeQL 2.27.1 / Java queries 1.11.11 and Error Prone 2.50.0.
Usage: python gt/37_more_analysers.py {codeql,errorprone} --split all --which both
The original source-pruning and default-check configurations are retained. Raw
SARIF and compiler diagnostics are preserved alongside legacy normalized JSON.
The legacy JSON tiers/obligation labels are not the paper's uniform-selection
statistics: scripts/recompute_protocols.py selects dedicated and uniformly related
native diagnostics from the raw output. A usable output does not imply complete
compilation or a verified lifecycle diagnosis.
"""
import argparse, importlib.util, json, os, re, sys, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

HERE = os.path.join(RUNTIME_ROOT, "gt"); ROOT = RUNTIME_ROOT
spec = importlib.util.spec_from_file_location("st", os.path.join(HERE, "27_source_tools.py")); st = importlib.util.module_from_spec(spec); spec.loader.exec_module(st)
WSL_ROOT, ENV = st.WSL_ROOT, st.ENV
CODEQL = tool_command("TL_CODEQL", "~/tools/codeql/codeql")
EP_CP_FILE = tool_command("TL_ERRORPRONE_CP_FILE", "~/tools/errorprone/cp.txt")
EP_PROCESSORPATH = (tool_command("TL_ERRORPRONE_JAR", "") if os.environ.get("TL_ERRORPRONE_JAR")
                    else '"$(cat ' + EP_CP_FILE + ')"')
EP_EXPORTS = " ".join(f"-J--add-exports=jdk.compiler/com.sun.tools.javac.{p}=ALL-UNNAMED" for p in
                      ("api", "file", "main", "model", "parser", "processing", "tree", "util", "code", "comp")) + " -J--add-opens=jdk.compiler/com.sun.tools.javac.comp=ALL-UNNAMED"

PREP_SH = r"""
set -u
{env}
cd {root}
W=out/{tag}/work/{k}
mkdir -p $W/classes
JAR=$(pwd)/gt/{jar}
OPTS="-proc:none -nowarn -encoding UTF-8 -source {lvl} -target {lvl} -Xmaxerrs 100000 -XDignore.symbol.file"
I=out/bl-infer/work/{k}
if {infer_ready} && [ -s $I/ok.txt ]; then
  cp $I/ok.txt $W/ok.txt; cp $I/files.txt $W/files.txt 2>/dev/null || cp $I/ok.txt $W/files.txt
  if [ -s $I/cp.txt ]; then cp $I/cp.txt $W/cp.txt; fi
  echo PREP_REUSED
else
  find {sd}/src -name '*.java' ! -name 'module-info.java' ! -name 'package-info.java' > $W/files.txt
  if [ -f {sd}/{art}-{ver}.pom ]; then
    cp {sd}/{art}-{ver}.pom $W/pom.xml
    (cd $W && timeout 600 mvn -q -B -f pom.xml dependency:build-classpath -Dmdep.outputFile=cp.txt > mvn.log 2>&1)
  fi
  cp $W/files.txt $W/ok.txt
  CP=$JAR; [ -s $W/cp.txt ] && CP=$JAR:$(cat $W/cp.txt)
  for round in 1 2 3 4 5 6 7 8 9 10; do
    [ -s $W/ok.txt ] || break
    if javac $OPTS -cp "$CP" -d $W/classes @$W/ok.txt > $W/javac$round.log 2>&1; then break; fi
    grep -oE '^[^ :]+\.java:[0-9]+: error' $W/javac$round.log | sed -E 's/:[0-9]+: error$//' | sort -u > $W/bad$round.txt
    [ -s $W/bad$round.txt ] || break
    grep -vxFf $W/bad$round.txt $W/ok.txt > $W/ok.next || true
    mv $W/ok.next $W/ok.txt
  done
  rm -rf $W/classes; mkdir -p $W/classes
fi
CP=$JAR; [ -s $W/cp.txt ] && CP=$JAR:$(cat $W/cp.txt)
echo FILES_TOTAL=$(wc -l < $W/files.txt) FILES_OK=$(wc -l < $W/ok.txt)
[ -s $W/ok.txt ] || exit 3
"""

CODEQL_SH = PREP_SH + r"""
rm -rf $W/db
timeout {t1} {codeql} database create $W/db --language=java --source-root {sd}/src --working-dir=$(pwd) --overwrite \
  --command="javac $OPTS -cp \"$CP\" -d $W/classes @$W/ok.txt" > $W/create.log 2>&1 || {{ echo CREATE_FAILED; tail -3 $W/create.log; exit 4; }}
timeout {t2} {codeql} database analyze $W/db codeql/java-queries@1.11.11:codeql-suites/java-security-and-quality.qls --threads=4 \
  --format=sarif-latest --output=$W/res.sarif > $W/analyze.log 2>&1 || {{ echo ANALYZE_FAILED; tail -3 $W/analyze.log; exit 5; }}
cp $W/res.sarif out/{tag}/{k}.sarif
rm -rf $W/db $W/classes
echo DONE
"""

EP_SH = PREP_SH + r"""
# -nowarn of the shared compile options would silence the plugin's warnings, so it is dropped here; -Xlint:-options hides the javac notes about -source/-target
timeout {t1} javac ${{OPTS/-nowarn/}} -Xlint:-options {exports} -XDcompilePolicy=simple -XDaddTypeAnnotationsToSymbol=true --should-stop=ifError=FLOW -Xmaxwarns 100000 \
  -processorpath {epcp} -Xplugin:"ErrorProne -XepAllErrorsAsWarnings" -cp "$CP" -d $W/classes @$W/ok.txt > $W/ep.log 2>&1
echo EP_RC=$?
cp $W/ep.log out/{tag}/{k}.ep.log
rm -rf $W/classes
echo DONE
"""


def prep_args(tag, jar_rel, java, timeout):
    k = st.key(jar_rel); sd = st.src_dir(jar_rel); parts = jar_rel.split("/")
    try: lvl = max(8, min(21, int(java)))
    except ValueError: lvl = 8
    # Failed/in-progress Infer work directories can be replaced by the repair lane.
    # Reuse compilation lists only from a completed successful Infer release.
    try:
        with open(os.path.join(ROOT, "out", "bl-infer", k + ".json"), encoding="utf-8") as f:
            infer_ready = json.load(f).get("status") == "OK"
    except (OSError, ValueError):
        infer_ready = False
    return dict(env=ENV, root=shell_path(WSL_ROOT), tag=tag, k=k, sd=sd, jar=jar_rel, art=parts[2], ver=parts[3], lvl=lvl,
                infer_ready="true" if infer_ready else "false", t1=int(timeout * 0.4), t2=int(timeout * 0.55))


def run_script(tag, k, text, timeout):
    os.makedirs(os.path.join(ROOT, "out", tag, "work"), exist_ok=True)
    sh = os.path.join(ROOT, "out", tag, "work", k + ".sh")
    open(sh, "w", encoding="utf-8", newline="\n").write(text)
    return st.wsl(f"bash {shell_path(WSL_ROOT + '/out/' + tag + '/work/' + k + '.sh')}", timeout + 600)


def files_info(out):
    m = re.search(r"FILES_TOTAL=(\d+) FILES_OK=(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def run_codeql(jar_rel, java, timeout):
    tag = "bl-codeql"; k = st.key(jar_rel); sd = st.src_dir(jar_rel)
    if st.n_java(jar_rel) == 0:
        st.write(tag, k, "NO_SOURCES", [], 0, {"n_java": 0}); return k, 0, 0.0, "NO_SOURCES"
    a = prep_args(tag, jar_rel, java, timeout); a["codeql"] = CODEQL
    rc, out, dt = run_script(tag, k, CODEQL_SH.format(**a), timeout)
    ft, fo = files_info(out)
    info = {"n_java": st.n_java(jar_rel), "files_total": ft, "files_compiled": fo, "prep": "reused" if "PREP_REUSED" in out else "fresh",
            "codeql_version": "2.27.1", "query_pack": "codeql/java-queries 1.11.11, java-security-and-quality"}
    sarif = os.path.join(ROOT, "out", tag, k + ".sarif")
    if "DONE" not in out or not os.path.exists(sarif):
        status = "TIMEOUT" if rc == -9 else ("COMPILE_FAILED" if fo == 0 else "ERROR")
        info["error"] = out[-400:]; st.write(tag, k, status, [], dt * 1000, info)
        return k, rc, dt, f"{status} files_ok={fo}/{ft}"
    doc = json.load(open(sarif, encoding="utf-8"))
    ws, by, allby = [], Counter(), Counter()
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            rule = res.get("ruleId", "?"); allby[rule] += 1
            locs = res.get("locations") or []
            if not locs: continue
            pl = locs[0].get("physicalLocation", {}); uri = pl.get("artifactLocation", {}).get("uri", ""); line = int(pl.get("region", {}).get("startLine") or 0)
            rel = f"{sd}/src/{uri}"
            why = st.touches(os.path.join(ROOT, rel.replace("/", os.sep)), line, line, res.get("message", {}).get("text"))
            if not why: continue
            by[rule] += 1
            ws.append(st.warn("CODEQL_" + rule.replace("/", "_"), st.class_of(rel, sd), None, line, f"{(res.get('message', {}).get('text') or '')[:140]} ({why})"))
    info.update({"results_total": sum(allby.values()), "results_by_rule": dict(allby.most_common(20)), "results_touching_threadlocal": len(ws), "touching_by_rule": dict(by)})
    st.write(tag, k, "OK", ws, dt * 1000, info)
    return k, rc, dt, f"compiled={fo}/{ft} results={sum(allby.values())} touching={len(ws)}"


EP_LINE = re.compile(r"^(?P<file>[^\s:]+\.java):(?P<line>\d+): warning: \[(?P<check>\w+)\] (?P<msg>.*)$")


def run_errorprone(jar_rel, java, timeout):
    tag = "bl-errorprone"; k = st.key(jar_rel); sd = st.src_dir(jar_rel)
    if st.n_java(jar_rel) == 0:
        st.write(tag, k, "NO_SOURCES", [], 0, {"n_java": 0}); return k, 0, 0.0, "NO_SOURCES"
    a = prep_args(tag, jar_rel, java, timeout); a["exports"] = EP_EXPORTS; a["epcp"] = EP_PROCESSORPATH
    rc, out, dt = run_script(tag, k, EP_SH.format(**a), timeout)
    ft, fo = files_info(out)
    info = {"n_java": st.n_java(jar_rel), "files_total": ft, "files_compiled": fo, "prep": "reused" if "PREP_REUSED" in out else "fresh", "errorprone_version": "2.50.0"}
    log = os.path.join(ROOT, "out", tag, k + ".ep.log")
    m = re.search(r"EP_RC=(\d+)", out)
    if "DONE" not in out or not os.path.exists(log):
        status = "TIMEOUT" if rc == -9 else ("COMPILE_FAILED" if fo == 0 else "ERROR")
        info["error"] = out[-400:]; st.write(tag, k, status, [], dt * 1000, info)
        return k, rc, dt, f"{status} files_ok={fo}/{ft}"
    info["javac_rc"] = int(m.group(1)) if m else None
    ws, by, allby = [], Counter(), Counter()
    for line in open(log, encoding="utf-8", errors="replace"):
        mm = EP_LINE.match(line.rstrip("\n"))
        if not mm: continue
        check = mm.group("check"); allby[check] += 1
        f = mm.group("file"); ln = int(mm.group("line"))
        rel = f if f.startswith("gt/") else f
        if check == "ThreadLocalUsage":
            w = st.warn("EP_ThreadLocalUsage", st.class_of(rel, sd), None, ln, mm.group("msg")[:140])
            w["obligations"] = ["O4"]; w["dominant"] = "O4"; ws.append(w); by[check] += 1
        else:
            why = st.touches(os.path.join(ROOT, rel.replace("/", os.sep)), ln, ln, mm.group("msg"))
            if not why: continue
            w = st.warn("EP_" + check, st.class_of(rel, sd), None, ln, f"{mm.group('msg')[:140]} ({why})"); w["tier"] = "NOTE"; ws.append(w); by[check] += 1
    info.update({"warnings_total": sum(allby.values()), "warnings_by_check": dict(allby.most_common(20)), "threadlocal_rule_warnings": by.get("ThreadLocalUsage", 0),
                 "other_checks_touching_threadlocal": sum(v for c, v in by.items() if c != "ThreadLocalUsage")})
    if info["javac_rc"] != 0 and sum(allby.values()) == 0:
        # javac aborted before Error Prone ran (e.g. a plugin option error): no analysis took place
        info["error"] = open(log, encoding="utf-8", errors="replace").read()[-400:]
        st.write(tag, k, "ERROR", [], dt * 1000, info)
        return k, rc, dt, f"ERROR javac_rc={info['javac_rc']} (no warnings parsed)"
    st.write(tag, k, "OK", ws, dt * 1000, info)
    return k, rc, dt, f"compiled={fo}/{ft} warnings={sum(allby.values())} ThreadLocalUsage={by.get('ThreadLocalUsage', 0)}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tool", choices=["codeql", "errorprone"])
    ap.add_argument("--split", default="all", choices=["all", "design", "heldout"])
    ap.add_argument("--which", default="both", choices=["pre", "both"])
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--ids", default="")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    tag = {"codeql": "bl-codeql", "errorprone": "bl-errorprone"}[a.tool]
    jobs = st.jobs_of(a.split, a.which)
    if a.ids: jobs = {j: v for j, v in jobs.items() if st.key(j) in set(a.ids.split(","))}
    todo = []
    for j, java in sorted(jobs.items()):
        p = os.path.join(ROOT, "out", tag, st.key(j) + ".json")
        if os.path.exists(p) and not a.force:
            stt = json.load(open(p, encoding="utf-8")).get("status")
            if st.cached_result_current(tag, j, stt): continue
        todo.append((j, java))
    print(f"{tag}: {len(jobs)} releases in split {a.split} ({a.which}), {len(todo)} to run (jobs={a.jobs})", flush=True)
    fn = {"codeql": run_codeql, "errorprone": run_errorprone}[a.tool]
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(fn, j, java, a.timeout) for j, java in todo]
        for f in as_completed(futs):
            try: k, rc, dt, msg = f.result()
            except Exception as e: k, rc, dt, msg = "?", -1, 0, f"EXC {e}"
            print(f"{time.strftime('%H:%M:%S')} rc={rc} {dt:6.1f}s {k} | {msg}", flush=True)


if __name__ == "__main__":
    main()
