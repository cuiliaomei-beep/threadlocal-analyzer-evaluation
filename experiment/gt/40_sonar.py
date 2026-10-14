"""SonarQube Community Build 26.8.0.126808 with the recorded Sonar way profile.
Usage: python gt/40_sonar.py --split all --which both --jobs 2
All fetched raw issue pages and scanner output are retained; legacy normalized
JSON tiers are not the current paper's selection policy. Use
scripts/recompute_protocols.py for dedicated/related native statistics.
Release bytecode and available Maven dependencies are supplied to the analyzer;
this does not establish complete dependency or semantic coverage.
Credentials are read at runtime from TL_SONAR_TOKEN_FILE, never included here.
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
TAG = "bl-sonar"
SCANNER = tool_command("TL_SONAR_SCANNER", "~/tools/sonarqube/sonar-scanner-8.1.0.6389-linux-x64/bin/sonar-scanner")
TOKEN = tool_command("TL_SONAR_TOKEN_FILE", "~/.local/share/threadlocal-evaluation/sonar/token.txt")
SONAR_URL = os.environ.get("TL_SONAR_URL", "http://localhost:9000")

SONAR_SH = r"""
set -u
{env}
URL={url}
cd {root}
W=out/{tag}/work/{k}
mkdir -p $W
JAR=$(pwd)/gt/{jar}
I=out/bl-infer/work/{k}
if {infer_ready} && [ -s $I/cp.txt ]; then cp $I/cp.txt $W/cp.txt; echo CP_REUSED
elif [ ! -s $W/cp.txt ] && [ -f {sd}/{art}-{ver}.pom ]; then
  cp {sd}/{art}-{ver}.pom $W/pom.xml
  (cd $W && timeout 600 mvn -q -B -f pom.xml dependency:build-classpath -Dmdep.outputFile=cp.txt > mvn.log 2>&1); echo CP_RESOLVED
fi
LIBS=$( [ -s $W/cp.txt ] && tr ':' ',' < $W/cp.txt || true )
rm -rf $W/classes $W/scannerwork; mkdir -p $W/classes
(cd $W/classes && unzip -q -o "$JAR" 2>/dev/null || true)
echo CLASSES=$(find $W/classes -name '*.class' | wc -l)
KEY=tl-{k}
TOKEN=$(cat {token})
timeout {t1} {scanner} -Dsonar.host.url="$URL" -Dsonar.token=$TOKEN -Dsonar.projectKey=$KEY -Dsonar.projectName=$KEY \
  -Dsonar.projectBaseDir=$(pwd)/{sd} -Dsonar.sources=src -Dsonar.java.binaries=$(pwd)/$W/classes ${{LIBS:+-Dsonar.java.libraries=$LIBS}} \
  -Dsonar.java.source={lvl} -Dsonar.scm.disabled=true -Dsonar.sourceEncoding=UTF-8 -Dsonar.working.directory=$(pwd)/$W/scannerwork \
  -Dsonar.scanner.javaOpts=-Xmx4g > $W/scanner.log 2>&1
echo SCANNER_RC=$?
grep -E "ANALYSIS SUCCESSFUL|EXECUTION FAILURE" $W/scanner.log | head -2
TID=$(grep -oE "^ceTaskId=.*" $W/scannerwork/report-task.txt 2>/dev/null | cut -d= -f2)
S=NONE
if [ -n "$TID" ]; then
  for i in $(seq 1 240); do
    S=$(curl -s -u $TOKEN: "$URL/api/ce/task?id=$TID" | grep -oE '"status":"[A-Z_]+"' | head -1 | cut -d'"' -f4)
    case "$S" in SUCCESS|FAILED|CANCELED) break;; esac; sleep 5
  done
fi
echo CE_STATUS=$S
rm -f $W/issues_*.json
if [ "$S" = SUCCESS ]; then
  for p in $(seq 1 20); do
    curl -s -u $TOKEN: "$URL/api/issues/search?components=$KEY&ps=500&p=$p&resolved=false" -o $W/issues_$p.json
    if grep -q '"issues":\[\]' $W/issues_$p.json; then rm -f $W/issues_$p.json; break; fi
  done
fi
cp $W/scanner.log out/{tag}/{k}.sonar.log
curl -s -u $TOKEN: -X POST "$URL/api/projects/delete?project=$KEY" > /dev/null
rm -rf $W/classes
echo DONE
"""


def server_up():
    rc, out, _ = st.wsl("curl -s -m 5 " + shell_path(SONAR_URL + "/api/system/status"), 30)
    return '"UP"' in out


def ensure_server():
    if server_up(): return True
    print("starting SonarQube server ...", flush=True)
    rc, out, _ = st.wsl(f"{ENV}; bash {shell_path(WSL_ROOT + '/gt/sonar_server.sh')} start", 900)
    print(out.strip()[-500:], flush=True)
    return server_up()


def run_sonar(jar_rel, java, timeout):
    k = st.key(jar_rel); sd = st.src_dir(jar_rel); parts = jar_rel.split("/")
    if st.n_java(jar_rel) == 0:
        st.write(TAG, k, "NO_SOURCES", [], 0, {"n_java": 0}); return k, 0, 0.0, "NO_SOURCES"
    try: lvl = max(8, min(21, int(java)))
    except ValueError: lvl = 8
    try:
        with open(os.path.join(ROOT, "out", "bl-infer", k + ".json"), encoding="utf-8") as f:
            infer_ready = json.load(f).get("status") == "OK"
    except (OSError, ValueError):
        infer_ready = False
    a = dict(env=ENV, root=shell_path(WSL_ROOT), tag=TAG, k=k, sd=sd, jar=jar_rel, art=parts[2], ver=parts[3], lvl=lvl,
             infer_ready="true" if infer_ready else "false", t1=int(timeout * 0.6), scanner=SCANNER, token=TOKEN, url=shell_path(SONAR_URL))
    os.makedirs(os.path.join(ROOT, "out", TAG, "work"), exist_ok=True)
    sh = os.path.join(ROOT, "out", TAG, "work", k + ".sh")
    open(sh, "w", encoding="utf-8", newline="\n").write(SONAR_SH.format(**a))
    rc, out, dt = st.wsl(f"bash {shell_path(WSL_ROOT + '/out/' + TAG + '/work/' + k + '.sh')}", timeout + 600)
    m = re.search(r"CLASSES=(\d+)", out); ncls = int(m.group(1)) if m else 0
    m = re.search(r"SCANNER_RC=(\d+)", out); src = int(m.group(1)) if m else None
    m = re.search(r"CE_STATUS=(\w+)", out); ce = m.group(1) if m else None
    info = {"n_java": st.n_java(jar_rel), "classes_in_jar": ncls, "cp": "reused" if "CP_REUSED" in out else ("resolved" if "CP_RESOLVED" in out else "none"),
            "scanner_rc": src, "ce_status": ce, "sonarqube": "26.8.0.126808"}
    if "DONE" not in out or src != 0 or ce != "SUCCESS":
        status = "TIMEOUT" if rc == -9 or src == 124 else "ERROR"
        log = os.path.join(ROOT, "out", TAG, k + ".sonar.log")
        tail = open(log, encoding="utf-8", errors="replace").read()[-600:] if os.path.exists(log) else out[-600:]
        info["error"] = tail; st.write(TAG, k, status, [], dt * 1000, info)
        return k, rc, dt, f"{status} scanner_rc={src} ce={ce}"
    wd = os.path.join(ROOT, "out", TAG, "work", k)
    issues = []
    for f in sorted(os.listdir(wd)):
        if f.startswith("issues_") and f.endswith(".json"):
            try: issues += json.load(open(os.path.join(wd, f), encoding="utf-8")).get("issues", [])
            except json.JSONDecodeError: pass
    ws, by, allby = [], Counter(), Counter()
    for it in issues:
        rule = it.get("rule", ""); allby[rule] += 1
        comp = it.get("component", ""); path = comp.split(":", 1)[1] if ":" in comp else ""
        if not path.endswith(".java"): continue
        rel = sd + "/" + path; line = int(it.get("line") or 0); msg = it.get("message", "")
        cls = st.class_of(rel, sd)
        if rule == "java:S5164":
            w = st.warn("SONAR_S5164", cls, None, line, msg[:140]); w["obligations"] = ["O1"]; w["dominant"] = "O1"; ws.append(w); by[rule] += 1
        else:
            why = st.touches(os.path.join(ROOT, rel.replace("/", os.sep)), line, line, msg)
            if not why: continue
            w = st.warn("SONAR_" + rule.replace("java:", ""), cls, None, line, f"{msg[:140]} ({why})"); w["tier"] = "NOTE"; ws.append(w); by[rule] += 1
    info.update({"issues_total": len(issues), "issues_by_rule": dict(allby.most_common(20)), "threadlocal_rule_issues": by.get("java:S5164", 0),
                 "other_rules_touching_threadlocal": sum(v for r, v in by.items() if r != "java:S5164")})
    st.write(TAG, k, "OK", ws, dt * 1000, info)
    return k, rc, dt, f"classes={ncls} issues={len(issues)} S5164={by.get('java:S5164', 0)}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="all", choices=["all", "design", "heldout"])
    ap.add_argument("--which", default="both", choices=["pre", "both"])
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=2400)
    ap.add_argument("--ids", default="")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if not ensure_server(): print("SonarQube server is not up; aborting"); sys.exit(2)
    jobs = st.jobs_of(a.split, a.which)
    if a.ids: jobs = {j: v for j, v in jobs.items() if st.key(j) in set(a.ids.split(","))}
    todo = []
    for j, java in sorted(jobs.items()):
        p = os.path.join(ROOT, "out", TAG, st.key(j) + ".json")
        if os.path.exists(p) and not a.force:
            if st.cached_result_current(TAG, j, json.load(open(p, encoding="utf-8")).get("status")): continue
        todo.append((j, java))
    print(f"{TAG}: {len(jobs)} releases in split {a.split} ({a.which}), {len(todo)} to run (jobs={a.jobs})", flush=True)
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(run_sonar, j, java, a.timeout) for j, java in todo]
        for f in as_completed(futs):
            try: k, rc, dt, msg = f.result()
            except Exception as e: k, rc, dt, msg = "?", -1, 0, f"EXC {e}"
            print(f"{time.strftime('%H:%M:%S')} rc={rc} {dt:6.1f}s {k} | {msg}", flush=True)


if __name__ == "__main__":
    main()
