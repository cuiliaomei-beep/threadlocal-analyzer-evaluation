"""Run only the study SpotBugs-TL plugin (-effort:max -low).
Usage: python gt/25_baselines.py spotbugs-tl --split all --jobs 3
Stock SpotBugs is exclusively gt/42_spotbugs_full.py: all default-enabled
detectors, no visitor restriction. This runner retains the published plugin's
four detector selection and its specified obligation mapping.
"""
import argparse, csv, json, os, subprocess, time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

HERE = os.path.join(RUNTIME_ROOT, "gt"); ROOT = RUNTIME_ROOT
WSL_ROOT = BASH_ROOT
JAVA = java_command()
SPOTBUGS = tool_command("TL_SPOTBUGS_JAR", "~/tools/spotbugs-4.9.8/lib/spotbugs.jar")
PLUGIN = "baselines/spotbugs-tl/target/spotbugs-threadlocal-plugin-1.0-SNAPSHOT.jar"
TOOLS = {
    "spotbugs-tl": {"tag": "bl-spotbugs-tl",
                    "args": f"-pluginList {PLUGIN} -visitors TL_SCO_MissingRemoveDetector,TL_CLP_StaticThreadLocalDetector,"
                            "TL_CPM_UnbalancedContextDetector,TL_HVR_HeavyValueRetentionDetector",
                    "map": {"TL_SCO_MISSING_REMOVE": ["O1"], "TL_CLP_STATIC_THREADLOCAL": ["O3"],
                            "TL_CPM_UNBALANCED_CONTEXT": ["O2"], "TL_HVR_HEAVY_VALUE_RETENTION": ["O4"]}},
}


def jars_of(split):
    sp = list(csv.DictReader(open(os.path.join(HERE, "split", "split_frozen.csv"), encoding="utf-8-sig")))
    pairs = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "jar_pairs_verified.csv"), encoding="utf-8-sig"))}
    jars = []
    for r in sp:
        if split != "all" and r["split"] != split: continue
        if r["pair_status"] != "VALID" or r["id"] not in pairs: continue
        for k in ("pre_path", "post_path"):
            j = pairs[r["id"]][k].replace("\\", "/")
            if j not in jars: jars.append(j)
    return jars


def key(jar_rel):
    parts = jar_rel.split("/")
    return f"{parts[-3]}-{parts[-2]}"


def write(tag, k, status, warnings, ms, extra=None):
    d = {"jar": k, "status": status, "tool": tag, "tlCount": 0, "tlUnknownCtx": 0, "time_ms": int(ms), "warnings": warnings}
    if extra: d.update(extra)
    os.makedirs(os.path.join(ROOT, "out", tag), exist_ok=True)
    json.dump(d, open(os.path.join(ROOT, "out", tag, k + ".json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def warn(rule, obligations, cls, method, line, detail):
    return {"rule": rule, "obligations": obligations, "dominant": obligations[0], "severity": "n/a", "tier": "REPORT",
            "tl": cls, "tlKind": "BASELINE", "tlDeclClass": cls, "tlRuntimeClass": None, "method": method, "methodClass": cls,
            "line": line, "detail": detail, "sites": None, "facts": {}}


def run(tool, jar_rel, timeout):
    cfg = TOOLS[tool]; tag = cfg["tag"]; k = key(jar_rel)
    xml_rel = f"out/{tag}/{k}.xml"
    cmd = (f"cd {shell_path(WSL_ROOT)} && mkdir -p out/{tag} && rm -f {xml_rel} && {JAVA} -Xmx4g -jar {SPOTBUGS} -textui -effort:max -low "
           f"{cfg['args']} -xml:withMessages -output {xml_rel} gt/{jar_rel}")
    t0 = time.time()
    try:
        res = subprocess.run(bash_argv(cmd), capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
        rc, err = res.returncode, (res.stderr or "") + (res.stdout or "")
    except subprocess.TimeoutExpired:
        rc, err = -9, "timeout"
    dt = time.time() - t0
    path = os.path.join(ROOT, xml_rel)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        write(tag, k, "TIMEOUT" if rc == -9 else "ERROR", [], dt * 1000, {"error": err[-400:]})
        return k, rc, dt, "no xml"
    ws, total = [], 0
    try:
        for bi in ET.parse(path).getroot().iter("BugInstance"):
            total += 1
            t = bi.get("type")
            if t not in cfg["map"]: continue
            cls = bi.find("Class"); cn = cls.get("classname") if cls is not None else ""
            me = bi.find("Method"); fl = bi.find("Field"); sl = bi.find("SourceLine")
            method = f"<{cn}: {me.get('name')}{me.get('signature')}>" if me is not None else None
            line = int(sl.get("start")) if sl is not None and (sl.get("start") or "").isdigit() else 0
            detail = (bi.findtext("LongMessage") or "").strip()[:160] + (f" field={fl.get('name')}" if fl is not None else "")
            ws.append(warn(t, cfg["map"][t], cn, method, line, detail))
    except ET.ParseError as e:
        write(tag, k, "ERROR", [], dt * 1000, {"error": f"xml parse: {e}"})
        return k, rc, dt, "xml parse error"
    write(tag, k, "OK", ws, dt * 1000, {"instances_total": total, "spotbugs_version": "4.9.8"})
    return k, rc, dt, f"instances={total} scored={len(ws)}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("tool", choices=sorted(TOOLS))
    ap.add_argument("--split", default="heldout")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=1500)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    tag = TOOLS[a.tool]["tag"]
    todo = []
    jars = jars_of(a.split)
    for j in jars:
        p = os.path.join(ROOT, "out", tag, key(j) + ".json")
        if not a.force and os.path.exists(p):
            try:
                if json.load(open(p, encoding="utf-8")).get("status") == "OK": continue
            except Exception:
                pass
        todo.append(j)
    print(f"{tag}: {len(jars)} jars in split {a.split}, {len(todo)} to run (jobs={a.jobs})", flush=True)
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(run, a.tool, j, a.timeout) for j in todo]
        for f in as_completed(futs):
            k, rc, dt, msg = f.result()
            print(f"{time.strftime('%H:%M:%S')} rc={rc} {dt:6.1f}s {k} | {msg}", flush=True)
