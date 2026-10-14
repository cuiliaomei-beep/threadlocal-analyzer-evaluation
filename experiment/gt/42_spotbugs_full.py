"""Run the unrestricted stock SpotBugs configuration in a durable, separate queue.

Windows: python -u gt/42_spotbugs_full.py --jobs 3
Raw XML and every diagnostic are preserved in out/bl-spotbugs-full. This runner
does not apply a ThreadLocal relevance filter or modify existing evaluations.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

ROOT = EXPERIMENT_ROOT
OUT = ROOT / "out" / "bl-spotbugs-full"
SPEC = importlib.util.spec_from_file_location("source_tools", ROOT / "gt" / "27_source_tools.py")
ST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ST)
LOCK = threading.Lock()
ACTIVE = {}


def stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temp = path.with_suffix(path.suffix + ".part")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)


def event(message):
    line = f"{stamp()} {message}"
    with LOCK:
        print(line, flush=True)
        with (OUT / "events.log").open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")


def phase(key, name):
    with LOCK:
        ACTIVE[key] = {"phase": name, "updated": stamp()}


def linux(path):
    return bash_path(path.resolve())


def wsl(command, timeout):
    # GNU timeout inside analysis scripts terminates the Linux process group.
    return subprocess.run(bash_argv(command),
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def cached_cp(key):
    for tag in ("bl-infer", "bl-codeql", "bl-errorprone", "bl-sonar"):
        path = ROOT / "out" / tag / "work" / key / "cp.txt"
        if path.is_file() and path.stat().st_size and path.read_text(encoding="utf-8").strip():
            return path
    return None


def parse_xml(path):
    root = ET.parse(path).getroot()
    diagnostics = []
    for bug in root.findall("BugInstance"):
        locations = [dict(node.attrib) for node in bug.iter("SourceLine")]
        classes = [dict(node.attrib) for node in bug.findall("Class")]
        methods = [dict(node.attrib) for node in bug.findall("Method")]
        fields = [dict(node.attrib) for node in bug.findall("Field")]
        primary = next((c for c in classes if c.get("primary") == "true"), classes[0] if classes else {})
        loc = next((s for s in locations if s.get("primary") == "true"), locations[0] if locations else {})
        diagnostics.append({"rule": bug.get("type"), "tier": "RAW", "obligations": [],
                            "dominant": "-", "priority": bug.get("priority"), "rank": bug.get("rank"),
                            "category": bug.get("category"), "instance_hash": bug.get("instanceHash"),
                            "class": primary.get("classname", ""), "line": loc.get("start"),
                            "short_message": bug.findtext("ShortMessage", ""),
                            "message": bug.findtext("LongMessage", ""),
                            "classes": classes, "methods": methods, "fields": fields,
                            "locations": locations})
    errors_node = root.find("Errors")
    missing = [n.text or "" for n in root.findall("./Errors/MissingClass")]
    errors = [ET.tostring(n, encoding="unicode") for n in root.findall("./Errors/Error")]
    error_count = max(len(errors), int(errors_node.get("errors", "0"))) if errors_node is not None else 0
    missing_count = max(len(missing), int(errors_node.get("missingClasses", "0"))) if errors_node is not None else 0
    summary = root.find("FindBugsSummary")
    return {"warnings": diagnostics, "instances_total": len(diagnostics),
            "by_rule": dict(Counter(d["rule"] for d in diagnostics)),
            "missing_classes": missing, "missing_class_count": missing_count,
            "analysis_errors": errors, "analysis_error_count": error_count,
            "xml_summary": dict(summary.attrib) if summary is not None else {},
            "xml_version": root.get("version"),
            "xml_project": ET.tostring(root.find("Project"), encoding="unicode") if root.find("Project") is not None else ""}


def run_one(jar, config, args):
    key = ST.key(jar)
    started = time.monotonic()
    started_at = stamp()
    phase(key, "dependency-preparation")
    directory = OUT / "work" / key
    directory.mkdir(parents=True, exist_ok=True)
    for stale in (directory / "prep-status.txt", OUT / (key + ".xml")):
        if stale.exists():
            stale.unlink()
    cp = cached_cp(key)
    sd = ROOT / ST.src_dir(jar)
    parts = jar.split("/")
    pom = sd / f"{parts[-3]}-{parts[-2]}.pom"
    if not pom.is_file():
        candidates = list(sd.glob("*.pom")) if sd.is_dir() else []
        pom = candidates[0] if len(candidates) == 1 else None
    q = shlex.quote
    dest = linux(directory)
    output_xml = linux(OUT / (key + ".xml"))
    source_jar = ROOT / "gt" / jar
    commands = ["set -eu", shell_environment(), f"D={q(dest)}",
                f"W={q(config['stage'])}/{q(key)}", 'mkdir -p "$W"',
                f"cp {q(linux(source_jar))} \"$W/input.jar\"",
                'rm -f "$W/cp.txt" "$W/mvn.log"', 'DEP_RC=0']
    if cp:
        commands += [f"cp {q(linux(cp))} \"$W/cp.txt\"", "DEP_MODE=REUSED"]
    elif pom:
        commands += [f"cp {q(linux(pom))} \"$W/pom.xml\"", "DEP_MODE=RESOLVED",
                     f'(cd "$W" && timeout --kill-after=30s {args.dependency_timeout}s mvn -q -B -f pom.xml dependency:build-classpath -Dmdep.outputFile=cp.txt > mvn.log 2>&1) || DEP_RC=$?',
                     'cp "$W/mvn.log" "$D/mvn.log" 2>/dev/null || true']
    else:
        commands += ["DEP_MODE=NO_POM"]
    commands += ['CP_TOTAL=0; CP_MISSING=0; : > "$W/auxclasspath.txt"; : > "$W/cp-missing.txt"',
                 'if [ -s "$W/cp.txt" ]; then',
                 '  IFS=: read -r -a CP_ENTRIES < "$W/cp.txt" || true',
                 '  for entry in "${CP_ENTRIES[@]}"; do',
                 '    [ -n "$entry" ] || continue; CP_TOTAL=$((CP_TOTAL + 1))',
                 '    if [ -e "$entry" ]; then printf "%s\\n" "$entry" >> "$W/auxclasspath.txt"',
                 '    else CP_MISSING=$((CP_MISSING + 1)); printf "%s\\n" "$entry" >> "$W/cp-missing.txt"; fi',
                 '  done', 'fi',
                 'cp "$W/auxclasspath.txt" "$D/auxclasspath.txt"',
                 'cp "$W/cp-missing.txt" "$D/cp-missing.txt"',
                 'cp "$W/cp.txt" "$D/cp.txt" 2>/dev/null || true',
                 'printf "DEP_MODE=%s\\nDEP_RC=%s\\nCP_TOTAL=%s\\nCP_MISSING=%s\\n" "$DEP_MODE" "$DEP_RC" "$CP_TOTAL" "$CP_MISSING" > "$D/prep-status.txt"']
    prep_script = directory / "prepare.sh"
    prep_script.write_text("\n".join(commands) + "\n", encoding="utf-8", newline="\n")
    prep = wsl("bash " + q(linux(prep_script)), args.dependency_timeout + 120)
    (directory / "prepare.log").write_text(prep.stdout + prep.stderr, encoding="utf-8")
    preparation = {}
    prep_status = directory / "prep-status.txt"
    if prep_status.exists():
        preparation = dict(line.split("=", 1) for line in prep_status.read_text().splitlines() if "=" in line)
    result = {"jar": key, "jar_path": jar, "input_sha256": sha(source_jar),
              "tool": "bl-spotbugs-full", "configuration_sha256": config["fingerprint"],
              "started": started_at, "dependencies": preparation,
              "classpath_source": str(cp.relative_to(ROOT)) if cp else (str(pom.relative_to(ROOT)) if pom else None),
              "dependency_input_sha256": sha(cp) if cp else (sha(pom) if pom else None),
              "source_available": (sd / "src").is_dir(), "warnings": []}
    if prep.returncode != 0 or not prep_status.exists():
        result.update(status="PREPARATION_FAILED", preparation_rc=prep.returncode)
    else:
        phase(key, "spotbugs-analysis")
        command = [java_command(), f"-Xmx{q(args.xmx)}", "-Duser.language=en",
                   '-jar ' + tool_command("TL_SPOTBUGS_JAR", "~/tools/spotbugs-4.9.8/lib/spotbugs.jar"),
                   "-textui -effort:max -low -exitcode -xml:withMessages",
                   f'-auxclasspathFromFile {q(config["stage"] + "/" + key + "/auxclasspath.txt")}',
                   f'-output {q(output_xml)}', f'{q(config["stage"] + "/" + key + "/input.jar")}']
        script = directory / "analysis.sh"
        script.write_text("set -u\n" + f"timeout --kill-after=30s {args.timeout}s " + " ".join(command) + "\n", encoding="utf-8", newline="\n")
        before = time.monotonic()
        analysis = wsl("bash " + q(linux(script)), args.timeout + 120)
        result["analysis_time_ms"] = round((time.monotonic() - before) * 1000)
        result["exit_code"] = analysis.returncode
        (OUT / (key + ".log")).write_text(analysis.stdout + analysis.stderr, encoding="utf-8")
        xml = OUT / (key + ".xml")
        if xml.is_file():
            try:
                result.update(parse_xml(xml))
                result["xml_sha256"] = sha(xml)
            except (ET.ParseError, ValueError) as error:
                result["xml_parse_error"] = str(error)
        if analysis.returncode == 124:
            result["status"] = "TIMEOUT"
        elif analysis.returncode == 137:
            result["status"] = "KILLED"
        elif "xml_parse_error" in result or "xml_sha256" not in result:
            result["status"] = "ERROR"
        elif result["analysis_error_count"] or analysis.returncode & 4 or analysis.returncode not in range(8):
            result["status"] = "ERROR"
        elif (result["missing_class_count"] or analysis.returncode & 2
              or int(preparation.get("CP_MISSING", "0")) or preparation.get("DEP_RC") != "0"):
            result["status"] = "PARTIAL"
        else:
            result["status"] = "OK"
        result["classpath_sha256"] = sha(directory / "auxclasspath.txt")
    result["ended"] = stamp()
    result["time_ms"] = round((time.monotonic() - started) * 1000)
    result["coverage_incomplete"] = result["status"] != "OK"
    save(OUT / (key + ".json"), result)
    event(f"end {key} status={result['status']} seconds={result['time_ms']/1000:.1f} warnings={result.get('instances_total', 0)} missing={result.get('missing_class_count', 0)} errors={result.get('analysis_error_count', 0)}")
    with LOCK:
        ACTIVE.pop(key, None)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--dependency-timeout", type=int, default=600)
    parser.add_argument("--xmx", default="4g")
    parser.add_argument("--limit", type=int, help="Smoke run: first N inventory releases; full run remains 264")
    parser.add_argument("--release", action="append", default=[],
                        help="Smoke run: artifact-version key, repeatable or comma-separated")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 3:
        parser.error("Use one to three workers for this queue")
    if not re.fullmatch(r"[1-9][0-9]*[mgMG]", args.xmx):
        parser.error("Invalid Java heap size")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    OUT.mkdir(parents=True, exist_ok=True)
    lock_file = (OUT / "queue.lock").open("a+b")
    if os.name == "nt":
        import msvcrt
        lock_file.seek(0); lock_file.write(b"0"); lock_file.flush(); lock_file.seek(0)
        try:
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise SystemExit("Another SpotBugs full queue is already running")
    else:
        import fcntl
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit("Another SpotBugs full queue is already running")
    jars = list(ST.jobs_of("all", "both"))
    assert len(jars) == 264, f"Input release inventory changed: {len(jars)}"
    assert len(set(ST.key(j) for j in jars)) == len(jars), "Release key collision"
    inventory_total = len(jars)
    requested = {key for item in args.release for key in item.split(",") if key}
    if requested:
        unknown = requested - {ST.key(j) for j in jars}
        if unknown:
            parser.error("Unknown release keys: " + ", ".join(sorted(unknown)))
        jars = [j for j in jars if ST.key(j) in requested]
    if args.limit is not None:
        jars = jars[:args.limit]
    scope = "smoke-subset" if requested or args.limit is not None else "full-inventory"
    for jar in jars:
        assert (ROOT / "gt" / jar).is_file(), f"Missing input jar: {jar}"
        assert re.fullmatch(r"[A-Za-z0-9_.+~-]+", ST.key(jar)), "Unsafe release key"
    spotbugs = tool_command("TL_SPOTBUGS_JAR", "~/tools/spotbugs-4.9.8/lib/spotbugs.jar")
    java = java_command()
    initial = wsl(shell_environment() + '; printf "HOME_PATH=%s\\n" "$HOME"; '
                  + f'sha256sum {spotbugs}; {java} -version 2>&1; '
                  + f'{java} -jar {spotbugs} -textui -effort:max -low -printConfiguration', 90)
    if initial.returncode != 0 or "SpotBugs 4.9.8" not in initial.stdout:
        raise RuntimeError("SpotBugs/JDK preflight failed")
    (OUT / "configuration.txt").write_text(initial.stdout, encoding="utf-8")
    (OUT / "preflight.log").write_text(initial.stderr, encoding="utf-8")
    home = re.search(r"^HOME_PATH=(.+)$", initial.stdout, re.M).group(1)
    stage = bash_path(os.environ.get("TL_SPOTBUGS_STAGE", home + "/.cache/threadlocal-evaluation/spotbugs-full-" + hashlib.sha256(str(ROOT).encode()).hexdigest()[:10]))
    if stage.startswith("~/"): stage = home + stage[1:]
    config = {"tool": "SpotBugs 4.9.8", "java": "JDK 21", "effort": "max", "confidence": "low",
              "detectors": "stock enabled detectors, no visitors/omitVisitors/chooseVisitors restriction",
              "plugin_policy": "core stock plugin; no study TL plugin",
              "warning_filter": "none; all emitted diagnostics retained as RAW, not scored",
              "auxclasspath": "cached Maven dependency paths checked for existence; resolve from release POM when uncached",
              "stage": stage, "xmx": args.xmx,
              "analysis_timeout_seconds": args.timeout, "dependency_timeout_seconds": args.dependency_timeout,
              "runner_sha256": sha(Path(__file__)), "configuration_output_sha256": sha(OUT / "configuration.txt")}
    config["fingerprint"] = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    save(OUT / "config.json", config)
    releases = [{"release": ST.key(j), "jar_path": j, "input_sha256": sha(ROOT / "gt" / j),
                 "jar_bytes": (ROOT / "gt" / j).stat().st_size} for j in jars]
    save(OUT / "inputs.json", {"scope": scope, "inventory_total": inventory_total,
                              "selected_total": len(jars), "releases": releases,
                              "split_sha256": sha(ROOT / "gt/split/split_frozen.csv"),
                              "pair_table_sha256": sha(ROOT / "gt/jar_pairs_verified.csv")})
    done = {}
    todo = []
    for jar in jars:
        path = OUT / (ST.key(jar) + ".json")
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            d = {}
        xml_path = OUT / (ST.key(jar) + ".xml")
        current_cp = cached_cp(ST.key(jar))
        if d.get("configuration_sha256") == config["fingerprint"] and d.get("input_sha256") == sha(ROOT / "gt" / jar) and d.get("status") == "OK" and current_cp and d.get("dependency_input_sha256") == sha(current_cp) and xml_path.exists() and d.get("xml_sha256") == sha(xml_path):
            done[jar] = d
        else:
            todo.append(jar)
    # Start one large release and two typical releases; then spread the large jars.
    big = sorted([j for j in todo if (ROOT / "gt" / j).stat().st_size > 10 * 1024**2], key=lambda j: (ROOT / "gt" / j).stat().st_size, reverse=True)
    small = sorted([j for j in todo if j not in big], key=lambda j: (ROOT / "gt" / j).stat().st_size, reverse=True)
    ordered = []
    while small or big:
        if big: ordered.append(big.pop(0))
        for _ in range(32):
            if small: ordered.append(small.pop(0))
    started = stamp()
    save(OUT / "state.json", {"status": "starting", "pid": os.getpid(), "started": started,
                             "updated": stamp(), "jobs": args.jobs, "total": len(jars),
                             "completed": len(done), "statuses": dict(Counter(d['status'] for d in done.values())),
                             "active": {}, "queued": len(ordered)})
    event(f"start full-stock SpotBugs queue releases={len(jars)} cached={len(done)} pending={len(ordered)} jobs={args.jobs} timeout={args.timeout}s")
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {executor.submit(run_one, jar, config, args): jar for jar in ordered}
        while futures:
            completed, _ = wait(futures, timeout=15, return_when=FIRST_COMPLETED)
            for future in completed:
                jar = futures.pop(future)
                try:
                    done[jar] = future.result()
                except Exception as error:
                    result = {"jar": ST.key(jar), "jar_path": jar, "status": "RUNNER_ERROR", "error": repr(error),
                              "configuration_sha256": config["fingerprint"], "ended": stamp(), "warnings": []}
                    save(OUT / (ST.key(jar) + ".json"), result)
                    done[jar] = result
                    with LOCK:
                        ACTIVE.pop(ST.key(jar), None)
                    event(f"runner-error {ST.key(jar)} {type(error).__name__}")
            with LOCK:
                active = dict(ACTIVE)
            save(OUT / "state.json", {"status": "running", "pid": os.getpid(), "started": started,
                                     "updated": stamp(), "jobs": args.jobs, "total": len(jars), "completed": len(done),
                                     "statuses": dict(Counter(d['status'] for d in done.values())),
                                     "active": active, "queued": max(0, len(futures)-len(active))})
    counts = Counter(d["status"] for d in done.values())
    final = {"status": "finished" if counts.get("OK", 0) == len(jars) else "finished_with_incomplete_or_failed_runs",
             "pid": os.getpid(), "started": started, "updated": stamp(), "jobs": args.jobs,
             "total": len(jars), "completed": len(done), "statuses": dict(counts), "active": {}, "queued": 0}
    save(OUT / "state.json", final)
    save(OUT / "audit.json", {**final, "configuration_sha256": config["fingerprint"],
                             "runs": [{k:v for k,v in d.items() if k not in ("warnings", "xml_project", "analysis_errors")} for d in done.values()]})
    event(f"finished releases={len(done)} statuses={dict(counts)}")


if __name__ == "__main__":
    main()
