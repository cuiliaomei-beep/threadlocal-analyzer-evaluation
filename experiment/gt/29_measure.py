"""Step 29: cost measurement. Every tool configuration is run once more on the pre-fix releases of a split, ONE JOB AT A
TIME on an otherwise idle machine. This historical protocol includes the restricted
SpotBugs UnreadFields configuration; it is not a cost rerun of the full stock
configuration in 42_spotbugs_full.py. Measurements use /usr/bin/time -v (gt/measure.sh).

  python gt/29_measure.py run --split heldout [--tools tldoctor2,typestate,spotbugs,...] [--force]
  python gt/29_measure.py report --split heldout          -> COST-REPORT.md, out/measure/measure_<split>.csv

Recorded per (tool, release): wall-clock, user and system CPU seconds, the maximum resident set size of the largest
process (exact) and the largest summed RSS of the tool's process tree (sampled every 0.5 s).
What is measured is the analysis command itself, with the same options as in the evaluation runs:
  tldoctor2 / typestate : java -Xmx6g -jar tldoctor2.jar [--mode typestate] --jar X
  spotbugs / spotbugs-tl: java -Xmx4g -jar spotbugs.jar -effort:max -low [-pluginList ...] -visitors <scored detectors> X
  pmd / pmd-tl          : pmd check -d <sources> -R <rules> --aux-classpath X -t 1
  infer                 : infer capture -- javac ... ; infer analyze -j 1   (two phases, reported separately and summed)
                          the file list and class path prepared by the evaluation run are reused; dependency resolution and
                          the pruning of non-compiling files are preparation and are not part of the measurement
  infer-tl              : the two post-processing scripts; its historical total is Infer capture + postprocessing, excluding the Infer analysis phase
All tools are restricted to one analysis thread where they offer the option (PMD -t 1, Infer -j 1) so that wall-clock
times are comparable; tldoctor2 and SpotBugs are single-threaded analyses on a JVM with default GC threads.

File system. Inputs (jars, sources, file lists) and all tool outputs are staged on the Linux ext4 file system (~/tlbench),
not on the Windows drive: a first attempt with everything on the 9p-mounted Windows drive made PMD's XML renderer ten
times slower in wall-clock time (70 s instead of 8 s on HikariCP-java6, same CPU time), an artefact of the mount and not
of the tool. The records of that attempt are kept in out/measure/measure_<split>.9p.csv.
"""
import argparse, hashlib, csv, json, os, re, subprocess, sys, time
from collections import defaultdict

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

HERE = os.path.join(RUNTIME_ROOT, "gt"); ROOT = RUNTIME_ROOT
W = shell_path(BASH_ROOT)
STAGE = shell_path(os.environ.get("TL_COST_STAGE", "~/.cache/threadlocal-evaluation/cost-" + hashlib.sha256(ROOT.encode()).hexdigest()[:10]))
ENV = shell_environment()
JAVA = java_command()
SB = tool_command("TL_SPOTBUGS_JAR", "~/tools/spotbugs-4.9.8/lib/spotbugs.jar")
PMD = tool_command("TL_PMD", "~/tools/pmd-bin-7.28.0/bin/pmd")
INFER = tool_command("TL_INFER", "~/tools/infer/bin/infer")
PMD_RULES = ",".join(f"category/java/{c}.xml" for c in
                     ["bestpractices", "codestyle", "design", "documentation", "errorprone", "multithreading", "performance", "security"])
SBTL = ("-pluginList baselines/spotbugs-tl/target/spotbugs-threadlocal-plugin-1.0-SNAPSHOT.jar -visitors TL_SCO_MissingRemoveDetector,"
        "TL_CLP_StaticThreadLocalDetector,TL_CPM_UnbalancedContextDetector,TL_HVR_HeavyValueRetentionDetector")
ALL = ["tldoctor2", "typestate", "spotbugs-tl", "pmd-tl", "spotbugs-restricted-cost", "pmd", "infer", "infer-tl"]


def releases(split):
    sp = list(csv.DictReader(open(os.path.join(HERE, "split", "split_frozen.csv"), encoding="utf-8-sig")))
    pairs = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "jar_pairs_verified.csv"), encoding="utf-8-sig"))}
    out = {}
    for r in sp:
        if split != "all" and r["split"] != split: continue
        if r["pair_status"] != "VALID" or r["id"] not in pairs: continue
        p = pairs[r["id"]]
        j = p["pre_path"].replace("\\", "/")
        parts = j.split("/")
        out.setdefault(j, {"key": f"{parts[-3]}-{parts[-2]}", "jar": j, "src": f"gt/sources/{parts[1]}/{parts[2]}/{parts[3]}/src",
                           "classes": int(p["n_classes_pre"] or 0), "java": p.get("pre_java") or "8", "bytes": int(p["pre_bytes"] or 0)})
    return list(out.values())


def commands(tool, r):
    """list of (phase, command) or None when the tool cannot run on this release"""
    k, jar, src = r["key"], r["jar"], r["src"]
    o = f"out/measure/{tool}/{k}"
    if tool == "tldoctor2": return [("analysis", f"{JAVA} -Xmx6g -jar tldoctor2/target/tldoctor2.jar --jar gt/{jar} --out {o}.json")]
    if tool == "typestate": return [("analysis", f"{JAVA} -Xmx6g -jar tldoctor2/target/tldoctor2.jar --mode typestate --jar gt/{jar} --out {o}.json")]
    if tool == "spotbugs-restricted-cost": return [("analysis", f"{JAVA} -Xmx4g -jar {SB} -textui -effort:max -low -visitors UnreadFields -xml:withMessages -output {o}.xml gt/{jar}")]
    if tool == "spotbugs-tl": return [("analysis", f"{JAVA} -Xmx4g -jar {SB} -textui -effort:max -low {SBTL} -xml:withMessages -output {o}.xml gt/{jar}")]
    if tool == "pmd": return [("analysis", f"{PMD} check -d {src} -R {PMD_RULES} -f xml -r {o}.xml --no-cache --no-progress --no-fail-on-violation --no-fail-on-error -t 1 --aux-classpath gt/{jar}")]
    if tool == "pmd-tl": return [("analysis", f"export CLASSPATH=$(pwd)/baselines/pmd-tl/target/pmd-threadlocal-rules-1.0-SNAPSHOT.jar; {PMD} check -d {src} -R rulesets/threadlocal-pmd-ruleset.xml -f xml -r {o}.xml --no-cache --no-progress --no-fail-on-violation --no-fail-on-error -t 1 --aux-classpath gt/{jar}")]
    work = f"out/bl-infer/work/{k}"
    if tool == "infer":
        if not os.path.exists(os.path.join(ROOT, work, "ok.txt")) or os.path.getsize(os.path.join(ROOT, work, "ok.txt")) == 0: return None
        try: lvl = min(21, max(8, int(r["java"])))
        except ValueError: lvl = 8
        cp = f'CP=$(pwd)/gt/{jar}; [ -s {work}/cp.txt ] && CP=$CP:$(cat {work}/cp.txt)'
        opts = f"-proc:none -nowarn -encoding UTF-8 -source {lvl} -target {lvl} -Xmaxerrs 100000 -XDignore.symbol.file"
        return [("capture", f'{cp}; rm -rf {o}.infer-out {o}.classes; mkdir -p {o}.classes; {INFER} capture --no-progress-bar -o {o}.infer-out -- javac {opts} -cp "$CP" -d {o}.classes @{work}/ok.txt'),
                ("analyze", f"{INFER} analyze --no-progress-bar -j 1 -o {o}.infer-out; rc=$?; cp {o}.infer-out/report.json {o}.report.json 2>/dev/null; rm -rf {o}.infer-out {o}.classes; exit $rc")]
    if tool == "infer-tl":
        b = f"out/bl-infer/{k}"
        if not os.path.exists(os.path.join(ROOT, b + ".infer.json")): return None
        return [("postprocess", f"python3 baselines/infer-tl/collect_threadlocal_facts.py --source-root {src} --procedures {b}.procedures.txt --output {o}.facts.json && "
                                f"python3 baselines/infer-tl/infer_tl_postprocess.py --infer-report {b}.infer.json --facts {o}.facts.json --output {o}.infertl.json")]
    raise ValueError(tool)


def stage(rel):
    """copy everything the measured commands read to the Linux file system, keeping project-relative paths"""
    paths = ["tldoctor2/target/tldoctor2.jar", "baselines/spotbugs-tl/target/spotbugs-threadlocal-plugin-1.0-SNAPSHOT.jar",
             "baselines/pmd-tl/target/pmd-threadlocal-rules-1.0-SNAPSHOT.jar", "baselines/infer-tl/collect_threadlocal_facts.py",
             "baselines/infer-tl/infer_tl_postprocess.py", "gt/measure.sh"]
    for r in rel:
        paths += ["gt/" + r["jar"], r["src"]]
        for f in (f"out/bl-infer/work/{r['key']}/ok.txt", f"out/bl-infer/work/{r['key']}/cp.txt", f"out/bl-infer/{r['key']}.infer.json",
                  f"out/bl-infer/{r['key']}.procedures.txt"):
            if os.path.exists(os.path.join(ROOT, f)): paths.append(f)
    lst = os.path.join(ROOT, "out", "measure", "stage_list.txt")
    open(lst, "w", encoding="utf-8", newline="\n").write("\n".join(paths) + "\n")
    res = subprocess.run(bash_argv(f"mkdir -p {STAGE} && cd {W} && rsync -a -r --files-from=out/measure/stage_list.txt . {STAGE}/ && "
                          f"sed -i 's/\\r$//' {STAGE}/gt/measure.sh && du -sh {STAGE} | cut -f1 && df -T {STAGE} | tail -1"), capture_output=True, text=True)
    print("staged:", " | ".join((res.stdout + res.stderr).strip().splitlines()), flush=True)


MEAS = re.compile(r"MEASURE rc=(\S+) wall_s=(\S+) user_s=(\S+) sys_s=(\S+) maxrss_kb=(\S+) peak_tree_kb=(\S+) load_before=(\S+) load_after=(\S+) host_cpu_s=(\S+)")
EXT_MAX = 0.5       # a record is comparable only if other processes used less than this many cores on average during the run


def cmd_run(a):
    tools = a.tools.split(",") if a.tools else ALL
    rel = releases(a.split)
    os.makedirs(os.path.join(ROOT, "out", "measure"), exist_ok=True)
    path = os.path.join(ROOT, "out", "measure", f"measure_{a.split}.csv")
    done = set()
    cols = ["tool", "release", "classes", "jar_bytes", "phase", "rc", "wall_s", "user_s", "sys_s", "maxrss_mb", "peak_tree_mb", "timeout_s", "when", "load_before", "load_after", "host_cpu_s"]
    if os.path.exists(path) and not a.force:
        for r in csv.DictReader(open(path, encoding="utf-8-sig")): done.add((r["tool"], r["release"], r["phase"]))
    else:
        with open(path, "w", newline="", encoding="utf-8-sig") as fh: csv.writer(fh).writerow(cols)
    stage(rel)
    # host load at start: the run is only meaningful on an idle machine
    ld = subprocess.run(bash_argv("uptime; nproc; free -m | sed -n 2p"), capture_output=True, text=True).stdout
    print("host at start:", " | ".join(ld.strip().splitlines()), flush=True)
    for tool in tools:
        os.makedirs(os.path.join(ROOT, "out", "measure", tool), exist_ok=True)
        for r in rel:
            cs = commands(tool, r)
            if cs is None:
                print(f"{tool} {r['key']} SKIPPED (no input)", flush=True); continue
            for phase, c in cs:
                if (tool, r["key"], phase) in done: continue
                script = os.path.join(ROOT, "out", "measure", tool, f"{r['key']}.{phase}.sh")
                open(script, "w", encoding="utf-8", newline="\n").write(f"{ENV}\ncd {STAGE}\n{c}\n")
                sh = f"out/measure/{tool}/{r['key']}.{phase}.sh"
                res = subprocess.run(bash_argv(f"mkdir -p {STAGE}/out/measure/{tool} && cp {W}/{sh} {STAGE}/{sh} && cd {STAGE} && "
                                                                f"bash gt/measure.sh {a.timeout} {sh}"),
                                     capture_output=True, text=True, encoding="utf-8", errors="replace")
                m = MEAS.search(res.stdout or "")
                if not m:
                    row = [tool, r["key"], r["classes"], r["bytes"], phase, "NOMEASURE", "", "", "", "", "", a.timeout, time.strftime("%Y-%m-%d %H:%M:%S"), "", "", ""]
                else:
                    rc, wall, user, sy, rss, peak, l0, l1, host = m.groups()
                    f = lambda x, d=1.0: "" if x == "NA" else round(float(x) / d, 1)
                    row = [tool, r["key"], r["classes"], r["bytes"], phase, rc, f(wall), f(user), f(sy), f(rss, 1024), f(peak, 1024), a.timeout, time.strftime("%Y-%m-%d %H:%M:%S"), l0, l1, host]
                with open(path, "a", newline="", encoding="utf-8-sig") as fh: csv.writer(fh).writerow(row)
                print(" ".join(str(x) for x in row), flush=True)
                if phase == "capture" and (not m or m.group(1) != "0"): break      # no analysis without a capture


def q(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * p))] if v else 0


def cmd_report(a):
    path = os.path.join(ROOT, a.input) if a.input else os.path.join(ROOT, "out", "measure", f"measure_{a.split}.csv")
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
    per = defaultdict(lambda: defaultdict(dict))
    for r in rows:
        if r["tool"] == "spotbugs": r["tool"] = "spotbugs-restricted-cost"
        per[r["tool"]][r["release"]][r["phase"]] = r
    for rel, ph in per.get("infer-tl", {}).items():          # Infer-TL reads the call graph that the capture phase of Infer produces
        cap = per.get("infer", {}).get(rel, {}).get("capture")
        if cap: ph["capture"] = cap
    md = [f"# 运行开销报告（{a.split} 集修复前版本，生成于 {time.strftime('%Y-%m-%d %H:%M')}）", "",
          "> 由 `python gt/29_measure.py report --split " + a.split + "` 生成，原始记录在 `" + (a.input or "out/measure/measure_" + a.split + ".csv") + "`。",
          "> 测量方式：单任务串行，`/usr/bin/time -v`；「单进程峰值」是 getrusage 给出的最大常驻内存，「进程树峰值」是每 0.5 秒采样的全部子进程常驻内存之和的最大值。",
          "> 硬件：Intel Core i9-11900T（16 线程），31 GB 内存，WSL2，JDK 21；输入与输出文件都放在 WSL 的 ext4 文件系统上。", "",
          "| 工具 | 成功 / 尝试 | 墙钟合计 s | 墙钟中位数 s | 90 分位 s | 最大 s | CPU 合计 s | 单进程峰值 MB：中位数 / 最大 | 进程树峰值 MB：中位数 / 最大 |", "|---|---|---|---|---|---|---|---|---|"]
    detail = []
    for tool in ALL:
        if tool not in per: continue
        ok, tried = [], 0
        for rel, ph in per[tool].items():
            tried += 1
            if all(p["rc"] == "0" for p in ph.values()) and (tool not in ("infer", "infer-tl") or len(ph) == 2):
                ok.append({"rel": rel, "wall": sum(float(p["wall_s"]) for p in ph.values()), "cpu": sum(float(p["user_s"]) + float(p["sys_s"]) for p in ph.values()),
                           "rss": max(float(p["maxrss_mb"]) for p in ph.values()), "tree": max(float(p["peak_tree_mb"]) for p in ph.values()),
                           "classes": int(next(iter(ph.values()))["classes"])})
        if not ok:
            md.append(f"| {tool} | 0 / {tried} | | | | | | | |"); continue
        w = [x["wall"] for x in ok]
        md.append(f"| {tool} | {len(ok)} / {tried} | {sum(w):.0f} | {q(w, .5):.1f} | {q(w, .9):.1f} | {max(w):.1f} | {sum(x['cpu'] for x in ok):.0f} | "
                  f"{q([x['rss'] for x in ok], .5):.0f} / {max(x['rss'] for x in ok):.0f} | {q([x['tree'] for x in ok], .5):.0f} / {max(x['tree'] for x in ok):.0f} |")
        big = max(ok, key=lambda x: x["wall"])
        detail.append(f"- {tool}：最慢的版本是 {big['rel']}（{big['classes']} 个类），{big['wall']:.1f} s，进程树峰值 {big['tree']:.0f} MB。")
    common = None
    for tool in per:
        s = {rel for rel, ph in per[tool].items() if all(p["rc"] == "0" for p in ph.values()) and (tool not in ("infer", "infer-tl") or len(ph) == 2)}
        common = s if common is None else common & s
    md += ["", "## 各工具最慢的版本", ""] + detail
    if common:
        md += ["", f"## 所有工具都成功的 {len(common)} 个版本上的对比", "", "| 工具 | 墙钟合计 s | 墙钟中位数 s | 进程树峰值 MB：中位数 / 最大 |", "|---|---|---|---|"]
        for tool in ALL:
            if tool not in per: continue
            xs = [(sum(float(p["wall_s"]) for p in per[tool][rel].values()), max(float(p["peak_tree_mb"]) for p in per[tool][rel].values())) for rel in common]
            md.append(f"| {tool} | {sum(x[0] for x in xs):.0f} | {q([x[0] for x in xs], .5):.1f} | {q([x[1] for x in xs], .5):.0f} / {max(x[1] for x in xs):.0f} |")
    fails = [(r["tool"], r["release"], r["phase"], r["rc"]) for r in rows if r["rc"] != "0"]
    md += ["", "## 主机上的其他负载", ""]
    if rows and rows[0].get("host_cpu_s") not in (None, ""):
        ext = []
        for r in rows:
            if r["rc"] == "NOMEASURE" or not r["wall_s"]: continue
            e = float(r["host_cpu_s"]) - float(r["user_s"]) - float(r["sys_s"])
            ext.append((r, e, e / max(float(r["wall_s"]), 1.0)))
        bad = [x for x in ext if x[2] > EXT_MAX and float(x[0]["wall_s"]) >= 2.0]
        md += [f"每条记录都测了运行期间整台主机的忙碌 CPU 时间，减去被测命令自身的 CPU 时间，得到其他进程占用的 CPU 时间。",
               f"全部 {len(ext)} 条记录合计：被测命令 {sum(float(x[0]['user_s']) + float(x[0]['sys_s']) for x in ext):.0f} CPU 秒，其他进程 {sum(x[1] for x in ext):.0f} CPU 秒。",
               f"其他进程平均占用超过 {EXT_MAX} 个核、且运行时间不少于 2 秒的记录：{len(bad)} 条。"
               + ("受影响的工具：" + "，".join(f"{t} {c} 条" for t, c in sorted(__import__("collections").Counter(x[0]["tool"] for x in bad).items())) + "。这些记录的墙钟时间不可用于比较。" if bad else "")]
    else:
        md += ["这一轮没有记录其他进程占用的 CPU 时间。`load_before` 一列是 1 分钟平均负载，其中包含本测量上一次运行自身产生的负载，不能据此判断是否有其他任务。"]
    md += ["", "## 未成功的运行", "", ("；".join(f"{t} {rel}（{ph}，退出码 {rc}）" for t, rel, ph, rc in fails) + "。") if fails else "无。", ""]
    open(os.path.join(ROOT, a.output), "w", encoding="utf-8").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run", "report"])
    ap.add_argument("--split", default="heldout")
    ap.add_argument("--tools", default="")
    ap.add_argument("--timeout", type=int, default=7200)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--input", default="", help="report: read this csv instead of out/measure/measure_<split>.csv")
    ap.add_argument("--output", default="COST-REPORT.md", help="report: file name of the report, relative to the project root")
    a = ap.parse_args()
    (cmd_run if a.cmd == "run" else cmd_report)(a)
