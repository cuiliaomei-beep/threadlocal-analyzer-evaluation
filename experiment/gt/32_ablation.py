"""32_ablation.py -- component ablation and sensitivity analysis of tldoctor2 (RQ3).

  python gt/32_ablation.py run    --group ablation|sensitivity [--split heldout] [--jobs 4]
  python gt/32_ablation.py report [--split heldout]

Every configuration is one complete run of gt/23_run_design.py (run + eval) with a tag of its own, so the raw output of every
configuration stays in out/<tag>/. No rule is changed: a configuration only switches a component off (--disable) or overrides a
limit (--set). The reference is the run of the unchanged tool, tag abl-full, which must equal the frozen held-out run (heldout-v6).

report writes out/ablation/ablation_<split>.csv and ABLATION-RESULTS.md. Scoring is the scoring of gt/23_run_design.py eval.
"""
import argparse, csv, os, subprocess, sys, time
from collections import defaultdict

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

ROOT = RUNTIME_ROOT

ABLATION = [  # (tag, --disable, --set, description, row label of the paper)
    ("abl-full", "", "", "完整配置（未改动的工具）", "Full configuration"),
    ("abl-value", "value", "", "值事实只取声明类型（泛型实参），不追踪分配点", "without value facts (declared types only)"),
    ("abl-ctx", "ctx", "", "线程上下文事实一律为 Unknown", "without thread-context facts"),
    ("abl-host", "host", "", "非静态声明的宿主寿命一律为 Unknown", "without host-lifetime facts"),
    ("abl-lazy", "lazy", "", "懒初始化状态并入普通安装", "without lazy-initialisation state"),
    ("abl-restore", "restore", "", "不识别还原（含经辅助方法的还原与已保存状态）", "without restore recognition"),
    ("abl-summaries", "summaries", "", "不使用方法摘要（过程内）", "without summaries (intraprocedural)"),
    ("abl-model", "model", "", "框架模型缩减为 ThreadLocal 与 InheritableThreadLocal", "without the framework model"),
]
# cumulative ablation: start with every component switched off and add them in the order of the layers of the approach;
# the last step (adding the framework model) is the full configuration abl-full, which is reused
CUMULATIVE = [
    ("cum-0", "value,ctx,host,lazy,restore,summaries,model", "", "全部组件关闭（只剩开/关 typestate 与声明事实 static）", "all components off"),
    ("cum-1", "value,ctx,host,summaries,model", "", "加入义务 typestate（懒初始化、还原、置空状态）", "+ obligation typestate"),
    ("cum-2", "value,ctx,summaries,model", "", "加入宿主寿命事实", "+ host facts"),
    ("cum-3", "ctx,summaries,model", "", "加入值事实（分配点追踪）", "+ value facts"),
    ("cum-4", "summaries,model", "", "加入线程上下文事实", "+ context facts"),
    ("cum-5", "model", "", "加入方法摘要", "+ summaries"),
]
SENSITIVITY = [("sens-root1", "", "reportDepth=1", "d_root = 1（默认 2）", ""), ("sens-root3", "", "reportDepth=3", "d_root = 3", ""),
               ("sens-root4", "", "reportDepth=4", "d_root = 4", ""),
               ("sens-entry2", "", "entryReportDepth=2", "d_entry = 2（默认 6）", ""), ("sens-entry4", "", "entryReportDepth=4", "d_entry = 4", ""),
               ("sens-entry8", "", "entryReportDepth=8", "d_entry = 8", ""),
               ("sens-chase4", "", "valueChaseDepth=4", "值追踪深度 4（默认 8）", ""), ("sens-chase12", "", "valueChaseDepth=12", "值追踪深度 12", "")]
for name, what in (("entry:CONTAINER", "入口模式：容器线程"), ("entry:POOLED", "入口模式：线程池"), ("entry:LONGLIVED", "入口模式：长寿命线程"),
                   ("entry:SHORTLIVED", "入口模式：短寿命线程"), ("facades", "日志上下文门面"), ("growable", "可增长类型清单"), ("hostHints", "宿主名称提示"),
                   ("tlLike", "与 ThreadLocal 同契约的类型"), ("delegation", "委派方法与建池类"), ("installerNames", "安装方法名模式"),
                   ("endNames", "结束方法名模式"), ("singletonAnnotations", "单例注解"), ("unknownFactory", "可插拔工厂清单"),
                   ("neverThrow", "不抛异常的类清单"), ("testClass", "测试类名模式")):
    SENSITIVITY.append(("sens-" + name.replace(":", "-"), name, "", "去掉" + what, ""))


def summary(tag, split):
    p = os.path.join(ROOT, "out", tag, f"eval_{split}.csv")
    if not os.path.exists(p): return None
    rows = list(csv.DictReader(open(p, encoding="utf-8-sig")))
    gt = [r for r in rows if r["gt"] == "True"]
    ctrl = [r for r in rows if r["gt"] != "True" and r["misuse"].startswith("no-") and r["id"] != "H0129"]
    ok = [r for r in gt if r["pre_status"] == "OK"]; cok = [r for r in ctrl if r["pre_status"] == "OK"]
    units = defaultdict(list)
    for r in gt: units[(r["repo"], r["fix_classes"])].append(r)
    jars = {}
    for r in rows:
        if r["pre_status"] == "OK": jars[r["artifact"] + "-" + r["pre_version"]] = int(r["pre_reports"] or 0)
    v = sorted(jars.values()) or [0]
    bad = sorted({r["artifact"] + "-" + r["pre_version"] for r in rows if r["pre_status"] != "OK"})
    return {"gt": len(gt), "analysed": len(ok), "any": sum(r["tp_any"] == "1" for r in ok), "dom": sum(r["tp_dom"] == "1" for r in ok),
            "uany": sum(any(x["tp_any"] == "1" and x["pre_status"] == "OK" for x in u) for u in units.values()),
            "udom": sum(any(x["tp_dom"] == "1" and x["pre_status"] == "OK" for x in u) for u in units.values()), "units": len(units),
            "ctrl": len(cok), "chit": sum((r["pre_matched"] or "0") != "0" for r in cok), "jars": len(jars), "warn": sum(v), "median": v[len(v) // 2], "max": v[-1],
            "hits": {r["id"] for r in ok if r["tp_any"] == "1"}, "doms": {r["id"] for r in ok if r["tp_dom"] == "1"},
            "chits": {r["id"] for r in cok if (r["pre_matched"] or "0") != "0"}, "failed": bad,
            "by": {d: (sum(r["tp_dom"] == "1" for r in ok if r["dominant"] == d), sum(r["tp_any"] == "1" for r in ok if r["dominant"] == d)) for d in ("O1", "O2", "O3", "O4")}}


def cmd_run(a):
    confs = {"ablation": ABLATION, "sensitivity": SENSITIVITY, "cumulative": CUMULATIVE}[a.group]
    for tag, dis, setl, what, _ in confs:
        if os.path.exists(os.path.join(ROOT, "out", tag, f"eval_{a.split}.csv")) and not a.force:
            print(f"{tag}: done", flush=True); continue
        t0 = time.time()
        cmd = [sys.executable, os.path.join(ROOT, "gt", "23_run_design.py"), "run", "--split", a.split, "--tag", tag, "--jobs", str(a.jobs)]
        if dis: cmd += ["--disable", dis]
        if setl: cmd += ["--set", setl]
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        log = open(os.path.join(ROOT, "out", f"run_{tag}.log"), "w", encoding="utf-8")
        subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        subprocess.run([sys.executable, os.path.join(ROOT, "gt", "23_run_design.py"), "eval", "--split", a.split, "--tag", tag], cwd=ROOT, env=env,
                       stdout=log, stderr=subprocess.STDOUT)
        log.close()
        s = summary(tag, a.split)
        print(f"{tag}: {time.time() - t0:.0f} s; " + ("no eval" if s is None else f"located {s['any']}/{s['gt']}, primary {s['dom']}, controls {s['chit']}/{s['ctrl']}, warnings {s['warn']}, failed jars {len(s['failed'])}"), flush=True)


def cmd_report(a):
    os.makedirs(os.path.join(ROOT, "out", "ablation"), exist_ok=True)
    full = summary("abl-full", a.split)
    rows = []; md = [f"# 消融与敏感性结果（{a.split} 集，生成于 {time.strftime('%Y-%m-%d %H:%M')}）", "",
                     "> 由 `python gt/32_ablation.py report` 生成；每个配置的原始输出在 `out/<tag>/`，评分口径与 `gt/23_run_design.py eval` 相同。",
                     "> 所有配置都只是关闭一个组件或覆盖一个阈值，没有修改任何检测规则。「丢失」与「新增」都相对完整配置而言。", ""]
    for title, confs in (("组件消融", ABLATION), ("累加消融：从全部关闭起逐层加入（最后一步即完整配置）", CUMULATIVE), ("敏感性：阈值与框架模型的各个清单", SENSITIVITY)):
        done = [(c, summary(c[0], a.split)) for c in confs]
        if not any(s for _, s in done): continue
        md += [f"## {title}", "", "| 配置 | 说明 | 定位 | 主因义务 | 去重单元：定位 / 主因 | 分义务主因/定位：O1 · O2 · O3 · O4 | 对照命中 | 报警总数 | 每版本中位数 / 最大 |", "|---|---|---|---|---|---|---|---|---|"]
        for (tag, dis, setl, what, label), s in done:
            if s is None: md.append(f"| {tag} | {what} | 未运行 | | | | | | |"); continue
            by = " · ".join(f"{s['by'][d][0]}/{s['by'][d][1]}" for d in ("O1", "O2", "O3", "O4"))
            md.append(f"| {tag} | {what} | {s['any']}/{s['gt']} | {s['dom']}/{s['gt']} | {s['uany']} / {s['udom']}（共 {s['units']}） | {by} | {s['chit']}/{s['ctrl']} | {s['warn']} | {s['median']} / {s['max']} |")
            rows.append({"tag": tag, "group": "ablation" if confs is ABLATION else ("cumulative" if confs is CUMULATIVE else "sensitivity"), "disable": dis, "set": setl, "label": label, "gt": s["gt"],
                         "located": s["any"], "primary": s["dom"], "units_located": s["uany"], "units_primary": s["udom"], "controls": s["ctrl"],
                         "controls_hit": s["chit"], "warnings": s["warn"], "median": s["median"], "max": s["max"], "failed_jars": len(s["failed"]),
                         "lost_located": ";".join(sorted(full["hits"] - s["hits"])) if full else "", "new_located": ";".join(sorted(s["hits"] - full["hits"])) if full else "",
                         "lost_primary": ";".join(sorted(full["doms"] - s["doms"])) if full else "", "new_primary": ";".join(sorted(s["doms"] - full["doms"])) if full else "",
                         "controls_no_longer_hit": ";".join(sorted(full["chits"] - s["chits"])) if full else "",
                         "controls_newly_hit": ";".join(sorted(s["chits"] - full["chits"])) if full else ""})
        md += ["", "### 相对完整配置的变化", "", "| 配置 | 丢失的定位 | 新增的定位 | 丢失的主因 | 新增的主因 | 不再命中的对照 | 新命中的对照 | 分析失败的版本 |", "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            if r["group"] != ("ablation" if confs is ABLATION else ("cumulative" if confs is CUMULATIVE else "sensitivity")) or r["tag"] == "abl-full": continue
            f = lambda k: r[k].replace(";", ", ") or "无"
            md.append(f"| {r['tag']} | {f('lost_located')} | {f('new_located')} | {f('lost_primary')} | {f('new_primary')} | {f('controls_no_longer_hit')} | {f('controls_newly_hit')} | {r['failed_jars']} |")
        md.append("")
    if rows:
        with open(os.path.join(ROOT, "out", "ablation", f"ablation_{a.split}.csv"), "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    open(os.path.join(ROOT, "ABLATION-RESULTS.md" if a.split == "heldout" else f"ABLATION-RESULTS-{a.split}.md"), "w", encoding="utf-8", newline="\n").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run", "report"])
    ap.add_argument("--group", default="ablation", choices=["ablation", "sensitivity", "cumulative"])
    ap.add_argument("--split", default="heldout")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    (cmd_run if a.cmd == "run" else cmd_report)(a)
