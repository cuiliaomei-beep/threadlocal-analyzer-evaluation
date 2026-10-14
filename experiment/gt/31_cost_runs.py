"""31_cost_runs.py -- compares the repeated cost measurements and appends the comparison to COST-REPORT.md.

  python gt/29_measure.py report --split heldout          writes COST-REPORT.md from the last run (out/measure/measure_heldout.csv)
  python gt/31_cost_runs.py                               appends the section that compares run 1 and run 2

Historical restricted-cost protocol; Infer-TL charges capture plus postprocessing,
not full Infer analysis. It is not the full stock SpotBugs configuration of step42.

Run 1: out/measure/measure_heldout.run1.csv   Run 2: out/measure/measure_heldout.csv
A release counts for a tool if all phases of the tool succeeded in both runs. The cost of Infer-TL includes the capture phase of Infer.
"""
import csv, os, statistics
from collections import defaultdict

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

ROOT = RUNTIME_ROOT
ALL = ["tldoctor2", "typestate", "spotbugs-tl", "pmd-tl", "infer-tl", "spotbugs-restricted-cost", "pmd", "infer"]


def load(rel):
    per = defaultdict(lambda: defaultdict(dict))
    for r in csv.DictReader(open(os.path.join(ROOT, rel), encoding="utf-8-sig")):
        if r["tool"] == "spotbugs": r["tool"] = "spotbugs-restricted-cost"
        per[r["tool"]][r["release"]][r["phase"]] = r
    for rel_, ph in per.get("infer-tl", {}).items():
        cap = per.get("infer", {}).get(rel_, {}).get("capture")
        if cap: ph["capture"] = cap
    out = defaultdict(dict)
    for t, d in per.items():
        for rel_, ph in d.items():
            if all(p["rc"] == "0" for p in ph.values()) and (t not in ("infer", "infer-tl") or len(ph) == 2):
                out[t][rel_] = (sum(float(p["wall_s"]) for p in ph.values()), max(float(p["peak_tree_mb"]) for p in ph.values()))
    return out


def med(v):
    return statistics.median(v) if v else 0.0


def main():
    a = load("out/measure/measure_heldout.run1.csv"); b = load("out/measure/measure_heldout.csv")
    md = ["", "## 两轮测量的对比", "",
          "run 1：2026-09-30 03:56 至 06:08；run 2：2026-09-30 06:20 至 08:30（其中 typestate 的 2 条记录因测量时有其他进程活动，于 08:31 重测）。",
          "只统计两轮都成功的版本。「逐版本差异」是同一版本两轮墙钟时间之差的绝对值除以两轮均值，取中位数和最大值；运行时间不足 2 秒的版本不计入。", "",
          "| 工具 | 版本数 | 墙钟合计 s：run 1 / run 2 | 墙钟中位数 s：run 1 / run 2 | 墙钟最大 s：run 1 / run 2 | 进程树峰值中位数 MB：run 1 / run 2 | 进程树峰值最大 MB：run 1 / run 2 | 逐版本差异：中位数 / 最大 |",
          "|---|---|---|---|---|---|---|---|"]
    for t in ALL:
        common = sorted(set(a[t]) & set(b[t]))
        if not common: continue
        wa = [a[t][k][0] for k in common]; wb = [b[t][k][0] for k in common]
        ma = [a[t][k][1] for k in common]; mb = [b[t][k][1] for k in common]
        d = [abs(x - y) / ((x + y) / 2) for x, y in zip(wa, wb) if min(x, y) >= 2.0]
        md.append(f"| {t} | {len(common)} | {sum(wa):.0f} / {sum(wb):.0f} | {med(wa):.1f} / {med(wb):.1f} | {max(wa):.1f} / {max(wb):.1f} | "
                  f"{med(ma):.0f} / {med(mb):.0f} | {max(ma):.0f} / {max(mb):.0f} | {100 * med(d):.1f}% / {100 * max(d):.1f}% |")
    p = os.path.join(ROOT, "COST-REPORT.md")
    s = open(p, encoding="utf-8").read()
    if "## 两轮测量的对比" in s: s = s[:s.index("## 两轮测量的对比")].rstrip("\n") + "\n"
    open(p, "w", encoding="utf-8", newline="\n").write(s + "\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    import argparse
    argparse.ArgumentParser(description=__doc__).parse_args()
    main()
