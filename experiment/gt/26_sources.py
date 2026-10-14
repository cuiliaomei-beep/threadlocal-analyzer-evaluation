"""Step 26: fetch the sources jar (and the pom) of every pre/post release of a split from Maven Central, so that
source-based tools (PMD, Infer) analyse exactly the release whose binary jar the bytecode tools analysed.

  python gt/26_sources.py --split heldout

Output: gt/sources/<group>/<artifact>/<version>/{<artifact>-<version>-sources.jar, <artifact>-<version>.pom, src/...}
        gt/sources_index.csv  (one row per jar: status OK / NO_SOURCES_JAR / EMPTY / ERROR, number of .java files)
"""
import argparse, csv, os, sys, time, urllib.request, zipfile

from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parent))
from _runtime import (EXPERIMENT_ROOT, ROOT as RUNTIME_ROOT, BASH_ROOT, bash_path,
                      host_path, shell_path, tool_command, java_command,
                      shell_environment, bash_argv)

HERE = os.path.join(RUNTIME_ROOT, "gt"); ROOT = RUNTIME_ROOT
CENTRAL = "https://repo1.maven.org/maven2"


def jars_of(split):
    sp = list(csv.DictReader(open(os.path.join(HERE, "split", "split_frozen.csv"), encoding="utf-8-sig")))
    pairs = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "jar_pairs_verified.csv"), encoding="utf-8-sig"))}
    out = {}
    for r in sp:
        if split != "all" and r["split"] != split: continue
        if r["pair_status"] != "VALID" or r["id"] not in pairs: continue
        for k in ("pre_path", "post_path"):
            j = pairs[r["id"]][k].replace("\\", "/")          # jars/<group>/<artifact>/<version>/<file>.jar
            out.setdefault(j, k[:3] if k.startswith("pre") else "post")
    return out


def fetch(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "tl-study/1.0"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            tmp = dest + ".part"
            open(tmp, "wb").write(data)
            os.replace(tmp, dest)
            return len(data), None
        except urllib.error.HTTPError as e:
            if e.code == 404: return 0, "404"
            err = f"http {e.code}"
        except Exception as e:
            err = str(e)[:80]
        time.sleep(3 * (attempt + 1))
    return 0, err


def write_index(rows, split):
    if not rows: return
    path = os.path.join(HERE, f"sources_index_{split}.csv")
    with open(path + ".part", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    os.replace(path + ".part", path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--split", default="heldout", choices=["design", "heldout", "all"]); a = ap.parse_args()
    rows = []
    jars = jars_of(a.split)
    for i, (j, which) in enumerate(sorted(jars.items()), 1):
        parts = j.split("/")
        group, artifact, version = parts[1], parts[2], parts[3]
        base = f"{CENTRAL}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}"
        d = os.path.join(HERE, "sources", group, artifact, version)
        os.makedirs(d, exist_ok=True)
        sj = os.path.join(d, f"{artifact}-{version}-sources.jar"); pom = os.path.join(d, f"{artifact}-{version}.pom")
        status, n_java, err = "OK", 0, ""
        if not os.path.exists(pom): fetch(base + ".pom", pom)
        if not os.path.exists(sj):
            size, e = fetch(base + "-sources.jar", sj)
            if e: status, err = ("NO_SOURCES_JAR" if e == "404" else "ERROR"), e
        if status == "OK":
            src = os.path.join(d, "src")
            try:
                with zipfile.ZipFile(sj) as z:
                    names = [n for n in z.namelist() if n.endswith((".java", ".kt", ".scala", ".groovy"))]
                    n_java = sum(1 for n in names if n.endswith(".java"))
                    os.makedirs(src, exist_ok=True)
                    for n in names:
                        target = os.path.abspath(os.path.join(src, n))
                        if os.path.commonpath([os.path.abspath(src), target]) != os.path.abspath(src):
                            raise ValueError("source archive entry outside release directory")
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        if not os.path.exists(target):
                            with open(target, "wb") as out: out.write(z.read(n))
                if n_java == 0: status = "EMPTY"
            except Exception as e:
                status, err = "ERROR", str(e)[:80]
        rows.append({"jar": j, "which": which, "group": group, "artifact": artifact, "version": version, "status": status,
                     "n_java": n_java, "has_pom": int(os.path.exists(pom)), "error": err})
        write_index(rows, a.split)
        print(f"{i}/{len(jars)} {status:15} java={n_java:5} {artifact}-{version} {err}", flush=True)
    from collections import Counter
    print(Counter(r["status"] for r in rows))
    if any(r["status"] == "ERROR" for r in rows): sys.exit(1)
