#!/usr/bin/env python3
"""Verify frozen files and recount the corpus, 11 configurations and native protocols.

This is an offline recount of recorded co-location and warning-key responses.
It checks frozen objects, scopes, aggregate counts and native per-record keys.
Analyzer reruns are a separate step described in the reproduction instructions.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rows(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def integer(value):
    return int(value or 0)


def check(actual, expected, context):
    if actual != expected:
        raise ValueError(f"{context}: expected {expected!r}, found {actual!r}")


def truth(value):
    return str(value).lower() in ("true", "1", "yes")


def defect(row):
    return row["gt"] == "True"


def control(row):
    return not defect(row) and row["misuse"].startswith("no-") and row["id"] != "H0129"


def located(row):
    return row["pre_status"] == "OK" and integer(row["pre_matched"]) > 0


def summarize(records):
    defects = [r for r in records if defect(r)]
    controls = [r for r in records if control(r)]
    usable = [r for r in defects if r["pre_status"] == "OK"]
    control_usable = [r for r in controls if r["pre_status"] == "OK"]
    paired = [r for r in usable if r["post_status"] == "OK"]
    hits = [r for r in usable if located(r)]
    volumes = {}
    for row in records:
        if row["pre_status"] == "OK":
            key = (row["repo"].lower(), row["artifact"], row["pre_version"])
            value = integer(row["pre_reports"])
            if key in volumes:
                check(value, volumes[key], f"Shared release warning count {key}")
            volumes[key] = value
    volume = list(volumes.values())
    return {"defects": len(defects), "analyzed": len(usable), "located": len(hits),
            "controls": len(controls), "control_analyzed": len(control_usable),
            "control_located": sum(located(r) for r in control_usable), "both": len(paired),
            "some": sum(located(r) and r["fix_sensitive"] == "1" for r in paired),
            "all": sum(located(r) and r["fix_sensitive_all"] == "1" for r in paired),
            "silent": sum(located(r) and integer(r["post_matched"]) == 0 for r in paired),
            "buggy_versions_ok": len(volume), "warning_total": sum(volume),
            "warning_median": statistics.median(volume) if volume else 0,
            "warning_max": max(volume, default=0),
            "units": len({(r["repo"].lower(), r["fix_classes"]) for r in defects}),
            "units_located": len({(r["repo"].lower(), r["fix_classes"]) for r in hits}),
            "located_ids": sorted(r["id"] for r in hits),
            "pre_statuses": dict(Counter(r["pre_status"] for r in defects))}


def protocol_summary(records):
    defects = [r for r in records if r["cohort"] == "defect"]
    controls = [r for r in records if r["cohort"] == "control"]
    usable = [r for r in defects if r["pre_status"] == "OK"]
    cu = [r for r in controls if r["pre_status"] == "OK"]
    paired = [r for r in usable if r["post_status"] == "OK"]
    return {"defects": len(defects), "pre_usable_defects": len(usable),
            "located_defects": sum(integer(r["tp_any"]) for r in usable),
            "controls": len(controls), "pre_usable_controls": len(cu),
            "located_controls": sum(integer(r["pre_matched"]) > 0 for r in cu),
            "paired_usable_defects": len(paired),
            "paired_located_defects": sum(bool(integer(r["tp_any"])) for r in paired),
            "some_original_keys_disappear": sum(r["fix_sensitive"] == "1" for r in paired),
            "all_original_keys_disappear": sum(r["fix_sensitive_all"] == "1" for r in paired),
            "post_class_silent": sum(r["post_class_silent"] == "1" for r in paired),
            "pre_usable_defects_with_coverage_flags": sum(bool(r["pre_coverage_flags"]) for r in usable),
            "paired_defects_with_coverage_flags": sum(bool(r["pre_coverage_flags"] or r["post_coverage_flags"]) for r in paired)}


def simple(name):
    return (name or "").split(".")[-1].split("$")[0]


def warning_classes(warning):
    names = {simple(warning.get(k)) for k in ("tlDeclClass", "methodClass", "tlRuntimeClass")}
    for site in warning.get("sites") or []:
        signature = site.split(" ", 1)[-1]
        if signature.startswith("<") and ":" in signature:
            names.add(simple(signature[1:signature.index(":")]))
    names.discard("")
    return names


def key(warning):
    tl = warning["tl"]
    return (warning["rule"].split("+")[0], simple(warning.get("tlDeclClass")),
            tl.split(":")[-1].strip(" >") if tl.startswith("<") else tl,
            simple(warning.get("methodClass")))


def verify_native(root):
    snapshot = json.loads((root / "results/protocol_summary.json").read_text(encoding="utf-8"))
    warnings = json.loads((root / "results/protocol_warnings.json").read_text(encoding="utf-8"))
    releases = rows(root / "results/protocol_releases.csv")
    by_release = defaultdict(list)
    warning_ids = set()
    for warning in warnings:
        if warning["warning_id"] in warning_ids:
            raise ValueError("Duplicate normalized warning identity")
        warning_ids.add(warning["warning_id"])
        if not warning["filter_evidence"]:
            raise ValueError("Selected native warning lacks relevance evidence")
        check(list(key(warning["legacy_warning"])), warning["repair_key"], "Native repair identity")
        special = snapshot["dedicated_rule_ids"].get(warning["tool"]) == warning["raw_rule"]
        check("dedicated" in warning["protocols"], special, "Dedicated whitelist/filter intersection")
        by_release[(warning["tool"], warning["release"])].append(warning)
    for release in releases:
        selected = by_release[(release["tool"], release["release"])]
        check(len(selected), integer(release["selected_related_count"]), "Selected related release count")
        check(sum("dedicated" in w["protocols"] for w in selected), integer(release["selected_dedicated_count"]), "Selected dedicated release count")
    for protocol in ("related", "dedicated"):
        records = rows(root / f"results/protocol_{protocol}_rows.csv")
        for row in records:
            matched_keys = {}
            for which in ("pre", "post"):
                parts = row[which].replace("\\", "/").split("/")
                release_key = parts[-3] + "-" + parts[-2]
                selected = [w for w in by_release[(row["tool"], release_key)] if protocol in w["protocols"]]
                matched = [w for w in selected if warning_classes(w["legacy_warning"]) & set(row["fix_classes"].split())]
                matched_keys[which] = {key(w["legacy_warning"]) for w in matched}
                if row[which + "_status"] == "OK":
                    check(len(selected), integer(row[which + "_reports"]), "Native report count")
                    check(len(matched), integer(row[which + "_matched"]), "Native class co-location count")
                    check(sorted(matched_keys[which]), sorted(tuple(k) for k in json.loads(row[which + "_matched_keys"])), "Native matched warning keys")
            if row["pre_status"] == row["post_status"] == "OK":
                old, new = matched_keys["pre"], matched_keys["post"]
                check(integer(row["fix_sensitive"]), int(bool(old) and bool(old - new)), "Some old key disappears")
                check(integer(row["fix_sensitive_all"]), int(bool(old) and not old & new), "All old keys disappear")
                check(integer(row["post_class_silent"]), int(bool(old) and not new), "Post class silence")
        for tool, scopes in snapshot["protocols"][protocol].items():
            own = [r for r in records if r["tool"] == tool]
            for scope, expected in scopes.items():
                subset = own
                if scope in ("common_pre", "common_paired"):
                    eligible = set(snapshot[scope + "_ids"])
                    subset = [r for r in own if r["id"] in eligible]
                elif scope == "run_ok_only":
                    subset = [dict(r) for r in own]
                    for row in subset:
                        for which in ("pre", "post"):
                            if row[which + "_run_status"] != "OK":
                                row[which + "_status"] = row[which + "_run_status"]
                check(protocol_summary(subset), expected, f"{protocol}/{tool}/{scope}")
    return len(warnings)


def verify(root):
    manifest = json.loads((root / "manifests/frozen_files.json").read_text(encoding="utf-8"))
    for name, record in manifest["files"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Frozen manifest contains an unsafe path")
        check(path.stat().st_size, record["size_bytes"], f"Byte count {name}")
        check(sha256(path), record["sha256"], f"SHA256 {name}")
    evaluation = json.loads((root / "results/evaluation.json").read_text(encoding="utf-8"))
    aggregate = {r["tool"]: r for r in rows(root / "results/evaluation.csv")}
    records = rows(root / "results/evaluation_rows.csv")
    releases = rows(root / "results/evaluation_releases.csv")
    annotations = rows(root / "experiment/gt/annotation/annotation_final.csv")
    pairs = {r["id"]: r for r in rows(root / "experiment/gt/jar_pairs_verified.csv")}
    # Legacy study evaluation CSVs omit pre/post path columns. Their release
    # identity comes from the frozen pair map, not an empty union-column cell.
    prepared = [{**r, **{side: pairs[r["id"]][side + "_path"].replace("\\", "/")
                       for side in ("pre", "post")}}
                for r in records if r["tool"] == "LifeTL"]
    defects, controls = [r for r in prepared if defect(r)], [r for r in prepared if control(r)]
    counts = {"annotations": len(annotations), "corpus_defects": sum(r["gt_include"] == "1" for r in annotations),
              "corpus_repositories": len({r["repo"].lower() for r in annotations if r["gt_include"] == "1"}),
              "corpus_controls": sum(r["misuse"].startswith("no-") for r in annotations),
              "excluded_positive_annotations": sum(r["misuse"] == "yes" and r["gt_include"] != "1" for r in annotations),
              "prepared_records": len(prepared), "scored_defects": len(defects), "scored_controls": len(controls),
              "unscored_prepared_records": len(prepared) - len(defects) - len(controls),
              "evaluated_defect_repositories": len({r["repo"].lower() for r in defects}),
              "fix_class_units": len({(r["repo"].lower(), r["fix_classes"]) for r in defects}),
              "unique_releases": len({r[side].replace("\\", "/") for r in prepared for side in ("pre", "post")}),
              "configurations": len(aggregate)}
    check(counts, manifest["expected_counts"], "Corpus and operational scopes")
    included_annotations = [r for r in annotations if r["gt_include"] == "1"]
    for obligation, short, column, label in (("O1", "C", "O1_cleanup", "Cleanup"),
            ("O2", "R", "O2_restore", "Restore"), ("O3", "D", "O3_reachability", "Reach"),
            ("O4", "B", "O4_boundedness", "Bound")):
        check(sum(r["dominant"] == obligation for r in included_annotations), evaluation["core_counts"]["nDom" + short], "Corpus primary obligation")
        check(sum(r[column] == "1" for r in included_annotations), evaluation["core_counts"]["nOb" + short], "Corpus multi-label obligation")
        check(sum(r["dominant"] == obligation for r in defects), evaluation["core_counts"]["nEval" + label + "Primary"], "Scored primary obligation")
    prepared_ids = {r["id"] for r in prepared}
    check(len(prepared_ids), len(prepared), "Prepared IDs are unique")
    frozen_split = {r["id"]: r for r in rows(root / "experiment/gt/split/split_frozen.csv")}
    check({record_id for record_id, r in frozen_split.items()
           if r["pair_status"] == "VALID" and record_id in pairs},
          prepared_ids, "Prepared scope from split/pair join")
    for row in prepared:
        check(frozen_split[row["id"]]["split"], row["split"], "Frozen split")
        for side in ("pre", "post"):
            check(pairs[row["id"]][side + "_path"].replace("\\", "/"), row[side].replace("\\", "/"), "Frozen pair mapping")
    unions = set()
    failure_releases = set()
    for tool, expected in evaluation["tools"].items():
        own = [r for r in records if r["tool"] == tool]
        check({r["id"] for r in own}, prepared_ids, f"Prepared scope {tool}")
        computed = summarize(own)
        for field, value in computed.items():
            check(value, expected[field], f"{tool}/{field}")
            if field in aggregate[tool]:
                check(float(aggregate[tool][field]), float(value), f"Aggregate CSV {tool}/{field}")
        for split in ("design", "heldout"):
            check(summarize([r for r in own if r["split"] == split]), {k: expected[split][k] for k in computed}, f"{tool}/{split}")
        if not (computed["silent"] <= computed["all"] <= computed["some"] <= computed["located"] <= computed["analyzed"]):
            raise ValueError(f"Invalid response relationship for {tool}")
        own_releases = [r for r in releases if r["tool"] == tool]
        check(len(own_releases), counts["unique_releases"], f"Distinct release scope {tool}")
        check(dict(Counter(r["status"] for r in own_releases)), expected["release_statuses"], f"Run statuses {tool}")
        check(sum(truth(r["usable"]) for r in own_releases), expected["release_usable"], f"Usable releases {tool}")
        no_sources = sum(r["status"] in ("NO_SOURCES", "INFER_NO_SOURCES") for r in own_releases)
        failed = [r for r in own_releases if not truth(r["usable"]) and r["status"] not in ("NO_SOURCES", "INFER_NO_SOURCES")]
        check(no_sources, expected["release_no_sources"], f"Unavailable sources {tool}")
        check(len(failed), expected["release_failures"], f"Unusable failures {tool}")
        failure_releases.update(r["release"] for r in failed)
        others = {r["id"] for r in records if r["tool"] != tool and defect(r) and located(r)}
        check(len(set(computed["located_ids"]) - others), expected["unique_located"], f"Unique co-locations {tool}")
        unions.update(computed["located_ids"])
    check(sorted(unions), evaluation["location_union_ids"], "Location union identities")
    check(len(unions), evaluation["core_counts"]["nEvalUnionLocated"], "Location union count")
    check(sorted(failure_releases), evaluation["unique_failure_releases"], "Unique failed release identities")
    check(len(failure_releases), evaluation["core_counts"]["nUniqueFailureVersions"], "Unique failed releases")
    artifacts = json.loads((root / "manifests/artifacts.json").read_text(encoding="utf-8"))
    check(len(artifacts["releases"]), counts["unique_releases"], "Artifact download scope")
    check({b["id"] for r in artifacts["releases"] for b in r["records"]}, prepared_ids, "Artifact-to-record bindings")
    check(sum(not r["source"]["available_in_snapshot"] for r in artifacts["releases"]),
          evaluation["core_counts"]["nMissingSources"], "Source-artifact availability")
    normalized = verify_native(root)
    for tag in ("abl-full", "abl-host", "abl-lazy", "abl-ctx", "cum-0", "cum-1"):
        path = root / f"results/ablation/{tag}/eval_heldout.csv"
        own = rows(path)
        suffix = {"abl-full": "Full", "abl-host": "NoHost", "abl-lazy": "NoLazy", "abl-ctx": "NoContext", "cum-0": "Initial", "cum-1": "States"}[tag]
        check(sum(defect(r) and located(r) for r in own), evaluation["core_counts"]["nComponentHeldout" + suffix + "Located"], f"Heldout component {tag}")
    print(json.dumps({"verified_files": len(manifest["files"]), "counts": counts,
                      "location_union": len(unions), "native_selected_warnings": normalized,
                      "status": "PASS", "scope": "offline recount of frozen proxies; no analyzers invoked"}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO, help="Repository containing manifests, results and experiment/gt")
    args = parser.parse_args()
    try:
        verify(args.root.resolve())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        parser.exit(1, f"Verification failed: {error}\n")


if __name__ == "__main__":
    main()
