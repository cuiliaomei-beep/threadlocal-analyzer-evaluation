"""Reconstruct two descriptive native-tool protocols from frozen raw outputs.

Run: python scripts/recompute_protocols.py
     python scripts/recompute_protocols.py --root experiment --output-dir results/reproduced
     python scripts/recompute_protocols.py --reuse-if-current
Fresh native raw outputs and extracted source files must already be prepared.
The default destination is results/reproduced; frozen results are never changed.
Never invokes an analyser or changes experimental inputs.  `tp_any` and
`tp_dom` are legacy CSV column names, not adjudicated true-positive counts.
Only selected diagnostics are exported; every consumed input is hashed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import re
import time
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = [("SpotBugs", "bl-spotbugs-full"), ("PMD", "bl-pmd"),
         ("Infer", "bl-infer"), ("CodeQL", "bl-codeql"),
         ("Error Prone", "bl-errorprone"), ("Sonar", "bl-sonar")]
DEDICATED = {"SpotBugs": "SIC_THREADLOCAL_DEADLY_EMBRACE",
             "Error Prone": "ThreadLocalUsage", "Sonar": "java:S5164"}
SCOPES = {"SpotBugs": "deadlock-related; outside lifecycle-only view",
          "Error Prone": "static-field structure; outside lifecycle-only view",
          "Sonar": "cleanup; lifecycle-only native rule"}
EP_LINE = re.compile(r"^(?P<file>.+\.java):(?P<line>\d+): (?P<severity>warning|error): \[(?P<check>\w+)\] (?P<msg>.*)$")
TL_DECL = re.compile(r"ThreadLocal\s*(?:<[^;=(){}]*>)?\s+([A-Za-z_$][\w$]*)\s*(?:=|;)")
LEXICAL = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
SOURCE_INFO = {}
SOURCE_EXISTS = {}
USABLE_DEFINITION = "accepted run status AND parseable raw output; does not assert complete compilation or analysis"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def tex(value):
    return "".join({"&": r"\&", "_": r"\_", "%": r"\%", "#": r"\#",
                    "$": r"\$", "{": r"\{", "}": r"\}"}.get(c, c) for c in str(value))


class Inputs:
    def __init__(self, root):
        self.root = root
        self.records = {}
        self.path_names = {}

    def track(self, path):
        original = str(path)
        if original in self.path_names:
            name = self.path_names[original]
            return name, self.records[name]["sha256"]
        path = Path(path).resolve()
        name = str(path.relative_to(self.root)).replace("\\", "/") if path.is_relative_to(self.root) else (
            os.path.relpath(path, self.root).replace("\\", "/") if path.is_relative_to(REPO) else str(path))
        if name not in self.records:
            self.records[name] = {"sha256": sha(path), "bytes": path.stat().st_size}
        self.path_names[original] = name
        return name, self.records[name]["sha256"]

    def json(self, path, **kwargs):
        self.track(path)
        return json.loads(Path(path).read_text(encoding="utf-8-sig"), **kwargs)


def field_names(text):
    """27's declaration heuristic, restricted to an immediate class body.

    Comments/strings are masked for brace context, not for the later text filter.
    This is lexical evidence of a field, not Java name binding or alias analysis.
    """
    if not TL_DECL.search(text):
        return []
    masked = LEXICAL.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), text)
    declarations = {m.start(): m.group(1) for m in TL_DECL.finditer(masked)}
    names, stack, boundary = set(), [], 0
    events = [(m.start(), m.group()) for m in re.finditer(r"[{};]", masked)]
    events += [(pos, "declaration") for pos in declarations]
    for pos, ch in sorted(events):
        if ch == "declaration" and stack and stack[-1] == "class":
            names.add(declarations[pos])
        if ch == "{":
            header = masked[boundary:pos]
            is_class = bool(re.search(r"\b(class|interface|enum|record)\b", header))
            is_class |= bool(re.search(r"\bnew\s+[\w.$<>?,\s]+\([^;{}]*\)\s*$", header))
            stack.append("class" if is_class else "other")
            boundary = pos + 1
        elif ch == "}":
            if stack:
                stack.pop()
            boundary = pos + 1
        elif ch == ";":
            boundary = pos + 1
    return sorted(names)


class SourceContext:
    def __init__(self, root, src, inputs):
        self.root, self.src, self.inputs = root, src, inputs
        self.cache = SOURCE_INFO
        self.resolve_cache = {}
        self.source_references = {}
        self.diagnostics_missing_main_source = 0
        self.diagnostics_without_main_span = 0

    def resolve(self, location):
        original = str(location or "")
        if original in self.resolve_cache:
            return self.resolve_cache[original]
        value = urllib.parse.unquote(original).replace("\\", "/")
        if value.startswith("file:"):
            value = urllib.parse.urlparse(value).path
        if "/gt/sources/" in value:
            value = "gt/sources/" + value.split("/gt/sources/", 1)[1]
        if value.startswith("gt/"):
            candidate = self.root / value
        elif value.startswith("src/"):
            candidate = self.src.parent / value
        elif re.match(r"^[A-Za-z]:/", value):
            candidate = Path(value)
        elif value.startswith("/mnt/"):
            candidate = Path(value[5].upper() + ":/" + value[7:]) if os.name == "nt" else Path(value)
        elif value.startswith("/"):
            candidate = Path(value)
        else:
            candidate = self.src / value
        resolved = candidate.resolve()
        self.resolve_cache[original] = resolved
        return resolved

    def info(self, path):
        key = str(path)
        if key not in self.cache:
            if path.is_file():
                self.inputs.track(path)
                text = path.read_text(encoding="utf-8", errors="replace")
                self.cache[key] = (text.splitlines(), field_names(text)) if "ThreadLocal" in text else ([], [])
            else:
                self.cache[key] = ([], [])
        return self.cache[key]

    def filter(self, message, spans):
        missing = False
        if not spans:
            self.diagnostics_without_main_span += 1
        for diagnostic_span in spans:
            path = self.resolve(diagnostic_span.get("file"))
            key = str(path)
            if key not in SOURCE_EXISTS:
                SOURCE_EXISTS[key] = path.is_file()
            self.source_references[key] = SOURCE_EXISTS[key]
            if SOURCE_EXISTS[key]:
                self.inputs.track(path)
            else:
                missing = True
        self.diagnostics_missing_main_source += int(missing)
        if "ThreadLocal" in (message or ""):
            return {"kind": "message:ThreadLocal"}
        for span in spans:
            path = self.resolve(span.get("file"))
            lines, names = self.info(path)
            begin = int(span.get("start") or 0)
            end = max(begin, int(span.get("end") or begin))
            if not lines or begin <= 0:
                continue
            bounded_end = min(end, begin + 4)
            excerpt = "\n".join(lines[begin - 1:bounded_end])
            evidence = {"file": str(path.relative_to(self.root)).replace("\\", "/") if path.is_relative_to(self.root) else str(path),
                        "start": begin, "end": bounded_end, "excerpt": excerpt}
            if "ThreadLocal" in excerpt:
                return {"kind": "source:ThreadLocal", **evidence}
            for name in names:
                if re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", excerpt):
                    return {"kind": "source:declared-field", "field": name, **evidence}
        return None

    def class_of(self, span):
        path = self.resolve(span.get("file"))
        try:
            relative = path.relative_to(self.src)
            return str(relative.with_suffix("")).replace("\\", ".").replace("/", ".")
        except ValueError:
            return path.stem


def span(file, start, end=None, **extra):
    return {"file": file or "", "start": int(start or 0), "end": int(end or start or 0), **extra}


def sb_diagnostics(path, inputs):
    inputs.track(path)
    doc = ET.parse(path).getroot()
    out = []
    for ordinal, bug in enumerate(doc.findall("BugInstance")):
        classes = bug.findall("Class")
        primary = next((c for c in classes if c.get("primary") == "true"), classes[0] if classes else None)
        direct = bug.findall("SourceLine")
        main = [s for s in direct if s.get("primary") == "true"] or direct[:1]
        resolution = "BugInstance/SourceLine"
        if not main:
            for annotation in bug.findall("Method") + bug.findall("Field"):
                if annotation.get("primary") == "true":
                    main.extend(annotation.findall("SourceLine"))
            resolution = "primary Method/Field SourceLine"
        if not main and primary is not None:
            main = primary.findall("SourceLine")
            resolution = "primary Class SourceLine"
        spans = [span(s.get("sourcepath") or s.get("sourcefile"), s.get("start"), s.get("end"),
                      classname=s.get("classname", ""), annotation=resolution) for s in main]
        method = next((m for m in bug.findall("Method") if m.get("primary") == "true"), None)
        out.append({"raw_rule": bug.get("type", "?"), "rule": "SPOTBUGS_" + bug.get("type", "?"),
                    "message": (bug.findtext("LongMessage", "") or bug.findtext("ShortMessage", "")),
                    "primary_class": primary.get("classname", "") if primary is not None else (spans[0].get("classname", "") if spans else ""),
                    "method": method.get("name") if method is not None else None,
                    "spans": spans, "native_id": bug.get("instanceHash"), "raw_ordinal": ordinal,
                    "raw_attributes": dict(bug.attrib), "location_resolution": resolution})
    errors = doc.find("Errors")
    info = {"analysis_errors": int(errors.get("errors", "0")) if errors is not None else 0,
            "missing_classes": int(errors.get("missingClasses", "0")) if errors is not None else 0}
    return out, info


def pmd_diagnostics(paths, inputs):
    raw, fallback = paths
    try:
        data = inputs.json(raw, strict=False)
        files = data.get("files", [])
        info = {"pmd_processing_errors": len(data.get("processingErrors", [])),
                "pmd_configuration_errors": len(data.get("configurationErrors", [])), "raw_format": "json"}
        source = raw
    except (json.JSONDecodeError, OSError):
        inputs.track(fallback)
        doc = ET.parse(fallback).getroot()
        ns = doc.tag[:doc.tag.index("}") + 1] if "}" in doc.tag else ""
        files = [{"filename": f.get("name"), "violations": [dict(v.attrib, description=(v.text or "").strip())
                  for v in f.findall(ns + "violation")]} for f in doc.findall(ns + "file")]
        info = {"pmd_processing_errors": len(doc.findall(ns + "error")),
                "pmd_configuration_errors": len(doc.findall(ns + "configerror")), "raw_format": "xml-fallback"}
        source = fallback
    out = []
    for f in files:
        for value in f.get("violations", []):
            out.append({"raw_rule": value["rule"], "rule": "PMD_" + value["rule"],
                        "message": value.get("description", ""), "method": None,
                        "spans": [span(f.get("filename"), value.get("beginline"), value.get("endline"))],
                        "raw_ordinal": len(out), "raw_attributes": {k: value[k] for k in ("priority", "ruleset") if k in value}})
    return out, info, source


def parse_raw(tool, tag, key, context, inputs):
    directory = context.root / "out" / tag
    paths, info = [], {}
    if tool == "SpotBugs":
        path = directory / (key + ".xml")
        values, info = sb_diagnostics(path, inputs)
        paths = [path]
    elif tool == "PMD":
        candidates = [directory / (key + ".pmd.json"), directory / (key + ".pmd.xml")]
        values, info, used = pmd_diagnostics(candidates, inputs)
        paths = [p for p in candidates if p.is_file()]
    elif tool == "Infer":
        path = directory / (key + ".infer.json")
        data = inputs.json(path)
        values = [{"raw_rule": v.get("bug_type", "?"), "rule": "INFER_" + v.get("bug_type", "?"),
                   "message": v.get("qualifier", ""), "method": v.get("procedure"),
                   "spans": [span(v.get("file"), v.get("line"))],
                   "native_id": v.get("hash") or v.get("key"), "raw_ordinal": i}
                  for i, v in enumerate(data)]
        paths = [path]
    elif tool == "CodeQL":
        path = directory / (key + ".sarif")
        data = inputs.json(path)
        values = []
        for run_index, run in enumerate(data.get("runs", [])):
            for value in run.get("results", []):
                spans = []
                for location in value.get("locations", []):
                    physical = location.get("physicalLocation", {})
                    artifact, region = physical.get("artifactLocation", {}), physical.get("region", {})
                    uri = artifact.get("uri", "")
                    if not uri and "index" in artifact:
                        uri = run.get("artifacts", [])[artifact["index"]].get("location", {}).get("uri", "")
                    spans.append(span(uri, region.get("startLine"), region.get("endLine")))
                rule = value.get("ruleId", "?")
                values.append({"raw_rule": rule, "rule": "CODEQL_" + rule.replace("/", "_"),
                               "message": value.get("message", {}).get("text") or value.get("message", {}).get("markdown", ""),
                               "method": None, "spans": spans, "raw_ordinal": len(values),
                               "native_id": value.get("partialFingerprints", {}), "run_index": run_index})
        paths = [path]
    elif tool == "Error Prone":
        path = directory / (key + ".ep.log")
        inputs.track(path)
        values = []
        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            match = EP_LINE.match(line)
            if match:
                value = match.groupdict()
                values.append({"raw_rule": value["check"], "rule": "EP_" + value["check"],
                               "message": value["msg"], "method": None,
                               "spans": [span(value["file"], value["line"])], "raw_ordinal": len(values),
                               "log_line": lineno, "severity": value["severity"]})
        paths = [path]
    else:
        paths = sorted((directory / "work" / key).glob("issues_*.json"))
        if not paths:
            raise FileNotFoundError("No Sonar issues pages")
        values, seen, duplicates, totals = [], set(), 0, set()
        for path in paths:
            data = inputs.json(path)
            if "issues" not in data or data.get("errors"):
                raise ValueError("Invalid Sonar issues page: " + path.name)
            if "total" in data.get("paging", {}):
                totals.add(data["paging"]["total"])
            for value in data["issues"]:
                identity = value.get("key")
                if identity and identity in seen:
                    duplicates += 1
                    continue
                seen.add(identity)
                component = value.get("component", "")
                file = component.split(":", 1)[1] if ":" in component else ""
                region = value.get("textRange", {})
                spans = [span(file, region.get("startLine") or value.get("line"), region.get("endLine"))] if file.endswith(".java") else []
                rule = value.get("rule", "?")
                values.append({"raw_rule": rule, "rule": "SONAR_" + rule.replace("java:", ""),
                               "message": value.get("message", ""), "method": None, "spans": spans,
                               "native_id": identity, "raw_ordinal": len(values), "page": path.name})
        info = {"sonar_duplicate_issue_keys": duplicates, "sonar_page_totals": sorted(totals)}
    for value in values:
        value.setdefault("primary_class", context.class_of(value["spans"][0]) if value["spans"] else "")
    for path in paths:
        inputs.track(path)
    return values, info, paths


def legacy_warning(value, ev):
    cls = value["primary_class"]
    # Only the dedicated cleanup rule has a lifecycle obligation here.
    obligations = ["O1"] if value["raw_rule"] == "java:S5164" else []
    return {"rule": value["rule"], "tier": "REPORT", "obligations": obligations,
            "dominant": obligations[0] if obligations else "-", "tl": cls,
            "tlDeclClass": cls, "methodClass": cls, "tlRuntimeClass": None,
            "method": value.get("method"), "sites": None,
            "line": value["spans"][0]["start"] if value["spans"] else 0}


def flags_for(metadata, raw_info):
    flags = []
    if metadata.get("status") == "PARTIAL":
        flags.append("run_partial")
    total, compiled = metadata.get("files_total"), metadata.get("files_compiled")
    if total is not None and compiled is not None and int(compiled) < int(total):
        flags.append("partial_compilation")
    if metadata.get("javac_rc") not in (None, 0):
        flags.append("javac_nonzero")
    for name in ("pmd_processing_errors", "pmd_configuration_errors", "analysis_errors", "missing_classes"):
        if raw_info.get(name):
            flags.append(name)
    if metadata.get("deps") in ("FAILED", "NO_POM"):
        flags.append("dependency_" + metadata["deps"].lower())
    dependencies = metadata.get("dependencies", {})
    if str(dependencies.get("DEP_RC", "0")) != "0" or int(dependencies.get("CP_MISSING", "0")):
        flags.append("dependency_incomplete")
    if raw_info.get("sonar_duplicate_issue_keys"):
        flags.append("sonar_duplicate_issue_keys")
    return flags


def summarize(rows):
    defects = [r for r in rows if r["cohort"] == "defect"]
    controls = [r for r in rows if r["cohort"] == "control"]
    usable = [r for r in defects if r["pre_status"] == "OK"]
    usable_controls = [r for r in controls if r["pre_status"] == "OK"]
    paired = [r for r in usable if r["post_status"] == "OK"]
    located_paired = [r for r in paired if r["tp_any"]]
    return {"defects": len(defects), "pre_usable_defects": len(usable),
            "located_defects": sum(r["tp_any"] for r in usable),
            "controls": len(controls), "pre_usable_controls": len(usable_controls),
            "located_controls": sum(int(r["pre_matched"] > 0) for r in usable_controls),
            "paired_usable_defects": len(paired), "paired_located_defects": len(located_paired),
            "some_original_keys_disappear": sum(r["fix_sensitive"] == 1 for r in paired),
            "all_original_keys_disappear": sum(r["fix_sensitive_all"] == 1 for r in paired),
            "post_class_silent": sum(r["post_class_silent"] == 1 for r in paired),
            "pre_usable_defects_with_coverage_flags": sum(bool(r["pre_coverage_flags"]) for r in usable),
            "paired_defects_with_coverage_flags": sum(bool(r["pre_coverage_flags"] or r["post_coverage_flags"]) for r in paired)}


def evaluate(protocol, tool, tag, rows, releases, old, ev):
    result = []
    for original in rows:
        row = dict(original)
        row.update(tool=tool, source_tag=tag, protocol=protocol,
                   cohort="defect" if row["gt"] else ("control" if row["misuse"].startswith("no-") and row["id"] != "H0129" else "excluded"))
        row["gt"] = str(row["gt"])
        row["fix_classes"] = " ".join(row["fix_classes"])
        fix = set(row["fix_classes"].split())
        keys, matches = {}, {}
        for which in ("pre", "post"):
            release = releases[(tool, ev.jar_key(row[which]))]
            available = release["usable"]
            warnings = release[protocol] if available else []
            matched = [w for w in warnings if ev.match_classes(w["legacy_warning"], fix)]
            keys[which] = {tuple(w["repair_key"]) for w in matched}
            matches[which] = matched
            unavailable_status = "RAW_UNAVAILABLE" if release["run_status"] in ("OK", "PARTIAL") else release["run_status"]
            row.update({which + "_status": "OK" if available else unavailable_status,
                        which + "_run_status": release["run_status"],
                        which + "_reports": len(warnings) if available else "",
                        which + "_matched": len(matched) if available else "",
                        which + "_coverage_flags": ";".join(release["coverage_flags"]),
                        which + "_time_ms": release["time_ms"],
                        which + "_matched_keys": json.dumps(sorted(keys[which]), ensure_ascii=False),
                        which + "_matched_warning_ids": json.dumps([w["warning_id"] for w in matched]),
                        which + "_matched_rules": ";".join(sorted({w["rule"] for w in matched}))})
        both = row["pre_status"] == row["post_status"] == "OK"
        row.update(tp_any=int(bool(matches["pre"])) if row["pre_status"] == "OK" else "",
                   tp_dom=int(any(row["dominant"] in w["legacy_warning"]["obligations"] for w in matches["pre"])) if row["pre_status"] == "OK" else "",
                   fix_sensitive=int(bool(keys["pre"]) and bool(keys["pre"] - keys["post"])) if both else "",
                   fix_sensitive_all=int(bool(keys["pre"]) and not (keys["pre"] & keys["post"])) if both else "",
                   post_class_silent=int(bool(keys["pre"]) and not matches["post"]) if both else "",
                   ctrl_changed=int(keys["pre"] != keys["post"]) if both else "",
                   pre_tls=0, post_tls=0, pre_unknown_ctx=0,
                   fix_tl_in_pre=old.get((row["split"], row["id"]), {}).get("fix_tl_in_pre", ""),
                   fix_present=old.get((row["split"], row["id"]), {}).get("fix_present", ""))
        assert not (row["post_class_silent"] == 1 and row["fix_sensitive_all"] != 1)
        assert not (row["fix_sensitive_all"] == 1 and row["fix_sensitive"] != 1)
        result.append(row)
    return result


def table(path, headers, rows, columns=None):
    columns = columns or ("l" + "r" * (len(headers) - 1))
    lines = ["% Generated by scripts/recompute_protocols.py; descriptive proxies only.",
             r"\begin{tabular}{" + columns + "}", r"\toprule",
             " & ".join(r"\textbf{" + tex(h) + "}" for h in headers) + r" \\", r"\midrule"]
    lines += [" & ".join(tex(v) for v in values) + r" \\" for values in rows]
    lines += [r"\bottomrule", r"\end{tabular}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def location_rows(summary):
    rows = []
    for tool, _ in TOOLS:
        related = summary["protocols"]["related"][tool]["tool_available"]
        dedicated = summary["protocols"]["dedicated"][tool]["tool_available"]
        rows.append([tool,
                     "--" if tool not in DEDICATED else f"{dedicated['located_defects']}/{dedicated['pre_usable_defects']}",
                     f"{related['located_defects']}/{related['pre_usable_defects']}",
                     "--" if tool not in DEDICATED else f"{dedicated['located_controls']}/{dedicated['pre_usable_controls']}",
                     f"{related['located_controls']}/{related['pre_usable_controls']}"])
    return rows


def host_path(value, base):
    """Resolve frozen relative inputs and Windows/WSL absolute paths."""
    value = str(value).replace("\\", "/")
    if os.name != "nt" and re.match(r"^[A-Za-z]:/", value):
        value = "/mnt/" + value[0].lower() + "/" + value[3:]
    elif os.name == "nt" and re.match(r"^/mnt/[A-Za-z]/", value):
        value = value[5].upper() + ":/" + value[7:]
    path = Path(value)
    return path if path.is_absolute() else base / path


def reuse_snapshot(root, output):
    path = output / "protocol_manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if host_path(manifest["source_root"], root).resolve() != root:
            return False
        if not manifest["inputs"] or not manifest["outputs"]:
            return False
        # Check inexpensive generated outputs before traversing the raw corpus.
        for name, record in manifest["outputs"].items():
            if sha(host_path(name, output)) != record["sha256"]:
                return False
        records = list(manifest["inputs"].items())
        # A changed runner invalidates this protocol before hashing large inputs.
        records.sort(key=lambda item: (not item[0].replace("\\", "/").endswith("/scripts/recompute_protocols.py"), item[0]))
        runner_seen = False
        for name, record in records:
            source = host_path(name, root)
            if name.replace("\\", "/").endswith("/scripts/recompute_protocols.py"):
                runner_seen = source.resolve() == Path(__file__).resolve()
            if sha(source) != record["sha256"]:
                return False
        if not runner_seen:
            return False
        print(f"Reused frozen protocol snapshot: {len(records)} input hashes and {len(manifest['outputs'])} output hashes match.", flush=True)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO / "experiment")
    parser.add_argument("--output-dir", type=Path, default=REPO / "results/reproduced",
                        help="Fresh protocol destination; cannot be the frozen results directory")
    parser.add_argument("--reuse-if-current", action="store_true",
                        help="Reuse outputs only when every frozen input/output SHA256 matches")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output_dir.resolve()
    if output == (REPO / "results").resolve() or output.is_relative_to(root):
        parser.error("Choose a separate output directory; experimental inputs and frozen results are read-only")
    sys.path.insert(0, str(root / "gt"))
    if args.reuse_if_current and reuse_snapshot(root, output):
        return
    inputs = Inputs(root)
    state_path = root / "out/bl-spotbugs-full/state.json"
    snapshot = inputs.json(state_path).get("updated") if state_path.exists() else "fresh-input-hash-snapshot"
    ev = module("protocol_eval23", root / "gt/23_run_design.py")
    st = module("protocol_source27", root / "gt/27_source_tools.py")
    for name in ("gt/23_run_design.py", "gt/27_source_tools.py", "gt/split/split_frozen.csv",
                 "gt/jar_pairs_verified.csv", "gt/annotation/annotation_final.csv", "gt/matrix/matrix_final.csv"):
        inputs.track(root / name)
    inputs.track(Path(__file__))
    rows = ev.load_rows("all")
    assert sum(r["gt"] for r in rows) == 82
    assert sum(not r["gt"] and r["misuse"].startswith("no-") and r["id"] != "H0129" for r in rows) == 64
    jars = list(st.jobs_of("all", "both"))
    assert len(jars) == len(set(ev.jar_key(j) for j in jars)) == 264
    # These auxiliary presence fields never affect warning selection or scoring.
    # Compute them from the same downloaded pre JAR, without the old restricted
    # stock-SpotBugs cache that the public replay does not run.
    old = {}
    for row in rows:
        jar_path = root / "gt" / row["pre"]
        if jar_path.exists():
            inputs.track(jar_path)
        old[(row["split"], row["id"])] = {
            "fix_tl_in_pre": ev.fix_tl_in_pre(str(jar_path), row["fix_classes"]),
            "fix_present": ev.fix_present(str(jar_path), row["fix_classes"])}
    releases, selected, release_csv = {}, [], []
    for tool, tag in TOOLS:
        counts = Counter()
        for jar in jars:
            key = ev.jar_key(jar)
            path = root / "out" / tag / (key + ".json")
            try:
                metadata = inputs.json(path)
            except (OSError, ValueError):
                metadata = {"status": "MISSING"}
            run_status = metadata.get("status", "MISSING")
            eligible = run_status in (("OK", "PARTIAL") if tool == "SpotBugs" else ("OK",))
            context = SourceContext(root, root / st.src_dir(jar) / "src", inputs)
            raw_paths, raw_info, values, parse_error = [], {}, [], None
            if eligible:
                try:
                    values, raw_info, raw_paths = parse_raw(tool, tag, key, context, inputs)
                except (OSError, ValueError, ET.ParseError, IndexError, KeyError) as error:
                    parse_error = type(error).__name__ + ": " + str(error)
            usable = eligible and parse_error is None
            coverage_flags = flags_for(metadata, raw_info)
            if parse_error:
                coverage_flags.append("raw_parse_failure")
            related, dedicated, rejected = [], [], []
            for value in values:
                evidence = context.filter(value.get("message"), value["spans"])
                is_dedicated = value["raw_rule"] == DEDICATED.get(tool)
                if not evidence:
                    if is_dedicated:
                        rejected.append({"raw_ordinal": value["raw_ordinal"], "native_id": value.get("native_id"),
                                         "raw_rule": value["raw_rule"], "primary_class": value["primary_class"],
                                         "message": value["message"], "spans": value["spans"]})
                    continue
                warning = {**value, "tool": tool, "source_tag": tag, "release": key,
                           "warning_id": f"{tag}/{key}/{value['raw_ordinal']}", "filter_evidence": evidence,
                           "protocols": ["related"] + (["dedicated"] if is_dedicated else []),
                           "simple_class": ev.simple(value["primary_class"]),
                           "scope": SCOPES.get(tool) if is_dedicated else "generic ThreadLocal-related diagnostic"}
                warning["legacy_warning"] = legacy_warning(warning, ev)
                warning["repair_key"] = list(ev.wkey(warning["legacy_warning"]))
                related.append(warning)
                selected.append(warning)
                if is_dedicated:
                    dedicated.append(warning)
            raw_info.update(main_source_file_count=len(context.source_references),
                            missing_main_source_file_count=sum(not v for v in context.source_references.values()),
                            diagnostics_missing_main_source=context.diagnostics_missing_main_source,
                            diagnostics_without_main_span=context.diagnostics_without_main_span)
            if context.diagnostics_missing_main_source:
                coverage_flags.append("relevance_source_missing")
            release = {"tool": tool, "source_tag": tag, "release": key, "jar_path": jar,
                       "run_status": run_status, "usable": usable, "coverage_flags": coverage_flags,
                       "metadata": {k: metadata[k] for k in ("files_total", "files_compiled", "javac_rc", "n_java", "processing_errors", "missing_class_count", "analysis_error_count", "dependencies", "deps") if k in metadata},
                       "raw_info": raw_info, "raw_diagnostics": len(values), "raw_parse_error": parse_error,
                       "dedicated_rejected_by_filter": rejected, "related": related, "dedicated": dedicated,
                       "time_ms": metadata.get("time_ms", ""),
                       "raw_sources": dict(inputs.track(p) for p in raw_paths)}
            releases[(tool, key)] = release
            release_csv.append({"tool": tool, "source_tag": tag, "release": key, "jar_path": jar,
                                "run_status": run_status, "status": run_status, "usable": str(usable),
                                "selected_related_count": len(related), "selected_dedicated_count": len(dedicated),
                                "dedicated_rejected_by_filter": len(rejected), "raw_diagnostics": len(values),
                                "coverage_flags": ";".join(coverage_flags), "raw_parse_error": parse_error or "",
                                "sourcehash": json.dumps(release["raw_sources"], sort_keys=True),
                                "files_total": metadata.get("files_total", ""), "files_compiled": metadata.get("files_compiled", ""),
                                "javac_rc": metadata.get("javac_rc", ""), **raw_info})
            counts[run_status] += 1
        print(f"{tool}: releases={len(jars)} statuses={dict(counts)} selected={sum(len(releases[(tool, ev.jar_key(j))]['related']) for j in jars)}", flush=True)
    protocol_rows = {protocol: [record for tool, tag in TOOLS for record in evaluate(protocol, tool, tag, rows, releases, old, ev)]
                     for protocol in ("related", "dedicated")}
    by_id = {tool: {r["id"]: r for r in protocol_rows["related"] if r["tool"] == tool} for tool, _ in TOOLS}
    common_pre = {r["id"] for r in rows if all(by_id[t][r["id"]]["pre_status"] == "OK" for t, _ in TOOLS)}
    common_pair = {i for i in common_pre if all(by_id[t][i]["post_status"] == "OK" for t, _ in TOOLS)}
    summary = {"snapshot": snapshot, "semantics": {"located": "diagnostic co-location with a simple fix-class name; not verified root-cause detection",
                              "repair": "mechanical warning-key response; not semantic correctness",
                              "usable": USABLE_DEFINITION,
                              "tp_any_tp_dom": "legacy column names retained only for shape compatibility",
                              "warning_volume": "selected diagnostic counts, not precision; differing analysis coverage remains"},
               "filter": {"message": "case-sensitive substring ThreadLocal in full raw diagnostic message",
                          "source": "any main diagnostic source span, start..min(end,start+4); point locations inspect one line",
                          "field": "same-file ThreadLocal declaration regex restricted lexically to direct class body; not name binding",
                          "secondary_paths": "Infer traces, CodeQL related locations/code flows and Sonar flows excluded",
                          "spotbugs_location": "direct BugInstance SourceLine primary or first; then primary Method/Field SourceLine; then primary Class",
                          "dedicated": "rule whitelist intersection with exactly the same relevance filter"},
               "cohorts": {"all_compatible_rows": len(rows), "defects": 82, "controls": 64,
                           "excluded_records": [r["id"] for r in rows if not r["gt"] and not (r["misuse"].startswith("no-") and r["id"] != "H0129")],
                           "unique_releases": len(jars)},
               "dedicated_rule_ids": DEDICATED, "dedicated_scopes": SCOPES,
               "lifecycle_only": {"native_in_scope": {"Sonar": "java:S5164"},
                                  "out_of_scope": {t: SCOPES.get(t, "no identified dedicated rule in configured stock inventory") for t, _ in TOOLS if t != "Sonar"}},
               "common_pre_ids": sorted(common_pre), "common_paired_ids": sorted(common_pair),
               "protocols": {}, "coverage": {}}
    for subset, ids in (("common_pre", common_pre), ("common_paired", common_pair)):
        summary["cohorts"][subset + "_defects"] = sum(r["id"] in ids and r["gt"] for r in rows)
        summary["cohorts"][subset + "_controls"] = sum(r["id"] in ids and not r["gt"] and r["misuse"].startswith("no-") and r["id"] != "H0129" for r in rows)
    aggregate_csv = []
    for protocol, records in protocol_rows.items():
        summary["protocols"][protocol] = {}
        for tool, tag in TOOLS:
            own = [r for r in records if r["tool"] == tool]
            scopes = {"tool_available": own,
                      "common_pre": [r for r in own if r["id"] in common_pre],
                      "common_paired": [r for r in own if r["id"] in common_pair]}
            if tool == "SpotBugs":
                run_ok = []
                for r in own:
                    record = dict(r)
                    for which in ("pre", "post"):
                        if record[which + "_run_status"] != "OK":
                            record[which + "_status"] = record[which + "_run_status"]
                    run_ok.append(record)
                scopes["run_ok_only"] = run_ok
            summary["protocols"][protocol][tool] = {}
            for scope, scoped in scopes.items():
                values = summarize(scoped)
                summary["protocols"][protocol][tool][scope] = values
                aggregate_csv.append({"protocol": protocol, "tool": tool, "source_tag": tag, "subset": scope,
                                      "dedicated_rule_present": str(tool in DEDICATED), **values})
    for tool, _ in TOOLS:
        own = [v for (t, _), v in releases.items() if t == tool]
        summary["coverage"][tool] = {"release_statuses": dict(Counter(v["run_status"] for v in own)),
                                     "usable_releases": sum(v["usable"] for v in own),
                                     "usable_releases_with_flags": sum(v["usable"] and bool(v["coverage_flags"]) for v in own),
                                     "coverage_flags": dict(Counter(f for v in own if v["usable"] for f in v["coverage_flags"])),
                                     "dedicated_raw_candidates": sum(len(v["dedicated"]) + len(v["dedicated_rejected_by_filter"]) for v in own),
                                     "dedicated_rejected_by_filter": sum(len(v["dedicated_rejected_by_filter"]) for v in own),
                                     "main_source_file_references": sum(v["raw_info"].get("main_source_file_count", 0) for v in own),
                                     "missing_main_source_file_references": sum(v["raw_info"].get("missing_main_source_file_count", 0) for v in own),
                                     "diagnostics_missing_main_source": sum(v["raw_info"].get("diagnostics_missing_main_source", 0) for v in own),
                                     "diagnostics_without_main_span": sum(v["raw_info"].get("diagnostics_without_main_span", 0) for v in own),
                                     "selected_related_unique_release_warnings": sum(len(v["related"]) for v in own)}
    data, tables = output, output / "tables"
    data.mkdir(parents=True, exist_ok=True); tables.mkdir(exist_ok=True)
    outputs = []
    for protocol, records in protocol_rows.items():
        path = data / f"protocol_{protocol}_rows.csv"
        write_csv(path, records); outputs.append(path)
    for filename, records in (("protocol_releases.csv", release_csv), ("protocol_aggregate.csv", aggregate_csv)):
        path = data / filename
        write_csv(path, records); outputs.append(path)
    for filename, value in (("protocol_summary.json", summary), ("protocol_warnings.json", selected),
                            ("protocol_dedicated_rejected.json", [{"tool": v["tool"], "release": v["release"], "warnings": v["dedicated_rejected_by_filter"]} for v in releases.values() if v["dedicated_rejected_by_filter"]])):
        path = data / filename
        write_json(path, value); outputs.append(path)
    loc, repair, dedicated_table, common, coverage = [], [], [], [], []
    for tool, _ in TOOLS:
        related = summary["protocols"]["related"][tool]["tool_available"]
        special = summary["protocols"]["dedicated"][tool]["tool_available"]
        repair.append([tool, related["paired_usable_defects"], related["paired_located_defects"], related["some_original_keys_disappear"], related["all_original_keys_disappear"], related["post_class_silent"]])
        dedicated_table.append([tool, "none" if tool not in DEDICATED else DEDICATED[tool].replace("SIC_THREADLOCAL_DEADLY_EMBRACE", "SIC (deadlock)").replace("ThreadLocalUsage", "TLUsage (structure)").replace("java:S5164", "S5164 (cleanup)"),
                                "--" if tool not in DEDICATED else f"{special['located_defects']}/{special['pre_usable_defects']}",
                                "--" if tool not in DEDICATED else f"{special['located_controls']}/{special['pre_usable_controls']}",
                                "yes" if tool == "Sonar" else "no"])
        pre = summary["protocols"]["related"][tool]["common_pre"]
        pair = summary["protocols"]["related"][tool]["common_paired"]
        common.append([tool, f"{pre['located_defects']}/{pre['defects']}", f"{pre['located_controls']}/{pre['controls']}",
                       pair["some_original_keys_disappear"], pair["all_original_keys_disappear"], pair["post_class_silent"]])
        cov = summary["coverage"][tool]
        coverage.append([tool, cov["release_statuses"].get("OK", 0), cov["release_statuses"].get("PARTIAL", 0),
                         264 - cov["usable_releases"], cov["usable_releases_with_flags"]])
    specs = [("protocol_location.tex", ["Tool", "D. defect", "R. defect", "D. control", "R. control"], location_rows(summary), None),
             ("protocol_repair.tex", ["Tool", "Pairs", "Located", "Some", "All", "Silent"], repair, None),
             ("protocol_dedicated.tex", ["Tool", "Dedicated scope", "Defect loc.", "Control loc.", "Lifecycle"], dedicated_table, "llrrc"),
             ("protocol_common.tex", ["Tool", "Defect loc.", "Control loc.", "Some", "All", "Silent"], common, None),
             ("protocol_coverage.tex", ["Tool", "Run OK", "Partial", "Unusable", "Flagged usable"], coverage, None)]
    for filename, headers, values, columns in specs:
        path = tables / filename
        table(path, headers, values, columns); outputs.append(path)
    manifest = {"snapshot": snapshot,
                "source_root": str(root), "input_count": len(inputs.records),
                "inputs": dict(sorted(inputs.records.items())),
                "outputs": {str(p.relative_to(output)).replace("\\", "/"): {"sha256": sha(p), "bytes": p.stat().st_size} for p in outputs},
                "policy": summary["filter"], "scope": summary["semantics"]}
    write_json(data / "protocol_manifest.json", manifest)
    print(json.dumps({"output_dir": str(output), "input_files": len(inputs.records),
                      "related": {tool: scopes["tool_available"] for tool, scopes in summary["protocols"]["related"].items()}}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
