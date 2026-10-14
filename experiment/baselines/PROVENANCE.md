# Baselines: what is published text and what was written for this evaluation

Date: 2026-09-29. Decision of the team: PMD-TL and Infer-TL are implemented from their descriptions in the TLDoctor
repository (`TLDoctor/PMD-TL.md`, `TLDoctor/Infer-TL.md`), because the repository does not contain runnable code for them.
All three -TL baselines were built **after** the held-out run of LifeTL and **without looking at held-out results of
any tool while writing them**; the only project used for smoke tests was `mvel2-2.1.4.Final` and `netty-common-4.0.53.Final`
(both held-out releases, used to check that the tools load and produce output, not to tune rules).

| baseline | published in the document | written for this evaluation |
|---|---|---|
| SpotBugs-TL | all four detectors (complete Java source), `findbugs.xml`, `messages.xml`, `bugrank.txt` — extracted verbatim by `spotbugs-tl/extract_from_md.py` | package placeholder `edu.****` → `edu.anon`; 3 `<Detector>` descriptions and 1 `<BugCode>` appended to `messages.xml` (SpotBugs refuses to load the plugin without them) |
| PMD-TL | ruleset XML (verbatim, extracted by `pmd-tl/build.sh`); the `visit` method of each of the four rules (§4.1–§4.4) | `ThreadLocalAstUtil` (311 lines): the document only names its methods and describes them in prose; property descriptors in the four rule classes (the published ruleset sets properties that the published skeletons do not define, which PMD rejects) |
| Infer-TL | the four `detect_*` functions and the HEAVY/BENIGN type lists (§4); the fact-database schema (§3); the workflow (§6) | `collect_threadlocal_facts.py` and `infer_tl_postprocess.py` as files; all helpers called by `detect_*` (`is_task_or_request_like`, `has_matching_cleanup`, `has_effect_before_delegate`, `has_restore_after_delegate`, `looks_growth_prone`, `has_bounding_or_reset_logic`, …); `detect_cpm` passes the boundary record to its helpers (needed to know where the delegate call is) |

Interpretations that had to be chosen (each is a place where the original authors may have done something else):

1. PMD-TL `requireLongLivedEvidence=true` is read as "the field is static".
2. PMD-TL / Infer-TL "known holder" is read as a receiver whose type or name contains `ContextHolder` (the only holder
   name given in the three documents).
3. Infer-TL `is_task_or_request_like`: a handler/task method name (run, call, handle*, process*, execute*, on*, doFilter…)
   or a method that no captured procedure calls and that is not setter-like.
4. Infer-TL call graph: Infer's own static callee list (`infer debug --procedures --procedures-callees`), searched to depth 3
   for a cleanup in a callee.
5. Infer-TL use of Infer's report: issues are attached to the warning of the method they occur in; an Infer leak issue
   whose message names a ThreadLocal is passed through as SCO. The published `detect_*` functions themselves do not read
   the Infer report.
6. Versions: PMD 7.28.0 (the document says 7.0.0; the rule API is the same), SpotBugs 4.9.8 (as in the document),
   Infer 1.3.0 (the document names no version).

Effort (for the pre-registration record of L3 baselines): SpotBugs-TL 0 lines written (descriptor entries only);
PMD-TL 311 lines of helper code + 185 lines of rule classes; Infer-TL 2 scripts (fact extraction, post-processing).
All of it was written in one working session on 2026-09-29.

Pattern → obligation mapping used for scoring (FSE-PLAN §2.2): SCO → O1, CLP → O3, CPM → O2, HVR → O4.

## Public reproduction copy

The checked-in adaptation sources and descriptors preserve the evaluated implementation.
The PMD ruleset is also supplied in `pmd-tl/resources/rulesets/threadlocal-pmd-ruleset.xml`;
its contents match the documented XML after the package substitution above (SHA-256
`3206dffa5855994b780a29999616b4e3a69dc13d6598f1f18c2d45cab2230b61`).
The public PMD build copies this file instead of extracting Markdown during every build.
The public runner changes concern platform invocation, paths, pinned tool configuration,
and subset smoke selection; they do not change the detector or post-processing predicates.
Native raw output is retained. Legacy normalized tiers and TP/FP column names are historical
report fields, not semantic precision judgments; current dedicated/related measurements
are produced by the public `scripts/recompute_protocols.py` parser.
Stock SpotBugs uses `gt/42_spotbugs_full.py`; `gt/25_baselines.py` accepts only SpotBugs-TL.
