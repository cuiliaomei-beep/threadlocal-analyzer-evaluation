# Reproduction commands

All Python commands below start from the repository root. Install [the pinned environment](setup.md) first for analyzer runs. The `scripts/` commands discover the checkout from their own path; experiment controllers use the shared runtime helper. Fresh outputs and downloaded inputs are ignored by Git.

## Frozen-result quick check

```bash
python scripts/verify_results.py
python scripts/reproduce_reports.py --check
```

`verify_results.py` verifies `manifests/frozen_files.json`, then recounts the annotations, prepared releases, configuration rows, native protocols, selected warning objects, and component summaries. `reproduce_reports.py` independently checks the project-report reference. Both commands are offline.

## Fetch subjects

First inspect the selection without downloading:

```bash
python scripts/fetch_subjects.py --mode both --split heldout --limit 2 --dry-run
```

Fetch all manifest-listed releases, or a specific record:

```bash
python scripts/fetch_subjects.py --mode both
python scripts/fetch_subjects.py --mode both --ids C004
python scripts/fetch_subjects.py --mode both --verify-only
```

`manifests/artifacts.json` provides the frozen download URLs, local destinations, and hashes. `--mode binary|source|both`, `--split all|design|heldout`, `--ids` with comma-separated record IDs, and `--limit` select a subset. A limit counts distinct releases after selection. Source mode fetches source archives and POMs and safely extracts source files into `experiment/gt/sources/`; binary mode fills `experiment/gt/jars/`. Four inventory releases have no recorded source archive. `--no-extract` retains verified archives without extraction; source analyzers need the extracted `src/` trees. `--force` permits replacement of a checksum-mismatching local file.

## Smoke example

The following exact subject and analyzer commands were executed successfully on 2026-10-14. `C004` selects `jackson-core` 2.9.1 and 2.9.2.

```bash
python scripts/fetch_subjects.py --ids C004 --mode both
python experiment/gt/23_run_design.py run --split all --ids C004 --tag smoke --jobs 2 --xmx 3g --timeout 180
python experiment/gt/23_run_design.py eval --split all --ids C004 --tag smoke
python experiment/gt/42_spotbugs_full.py --release jackson-core-2.9.1 --release jackson-core-2.9.2 --jobs 2
```

LifeTL produced four warnings on each release. Full stock SpotBugs retained 216 and 215 raw diagnostics, respectively, with no missing classes or analysis errors in these two runs. Inspect `experiment/out/smoke/` and `experiment/out/bl-spotbugs-full/`. This example checks fetching, compilation of the checker, path portability, and raw-output retention; it is a small input selection.

To exercise the same two releases with the other native runners, use their **release keys**, rather than the corpus record ID:

```bash
python experiment/gt/27_source_tools.py pmd --split all --which both --ids jackson-core-2.9.1,jackson-core-2.9.2 --jobs 1 --timeout 7200
python experiment/gt/27_source_tools.py infer --split all --which both --ids jackson-core-2.9.1,jackson-core-2.9.2 --jobs 1 --infer-jobs 2 --timeout 10800
python experiment/gt/37_more_analysers.py codeql --split all --which both --ids jackson-core-2.9.1,jackson-core-2.9.2 --jobs 1 --timeout 14400
python experiment/gt/37_more_analysers.py errorprone --split all --which both --ids jackson-core-2.9.1,jackson-core-2.9.2 --jobs 1 --timeout 7200
python experiment/gt/40_sonar.py --split all --which both --ids jackson-core-2.9.1,jackson-core-2.9.2 --jobs 1 --timeout 7200
```

These subset commands produce raw outputs for the selected releases. Native protocol reconstruction over an incomplete inventory retains unavailable records in its release accounting; use the full runs below for the complete frozen cohort's comparison.

## Full experiment

### Six native configurations

Fetch all subjects with `--mode both`. Run Infer before CodeQL and Error Prone if you want them to reuse the successfully prepared source-file lists. Each command preserves its own raw diagnostics under `experiment/out/bl-*/`.

```bash
python experiment/gt/27_source_tools.py pmd --split all --which both --jobs 3 --timeout 7200
python experiment/gt/27_source_tools.py infer --split all --which both --jobs 2 --infer-jobs 6 --timeout 10800
python experiment/gt/37_more_analysers.py codeql --split all --which both --jobs 2 --timeout 14400
python experiment/gt/37_more_analysers.py errorprone --split all --which both --jobs 3 --timeout 7200
python experiment/gt/40_sonar.py --split all --which both --jobs 2 --timeout 7200
python experiment/gt/42_spotbugs_full.py --jobs 3 --timeout 3600 --dependency-timeout 600 --xmx 4g
```

These commands select both sides of all prepared pairs and deduplicate shared releases. To run a smaller source-tool selection, add `--ids jackson-core-2.9.1,jackson-core-2.9.2`; SpotBugs full stock instead accepts repeated `--release` keys or `--limit N`. Controllers cache completed outputs. Source-tool `--force` reruns cached releases; inspect each runner's `--help` for its retry options.

After the six raw-output sets and extracted sources are available, construct the current native comparison:

```bash
python scripts/recompute_protocols.py
```

This reads full stock SpotBugs XML and the other five tools' raw outputs, applies the common relevance and class-location selection, and writes both **related** and **dedicated** protocols to `results/reproduced/`. Outputs include `protocol_related_rows.csv`, `protocol_dedicated_rows.csv`, `protocol_releases.csv`, `protocol_aggregate.csv`, `protocol_summary.json`, selected diagnostics in `protocol_warnings.json`, a hashed input/output manifest, and generated tables. `--output-dir` selects another destination. `--reuse-if-current` reuses outputs only when every consumed input and cached output has its recorded hash.

The normalized JSON written by the older configuration runners is also retained. In particular, `23_run_design.py eval` alone uses the earlier Error Prone/Sonar normalization and is not the uniform native protocol. Use `recompute_protocols.py` for the native figures and comparison counts.

### Reconstructed ThreadLocal baselines

Build the adaptations as described in setup, then run:

```bash
python experiment/gt/25_baselines.py spotbugs-tl --split all --jobs 3
python experiment/gt/27_source_tools.py pmd-tl --split all --which both --jobs 3 --timeout 7200
python experiment/gt/27_source_tools.py infer-tl --split all --which both --jobs 2 --infer-jobs 6 --timeout 10800
python experiment/gt/23_run_design.py eval --split all --tag bl-spotbugs-tl
python experiment/gt/23_run_design.py eval --split all --tag bl-pmd-tl
python experiment/gt/23_run_design.py eval --split all --tag bl-infer-tl
```

These are study reconstructions of the published description documents. [Component provenance](provenance.md) identifies the extracted material and helpers added for execution. Their diagnostic tiers and obligation mappings remain separate from the native uniform-relevance protocol.

### LifeTL and typestate-only

```bash
python experiment/gt/23_run_design.py run --split all --tag reproduced-full --jobs 4 --xmx 6g --timeout 1200
python experiment/gt/23_run_design.py eval --split all --tag reproduced-full
python experiment/gt/23_run_design.py run --split all --tag reproduced-typestate --mode typestate --jobs 4 --xmx 6g --timeout 1200
python experiment/gt/23_run_design.py eval --split all --tag reproduced-typestate
```

Use `--split design` or `--split heldout` for the two frozen partitions. The tags keep raw runs and generated `eval_<split>.csv` / Markdown summaries separate. `REPORT` tier feeds the principal co-location measurements; additional diagnostic tiers remain available in the raw checker JSON.

### Component diagnostics

```bash
python experiment/gt/32_ablation.py run --group ablation --split heldout --jobs 4
python experiment/gt/32_ablation.py run --group cumulative --split heldout --jobs 4
python experiment/gt/32_ablation.py report --split heldout
```

The ablation controller uses separate `abl-*` tags and the same evaluation definition. `--group sensitivity` runs the documented limit variations. Frozen component outputs are under `results/ablation/`. Historical cost helpers `29_measure.py` and `31_cost_runs.py` retain a **spotbugs-restricted-cost** configuration; it is distinct from the full stock detector configuration in `42_spotbugs_full.py`.

## Case studies

```bash
python scripts/audit_cases.py --list
python scripts/audit_cases.py --case all --jobs 2 --check-reference
```

The audit downloads the exact six upstream target source files and released dependencies listed in `manifests/case_studies.json`, checks their hashes, compiles each target and its nested classes with `javac --release 17 -proc:none`, and analyzes the resulting JAR with LifeTL. It creates a timestamped directory under `experiment/out/case-audit/` with logs, source hashes, class inventory, diagnostics, and `manifest.json`. `--case quickfix|redis|influx` selects one case; `--heap` and `--timeout` control analysis resources.

`--check-reference` compares `(rule, tier, ThreadLocal identifier, method, line)` diagnostic identities against `results/case_diagnostics.json`. All six sides passed this check on 2026-10-14, with zero body and graph errors. These are target-class audits with released dependency JARs: QuickFIX/J uses 3.0.0, InfluxDB Java uses 2.25, and Redis's selected target uses JDK types. The dependency releases are not a complete build of each source revision. QuickFIX/J's audit records two unresolved calls. The frozen diagnostics permit inspection of the actual checker response, including warnings retained after a repair.

## Project-report recount

```bash
python scripts/reproduce_reports.py --check
python scripts/reproduce_reports.py --output results/reproduced/report_counts.json
```

This reads `manifests/reports_source.csv` and `manifests/report_scope.json`. The scope excludes the Karaf record, which is not an author-submitted report. It recounts 64 reports across 61 repositories, 24 confirmed flags, 14 rejected flags, and 26 without either flag. Nineteen records have recorded repair activity: 17 have a commit or explicit merged marker, and two have a PR only. A PR is counted irrespective of its merge status, and confirmation is an independent field. The command recounts the frozen records rather than fetching changing issue states.
