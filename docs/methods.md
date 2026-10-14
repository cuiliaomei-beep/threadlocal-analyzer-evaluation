# Corpus, configurations, and result interpretation

## Corpus and operational scope

The annotation inventory contains 302 records: 156 included historical defects, four excluded positives, 128 benign changes, and 14 unclear records. The 156 defects span 95 repositories. Release matching prepares 159 pre/post pairs and 264 distinct releases, including 133 distinct pre releases. The scored selection contains 82 defects from 57 repositories and 64 effective controls. Thirteen prepared records remain outside location and repair-response scoring: four excluded positives, eight unclear records, and one invalid control (`H0129`).

The frozen design split has 46 scored defects and 31 controls; the held-out split has 36 defects and 33 controls. `experiment/gt/split/split_frozen.csv` fixes membership, `annotation/annotation_final.csv` fixes labels and obligations, `jar_pairs_verified.csv` supplies release paths and repair classes, and `matrix/matrix_final.csv` records the obligation inventory. `manifests/artifacts.json` supplies downloadable inputs and integrity hashes.

Warnings and availability are operational summaries over the full prepared inventory. Location and repair-response results use the eligible 82/64 scoring selection. A shared release is deduplicated for release-level availability and volume; distinct annotated records can still refer to that release. The 82/156 selection ratio describes executable input coverage, rather than analyzer recall.

## Eleven configurations

| Group | Configurations and recorded setup |
|---|---|
| Native | SpotBugs 4.9.8 full stock enabled detectors, `-effort:max -low`; PMD 7.28.0 with eight requested Java categories; Infer 1.3.0 default checkers; CodeQL 2.27.1 / Java queries 1.11.11 `java-security-and-quality`; Error Prone 2.50.0 default checks, errors reported as warnings; Sonar Community Build 26.8.0.126808 / Java analyzer 8.37 / Sonar way |
| Reconstructed adaptations | SpotBugs-TL, PMD-TL, Infer-TL, implemented from the description documents with the recorded reconstruction choices |
| Reference configurations | Typestate-only and full LifeTL, using the pinned framework model and limits |

PMD requests `bestpractices`, `codestyle`, `design`, `documentation`, `errorprone`, `multithreading`, `performance`, and `security`. Its stock inventory of 325 rule definitions is not evidence that all 325 execute: configuration and processing errors are preserved, including `LoosePackageCoupling` configuration errors. Inventories for other tools likewise describe inspected definitions, rather than uniform active-check counts.

Source analyzers consume the source archive for the same release used by bytecode analyzers. For tools that require compilation, preparation uses JDK 21, source/target levels derived from release metadata within 8–21, the release binary, and POM-resolved dependencies. Preparation can drop source files that fail compilation and records file counts. Annotation processing is disabled. PMD directly parses the release sources and uses the release binary as its auxiliary classpath. Sonar receives release binaries and resolved dependencies for semantic analysis. Successful preparation and parseable diagnostics therefore do not assert complete project compilation. The runners preserve raw XML, compiler logs, Infer reports, SARIF, or Sonar issue responses alongside normalized records.

## Two native selection protocols

The **related** protocol applies the same mechanical relevance test to every native tool's primary diagnostics. A diagnostic is retained when its full message contains the case-sensitive substring `ThreadLocal`, or a main source location contains `ThreadLocal` or a syntactically declared ThreadLocal field name from the same file. A span inspects its start through at most the next four lines, capped by the reported end; a point location inspects one line. Field discovery is restricted lexically to direct class-body declarations and is not semantic name binding.

Secondary Infer traces, CodeQL related locations/code flows, and Sonar flows do not create a relevance hit. For SpotBugs, the selected location is a primary or first direct `BugInstance` source line, then a primary method/field source line, then the primary class. Its complete raw output is retained; the relevance filter is applied during protocol reconstruction.

The **dedicated** protocol intersects that same relevance filter with the shipped rule whitelist: SpotBugs `SIC_THREADLOCAL_DEADLY_EMBRACE`, Error Prone `ThreadLocalUsage`, and Sonar `java:S5164`. These checks have different scopes: initialization/deadlock, static-field structure, and cleanup, respectively. PMD, Infer, and the configured CodeQL inventory have no identified dedicated ThreadLocal lifecycle check. The lifecycle-only inventory includes Sonar's cleanup check. Dedicated counts do not replace the broader related protocol.

## Co-location and repair-response keys

A record is located when an eligible pre-release diagnostic matches a simple repair-class name, using the recorded declaration, method, or ThreadLocal-related class. Enclosing and nested classes are normalized by the matcher. This is a fix-class co-location surrogate: a general diagnostic at the class can match without diagnosing the repair's causal obligation. A matched benign control is likewise a control co-location, rather than an adjudicated false positive.

The normalized key consists of rule family, declaration class, ThreadLocal identifier, and method class. Native tools use the primary class as the ThreadLocal identifier surrogate. Line numbers and method names are excluded from the repair key, so line movement alone cannot make a key disappear. Adaptation and checker outputs retain their own diagnostic tiers and identities; the main reference scoring uses `REPORT` diagnostics.

Let `Pre` and `Post` be matched key sets for a record with usable outputs on both sides:

- **Some**: `Pre` is nonempty and at least one pre key is absent from `Post`.
- **All**: `Pre` is nonempty and no pre key remains in `Post`. New post keys may still exist.
- **Silent**: `Pre` is nonempty and `Post` is empty.

These are nested predicates: Silent implies All, and All implies Some. Their counts must not be added. A disappearing key is a mechanical response to the version change, rather than proof that the diagnostic was correct or that the repair fully resolved the lifecycle obligation. CSV names such as `tp_any`, `tp_dom`, and `fp_candidates` are retained for script compatibility; they should be read through these definitions, rather than as adjudicated precision/recall statistics.

## Availability and warning volume

An output is **usable** when its recorded operational status is accepted and its raw output is parseable. Full stock SpotBugs accepts `OK` and `PARTIAL`; `ERROR` is excluded even if diagnostics were emitted. The frozen 264-release inventory records 185 `OK`, 73 `PARTIAL`, and six `ERROR` runs. Missing classes and dependency resolution information remain separate fields. Thirty-eight SpotBugs releases lack a matching source file for relevance lookup, limiting the source/field branch; message-based selection remains available.

Across the configurations, analyzer failures affect 22 unique releases. Tool-release failures can overlap and should not be added as unique versions; the four unavailable source archives are reported separately. The per-release CSV preserves raw and operational status distinctions. A complete-only SpotBugs view and a common native usable subset are also recorded. The common native subsets contain 70 defects / 61 controls for pre-side measurements and 69 defects / 60 controls for paired measurements. Usability of that subset still does not imply equal or complete analyzed code.

Warning volume counts selected diagnostics from usable pre releases, deduplicated by release, over the full prepared inventory. Raw diagnostic counts, selected counts, compilation coverage, and class matches describe different stages. Neither total warning volume nor a control-match count estimates a tool's diagnostic precision.

## Reading committed results

| File | Interpretation |
|---|---|
| `results/evaluation.csv` | Compact summaries for all 11 configurations; native rows use the related protocol |
| `results/evaluation_rows.csv` | Configuration-by-prepared-record outcomes, including unscored rows |
| `results/evaluation_releases.csv` | Release-level operational availability and counts |
| `results/evaluation.json` | Combined summaries, corpus scope, availability, and metadata |
| `results/protocol_aggregate.csv` | Native aggregates for both selection protocols and common subsets |
| `results/protocol_related_rows.csv`, `protocol_dedicated_rows.csv` | Record-level native measurements under each protocol |
| `results/protocol_releases.csv` | Native release status, coverage, source lookup, and selected volume |
| `results/protocol_summary.json` | Explicit relevance, keys, cohorts, and summary definitions |
| `results/protocol_warnings.json` | Selected native diagnostic objects, linked to counted records |
| `results/ablation/` | Frozen selected component and cumulative summaries |
| `results/report_counts.json` | Independent project-report recount and activity flags |
| `results/case_diagnostics.json` | Six pinned target-class audits and actual LifeTL diagnostic identities |

Run `python scripts/verify_results.py` to check the committed summaries against their record-level evidence and file hashes. Run the commands in [reproduction.md](reproduction.md) to create a new analysis and separately recompute its native protocols.
