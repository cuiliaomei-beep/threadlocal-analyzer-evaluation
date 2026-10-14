# Component provenance and distribution boundaries

This repository combines the study's annotations, runners, reconstruction code, and reference checker with inherited baseline description material. Component origins are recorded separately; an upstream tool's license does not automatically license a description document or a reconstruction of it.

## Study baseline reconstructions

The study's ThreadLocal adaptations were reconstructed from the TLDoctor description documents listed below. Those documents are not included in this checkout. The copied [baseline provenance record](../experiment/baselines/PROVENANCE.md) details extraction steps and implementation choices. Maven builds the checked-in SpotBugs-TL sources directly; its historical Markdown extraction helper requires the original description document as an external input.

| Component | Inherited material | Execution material added for the study |
|---|---|---|
| SpotBugs-TL | Four detector source listings and plugin descriptors from `SpotBugs-TL.md` | Placeholder package replacement and required descriptor entries so the plugin loads |
| PMD-TL | Ruleset XML and rule-visit descriptions from `PMD-TL.md` | AST helper functions, executable rule classes, and property descriptors required by the described ruleset |
| Infer-TL | Detection-function descriptions, type lists, fact schema, and workflow from `Infer-TL.md` | Source-fact collection, call-graph traversal, boundary helpers, and report postprocessing |

The adaptations should be identified as these study reconstructions. The provenance record explains interpretations such as static-field lifetime evidence, `ContextHolder` recognition, task-like boundaries, and Infer callee traversal depth. The PMD description names 7.0.0; this evaluation builds against the pinned 7.28.0 API. Infer is pinned to 1.3.0 because the description does not specify a release.

LifeTL is built from `experiment/LifeTL/`, including its framework model. Maven resolves its Soot, ASM, and Gson dependencies at the pinned versions. Their upstream distribution terms continue to apply to those dependencies.

## External tools and subjects

Stock analyzer distributions, dependency JARs, release binaries, source archives, and downloaded case-study source files are not committed. The [setup guide](setup.md) links official tool distributions. Subject and case manifests record URLs, hashes, paths, and revisions; reproduction fetches the corresponding upstream material. Downloads remain subject to the originating projects' distribution terms and notices.

The repository's ignore rules exclude `experiment/gt/jars/`, `experiment/gt/sources/`, `experiment/out/`, Maven `target/` directories, local tool installations, logs, and runtime credentials. Generated results use `results/reproduced/`; the committed reference contains recorded results and selected diagnostic objects rather than bundled analyzer binaries.

## Licensing scope

The inherited TLDoctor description documents were supplied without an accompanying license file in the source snapshot inspected for this artifact. The reconstruction provenance records their origin and transformations; it does not assert permission to relicense that material. No blanket license is assigned here to inherited descriptions or extracted source snippets. Consult component-specific notices and upstream terms when using or redistributing those components. Any future repository-level license should state precisely which study-owned files it covers and preserve inherited material's separate status.

Project-report records preserve their supplied CSV evidence and the explicit exclusion in `manifests/report_scope.json`. Case source revisions and released dependencies are recorded in `manifests/case_studies.json`. These evidence inventories are separate from the historical corpus and do not change its scoring selection.
