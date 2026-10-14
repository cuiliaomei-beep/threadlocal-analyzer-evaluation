# ThreadLocal analyzer evaluation

Reproduction materials for an empirical study of Java `ThreadLocal` lifecycle obligations, existing analyzers, repair responses, and project reports. The repository includes the frozen corpus, tool runners, reconstructed ThreadLocal baselines, the LifeTL reference checker, recorded results, and checks that recount those results.

中文入口：先执行下面的离线核对；重新运行实验请参阅 [安装说明](docs/setup.md) 和 [复现步骤](docs/reproduction.md)。工具与被分析项目的 JAR、源码归档按固定清单下载，不随仓库分发。

## Start with the frozen results

Clone the fixed artifact snapshot, then run these commands with Python 3.10 or newer. The checks require no analyzer installation and do not download subjects.

```bash
git clone --branch artifact-2026-10-14 https://github.com/cuiliaomei-beep/threadlocal-analyzer-evaluation.git
cd threadlocal-analyzer-evaluation
python scripts/verify_results.py
python scripts/reproduce_reports.py --check
python scripts/audit_cases.py --list
```

The first command checks file hashes and recomputes corpus counts, the 11 configuration summaries, and both native-tool selection protocols. The second independently recounts the project-report CSV under its explicit authorship scope. The third shows the pinned inputs for the three case studies.

The corpus contains 302 annotations, including 156 historical defects across 95 repositories. The prepared input inventory has 159 pre/post pairs and 264 distinct releases. Location and repair-response scoring uses 82 defects and 64 controls; the remaining 13 prepared records are retained for operational accounting. The six native suites, three reconstructed ThreadLocal adaptations, typestate-only configuration, and LifeTL are distinguished in the result files.

Read [the measurement definitions](docs/methods.md) before interpreting a match or a warning disappearing after a repair. These are class co-location and warning-key measurements. The result columns do not represent manually adjudicated precision, recall, or F1.

## Reproduce an analysis

1. Install the pinned tools using [setup.md](docs/setup.md).
2. Fetch the manifest-listed subjects and run [the smoke example](docs/reproduction.md#smoke-example).
3. Run the [full configurations and native postprocessing](docs/reproduction.md#full-experiment).
4. Optionally reproduce [the three case studies](docs/reproduction.md#case-studies) and [the project-report recount](docs/reproduction.md#project-report-recount).

Fresh analyzer outputs go under `experiment/out/`. Native protocol reconstruction writes `results/reproduced/`. The committed `results/` files remain the frozen reference.

## Repository layout

| Path | Contents |
|---|---|
| `experiment/gt/` | Annotations, frozen split, release pairing, source indexes, portable runners |
| `experiment/baselines/` | SpotBugs-TL, PMD-TL, Infer-TL implementations and reconstruction provenance |
| `experiment/TLDoctor/` | Original baseline description documents |
| `experiment/tldoctor2/` | LifeTL source, framework model, and Maven build |
| `manifests/` | Subject URLs and hashes, frozen-file hashes, report scope, pinned case inputs |
| `results/` | Configuration summaries, native protocols, selected diagnostics, ablations, report and case references |
| `scripts/` | Verified subject fetching, offline recounts, native postprocessing, case reproduction |
| `docs/` | Setup, commands, measurement definitions, and component provenance |

## Verification record

On 2026-10-14, the offline frozen-result verifier and report recount passed. The subject fetcher downloaded and hash-checked both binary releases, source archives, and POMs for record `C004` (`jackson-core` 2.9.1 / 2.9.2). LifeTL and full stock SpotBugs completed both releases through the Windows/WSL controller. The three case-study pre/post pairs also compiled and analyzed successfully, and all six stable diagnostic identity lists matched the frozen case reference. Exact commands appear in [reproduction.md](docs/reproduction.md).

Tool binaries and third-party subject archives are downloaded separately. See [provenance.md](docs/provenance.md) for component origins and distribution boundaries.
