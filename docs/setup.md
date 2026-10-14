# Pinned tools and setup

Use a Linux x86-64 environment with Bash, or Windows with WSL and a Linux x86-64 distribution. Python controllers can run on Windows or Linux. On Windows, analysis commands are sent through `wsl.exe --exec bash -lc`; `TL_WSL_DISTRO` selects a distribution. Installed tools and Java must be available inside that Linux environment.

## Requirements

- Python 3.10 or newer; the reproduction scripts use the standard library.
- Eclipse Temurin JDK **21.0.12.1+1**, the recorded analyzer runtime.
- Apache Maven **3.9.12** for building study components and resolving subject dependencies.
- Bash and GNU utilities, including `timeout`, `find`, `grep`, `sed`, `sort`, `curl`, `tar`, `unzip`, `sha256sum`, and `xz`; `openssl` is used for fresh local Sonar credentials.
- Network access to the listed official distributions, Maven Central, and GitHub when fetching inputs. Frozen-result checks are offline.

The original experiments used an Intel i9-11900T host with 64 GB RAM and a WSL memory allocation of 32 GB. Set `--jobs` and Java heap sizes to fit your machine; a single worker reduces peak memory. Multiple release workers each consume their own heap. Reserve at least 20 GB of free disk space for tool installations, extracted subjects, raw outputs, and temporary analysis data, with additional space for a growing Maven cache or concurrent CodeQL databases. The pinned binary and source archives alone total about 557 MiB. Concurrent run times are not a controlled speed comparison between tools.

## Official pinned distributions

The links below were checked against official release or distribution pages on 2026-10-14. Keep these versions when reproducing the recorded configuration.

| Component | Version | Official release / distribution |
|---|---|---|
| JDK | Temurin 21.0.12.1+1 | [Release](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1), [Linux x64 archive](https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz) |
| Maven | 3.9.12 | [Release history](https://maven.apache.org/docs/history.html), [archive](https://archive.apache.org/dist/maven/maven-3/3.9.12/binaries/apache-maven-3.9.12-bin.tar.gz) |
| SpotBugs | 4.9.8 | [Release](https://github.com/spotbugs/spotbugs/releases/tag/4.9.8), [ZIP](https://github.com/spotbugs/spotbugs/releases/download/4.9.8/spotbugs-4.9.8.zip) |
| PMD | 7.28.0 | [Release](https://github.com/pmd/pmd/releases/tag/pmd_releases/7.28.0), [binary ZIP](https://github.com/pmd/pmd/releases/download/pmd_releases/7.28.0/pmd-dist-7.28.0-bin.zip) |
| Infer | 1.3.0 | [Release](https://github.com/facebook/infer/releases/tag/v1.3.0), [Linux x86-64 archive](https://github.com/facebook/infer/releases/download/v1.3.0/infer-linux-x86_64-v1.3.0.tar.xz) |
| Error Prone | 2.50.0 | [Release](https://github.com/google/error-prone/releases/tag/v2.50.0), [JAR with dependencies](https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_core/2.50.0/error_prone_core-2.50.0-with-dependencies.jar) |
| CodeQL CLI | 2.27.1 | [Release](https://github.com/github/codeql-cli-binaries/releases/tag/v2.27.1), [Linux x64 ZIP](https://github.com/github/codeql-cli-binaries/releases/download/v2.27.1/codeql-linux64.zip) |
| CodeQL Java queries | 1.11.11 | [Pinned pack metadata](https://github.com/github/codeql/blob/codeql-cli/v2.27.1/java/ql/src/qlpack.yml); suite `java-security-and-quality.qls` |
| SonarQube Community Build | 26.8.0.126808 | [Release](https://github.com/SonarSource/sonarqube/releases/tag/26.8.0.126808), [ZIP](https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-26.8.0.126808.zip) |
| Sonar Java analyzer | 8.37 | Bundled with the pinned Community Build; recorded **Sonar way** profile |
| SonarScanner CLI | 8.1.0.6389 | [Official scanner documentation](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/scanners/sonarscanner), [Linux x64 ZIP](https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-8.1.0.6389-linux-x64.zip) |

Extract each distribution outside the repository, preserving its complete directory. In particular, `spotbugs.jar` needs the other files in the SpotBugs distribution. Add Maven to the Linux `PATH` and set `JAVA_HOME` to the extracted JDK. The default runtime location is `~/jdk/jdk21`; it can be a local symlink to the pinned JDK.

These official GitHub release asset SHA-256 values can check the downloaded archives:

```text
OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz  ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94
spotbugs-4.9.8.zip                                e13d476403cf69074f415e35ebcc2f865f7a1ea444c1e659516bc0260e74dfa5
pmd-dist-7.28.0-bin.zip                           f974ba571f7bc01c73fffe11bade25fbc1f438698f9e9c00e416e8d65e9fbac2
infer-linux-x86_64-v1.3.0.tar.xz                   02be62ba931cb43e2d42bbf7abf4bd9a410cf8464cce5453934e25c90a825850
codeql-linux64.zip                               6ad2cead390cecf62dd59ae7ffd673d216902a9c00975ce107a362464a8b891e
```

## Paths and environment variables

The examples use the runner defaults. Adjust each path to the directory you actually extracted. On Windows, set the same variables in the controller's environment; Linux paths refer to the selected WSL distribution. A variable set only in an unrelated terminal is not inherited by the controller.

```bash
export JAVA_HOME="$HOME/jdk/jdk21"
export PATH="$JAVA_HOME/bin:$HOME/tools/apache-maven-3.9.12/bin:$PATH"
export TL_SPOTBUGS_JAR="$HOME/tools/spotbugs-4.9.8/lib/spotbugs.jar"
export TL_PMD="$HOME/tools/pmd-bin-7.28.0/bin/pmd"
export TL_INFER="$HOME/tools/infer/bin/infer"
export TL_CODEQL="$HOME/tools/codeql/codeql"
export TL_ERRORPRONE_JAR="$HOME/tools/errorprone/error_prone_core-2.50.0-with-dependencies.jar"
```

For Infer, either use that local installation alias or set `TL_INFER` to the actual extracted archive's `bin/infer`. Error Prone accepts `TL_ERRORPRONE_JAR`, or `TL_ERRORPRONE_CP_FILE` pointing to a file containing its complete processor classpath. The JAR with dependencies avoids assembling that file manually.

`TL_JAVA` optionally overrides the Java executable. `TL_EVAL_ROOT` optionally changes the experiment directory; its value is the directory containing `gt/`, `baselines/`, and `tldoctor2/`, rather than the repository root. Leave it unset for this checkout. Windows drive paths are mapped into WSL; use a local drive checkout rather than a UNC network path.

For a Windows Python controller, a PowerShell environment example is:

```powershell
$env:TL_WSL_DISTRO = "Ubuntu"
$env:JAVA_HOME = "/home/your-user/jdk/jdk21"
$env:TL_SPOTBUGS_JAR = "/home/your-user/tools/spotbugs-4.9.8/lib/spotbugs.jar"
```

Replace the distribution and Linux user paths with your installation. Set the other `TL_*` tool variables in the same way when overriding their defaults. Maven must be on the WSL login shell's `PATH`.

Install the pinned CodeQL query pack once:

```bash
"$TL_CODEQL" pack download codeql/java-queries@1.11.11
```

The runner explicitly analyzes `codeql/java-queries@1.11.11:codeql-suites/java-security-and-quality.qls`. The CLI's own bundled runtime is separate from the JDK 21 used to compile subjects. See [official CLI setup](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli).

## Build study components

In the Linux/WSL shell, from the repository root:

```bash
cd experiment
mvn -f tldoctor2/pom.xml -DskipTests package
mvn -f baselines/spotbugs-tl/pom.xml -DskipTests package
bash baselines/pmd-tl/build.sh
cd ..
```

The outputs are `experiment/tldoctor2/target/tldoctor2.jar`, `experiment/baselines/spotbugs-tl/target/spotbugs-threadlocal-plugin-1.0-SNAPSHOT.jar`, and `experiment/baselines/pmd-tl/target/pmd-threadlocal-rules-1.0-SNAPSHOT.jar`. Infer-TL uses the scripts under `experiment/baselines/infer-tl/`.

LifeTL's Maven build pins [Soot 4.6.0](https://github.com/soot-oss/soot/releases/tag/4.6.0), [ASM 9.9.1](https://asm.ow2.io/versions.html), and [Gson 2.11.0](https://github.com/google/gson/releases/tag/gson-parent-2.11.0). Maven downloads these dependencies; the repository contains their configuration, not their binary distributions.

## Local Sonar service

From the repository root in Linux/WSL:

```bash
bash experiment/gt/sonar_download.sh
bash experiment/gt/sonar_server.sh start
bash experiment/gt/sonar_server.sh status
```

The download helper installs the pinned server and scanner under `~/tools/sonarqube`. Defaults are `TL_SONAR_HOME=~/tools/sonarqube/sonarqube-26.8.0.126808`, `TL_SONAR_SCANNER=~/tools/sonarqube/sonar-scanner-8.1.0.6389-linux-x64/bin/sonar-scanner`, and `TL_SONAR_URL=http://localhost:9000`. The server runs as a normal Linux user. Follow the pinned server's [host requirements](https://docs.sonarsource.com/sonarqube-community-build/server-installation/pre-installation/linux/) if its embedded search service cannot start.

For a fresh local server, the service helper creates its administrator password and analysis token outside the repository, under `~/.local/share/threadlocal-evaluation/sonar/`. `TL_SONAR_TOKEN_FILE` points to the token file, not the token value. To use an existing server, supply your own token file and service URL. The runner reads credentials at runtime; do not commit credential files. Stop a locally started server with `bash experiment/gt/sonar_server.sh stop`.
