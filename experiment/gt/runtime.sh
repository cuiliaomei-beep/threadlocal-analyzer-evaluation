#!/usr/bin/env bash
# Shared shell defaults; credentials are generated outside the repository.
JAVA_HOME="${JAVA_HOME:-$HOME/jdk/jdk21}"
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"
export SONAR_JAVA_PATH="$JAVA_HOME/bin/java"
TL_SONAR_INSTALL_DIR="${TL_SONAR_INSTALL_DIR:-$HOME/tools/sonarqube}"
TL_SONAR_HOME="${TL_SONAR_HOME:-$TL_SONAR_INSTALL_DIR/sonarqube-26.8.0.126808}"
TL_SONAR_SCANNER="${TL_SONAR_SCANNER:-$TL_SONAR_INSTALL_DIR/sonar-scanner-8.1.0.6389-linux-x64/bin/sonar-scanner}"
TL_SONAR_URL="${TL_SONAR_URL:-http://localhost:9000}"
TL_SONAR_RUNTIME_DIR="${TL_SONAR_RUNTIME_DIR:-$HOME/.local/share/threadlocal-evaluation/sonar}"
TL_SONAR_TOKEN_FILE="${TL_SONAR_TOKEN_FILE:-$TL_SONAR_RUNTIME_DIR/token.txt}"
