#!/usr/bin/env bash
# Downloads the recorded versions outside the repository.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/runtime.sh"
mkdir -p "$TL_SONAR_INSTALL_DIR"
cd "$TL_SONAR_INSTALL_DIR"
SQ=sonarqube-26.8.0.126808.zip
SC=sonar-scanner-cli-8.1.0.6389-linux-x64.zip
for archive in "$SQ" "$SC"; do
  if [ ! -s "$archive" ]; then
    component=sonarqube
    [[ "$archive" == sonar-scanner-* ]] && component=sonar-scanner-cli
    curl -fL --retry 3 -o "$archive.part" "https://binaries.sonarsource.com/Distribution/$component/$archive"
    mv "$archive.part" "$archive"
  fi
done
unzip -q -o "$SQ"
unzip -q -o "$SC"
sha256sum "$SQ" "$SC" > SHA256SUMS
printf 'Installed pinned Sonar server and scanner in %s\n' "$TL_SONAR_INSTALL_DIR"
