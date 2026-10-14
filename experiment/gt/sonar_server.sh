#!/usr/bin/env bash
# Local embedded-H2 server. No runtime password or token is distributed.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/runtime.sh"
umask 077
status() { curl -s -m 5 "$TL_SONAR_URL/api/system/status" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", "UNKNOWN"))' 2>/dev/null || true; }
case "${1:-status}" in
  start)
    [ -x "$TL_SONAR_HOME/bin/linux-x86-64/sonar.sh" ] || { echo 'Install pinned SonarQube first'; exit 2; }
    if [ "$(status)" != UP ]; then
      ulimit -n 131072 2>/dev/null || ulimit -n 65536 2>/dev/null || true
      "$TL_SONAR_HOME/bin/linux-x86-64/sonar.sh" start
      for i in $(seq 1 90); do [ "$(status)" = UP ] && break; sleep 5; done
    fi
    [ "$(status)" = UP ] || { tail -20 "$TL_SONAR_HOME/logs/sonar.log"; exit 3; }
    mkdir -p "$TL_SONAR_RUNTIME_DIR" "$(dirname "$TL_SONAR_TOKEN_FILE")"
    if [ ! -s "$TL_SONAR_TOKEN_FILE" ]; then
      PW_FILE="$TL_SONAR_RUNTIME_DIR/password.txt"
      if [ -s "$PW_FILE" ]; then PW=$(cat "$PW_FILE"); else
        PW="Tl!$(openssl rand -hex 10)Q9"
        curl -fsS -u admin:admin -X POST "$TL_SONAR_URL/api/users/change_password" --data-urlencode login=admin --data-urlencode previousPassword=admin --data-urlencode "password=$PW" > /dev/null
        printf '%s\n' "$PW" > "$PW_FILE"
      fi
      curl -fsS -u "admin:$PW" -X POST "$TL_SONAR_URL/api/user_tokens/generate" --data-urlencode "name=tl-$(date +%s)" --data-urlencode type=GLOBAL_ANALYSIS_TOKEN | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' > "$TL_SONAR_TOKEN_FILE.part"
      [ -s "$TL_SONAR_TOKEN_FILE.part" ] || { echo 'Token generation failed'; exit 4; }
      mv "$TL_SONAR_TOKEN_FILE.part" "$TL_SONAR_TOKEN_FILE"
      echo 'Runtime token generated'
    fi
    printf 'server UP, version %s\n' "$(curl -fsS "$TL_SONAR_URL/api/server/version")"
    ;;
  stop) "$TL_SONAR_HOME/bin/linux-x86-64/sonar.sh" stop ;;
  status) printf 'status=%s version=%s\n' "$(status)" "$(curl -s -m 5 "$TL_SONAR_URL/api/server/version")" ;;
  *) echo 'Usage: sonar_server.sh start|stop|status'; exit 2 ;;
esac
