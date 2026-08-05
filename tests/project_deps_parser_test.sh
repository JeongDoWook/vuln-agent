#!/usr/bin/env bash
# collect_project_deps_declared() 의 awk 파서 3종(go.mod/requirements.txt/pom.xml) 검증.
# 에이전트 스크립트에서 함수 정의만 뽑아 eval 하므로 실제 배포되는 코드를 그대로 검사한다.
set -uo pipefail
cd "$(dirname "$0")/.."
AGENT=agent/vuln-inventory-agent.sh

have() { command -v "$1" >/dev/null 2>&1; }
eval "$(sed -n '/^collect_project_deps_declared() {$/,/^}$/p' "$AGENT")"
SCAN_MAX_FILES=3000; SCAN_MAX_DEPTH=8

FIX=$(mktemp -d "tests/.fixtures.XXXXXX") || exit 1
trap 'rm -rf "$FIX"' EXIT
mkdir -p "$FIX/go" "$FIX/py" "$FIX/mvn"

cat > "$FIX/go/go.mod" <<'EOF'
module example.com/app
go 1.21
replace (
	old.example/x => new.example/x v1.0.0
)
require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/net v0.17.0 // indirect
)
require github.com/spf13/cobra v1.8.0
EOF

cat > "$FIX/py/requirements.txt" <<'EOF'
# 주석
django==4.2.1 \
    --hash=sha256:deadbeefcafe
requests===2.31.0
urllib3==2.0.7 ; python_version >= "3.8"
flask>=2.0
-e ./local
-r other.txt
celery[redis]==5.3.4
EOF

cat > "$FIX/mvn/pom.xml" <<'EOF'
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>managed.only</groupId>
        <artifactId>should-not-appear</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
      <exclusions>
        <exclusion>
          <groupId>excluded.group</groupId>
          <artifactId>excluded-art</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
    <dependency><groupId>one.line</groupId><artifactId>compact</artifactId><version>1.0.0</version></dependency>
    <dependency>
      <groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope>
    </dependency>
    <dependency>
      <groupId>pipe|inject</groupId><artifactId>bad</artifactId><version>1.0</version>
    </dependency>
  </dependencies>
</project>
EOF

PROJECT_SCAN_ROOTS="$FIX"
GOT=$(collect_project_deps_declared)
WANT='go|github.com/gin-gonic/gin|v1.9.1|weak
go|github.com/spf13/cobra|v1.8.0|weak
maven|one.line:compact|1.0.0|weak
maven|org.apache.logging.log4j:log4j-core|2.14.1|weak
pip|celery|5.3.4|weak
pip|django|4.2.1|weak
pip|requests|2.31.0|weak
pip|urllib3|2.0.7|weak'

if [ "$GOT" = "$WANT" ]; then
  echo "OK  project_deps_parser: 8건 일치"
  exit 0
fi
echo "FAIL project_deps_parser"
diff <(printf '%s\n' "$WANT") <(printf '%s\n' "$GOT")
exit 1
