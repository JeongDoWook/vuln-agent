# db/migrations — 자동 적용 마이그레이션

> 문서 기준: 2026-08-20. 최신 마이그레이션은 파일명 사전순으로 판단한다.

`deploy/migrate.sh` 가 여기 있는 `*.sql` 을 **파일명 사전순으로**, **아직 안 든 것만**
적용하고 `tb_schema_migrations` 에 기록한다. `compose_runner.sh up` 과 `update.sh` 가
자동 호출하므로, 스키마를 바꾸려면 여기에 파일 하나만 추가하면 된다(수동 apply 불필요).

## 규칙

### 파일명은 타임스탬프로 — `YYYYMMDDHHMMSS_이름.sql`
```
20260713153000_kev_due_date.sql
```
`date +%Y%m%d%H%M%S` 로 뽑는다:
```bash
echo "$(date +%Y%m%d%H%M%S)_무엇.sql"
```

**왜 연번(`0001`, `0002`…)을 버렸나.** 연번은 "다음 번호가 뭔지" 를 모두가 합의해야 성립하는데,
브랜치를 여러 개 동시에 띄우면 각자 `origin/main` 을 보고 같은 번호를 집는다. 실제로 두 번 터졌다:

| 충돌 | 어쩌다 |
|---|---|
| `0003_cce_findings` · `0003_pkg_source_version` | 서로 다른 PR 이 동시에 `0003` 을 집음 |
| `0014_containers` · `0014_cve_detail_fields` | 같은 일이 그대로 재발 |

"push 직전에 번호를 다시 매긴다" 는 규칙도 소용없었다 — 둘이 동시에 다시 매기면 또 같은 번호가
나온다. **타임스탬프는 아무와도 상의하지 않아도 겹치지 않는다.**

**기존 `0001~0020`(중복 번호 포함 22개) 은 그대로 둔다.** 사전순으로 `0…` 이 `2…` 보다 앞서므로
옛 파일이 먼저, 새 파일이 나중에 도는 순서가 자연히 지켜진다.

### 집행자는 `deploy/hooks/pre-push` — 규칙은 코드가 막는다

| 검사 | 언제 도나 | 걸리면 |
|---|---|---|
| **파일명 타임스탬프** | 이 브랜치가 `db/migrations/` 에 **새로 만든** 파일만(`origin/main` 에 이미 있는 옛 연번 파일은 안 본다) | push 중단 + `git mv` 명령 안내 |
| **`migration-rehearsal`** (일회용 MySQL 에 initdb + 전 마이그레이션 적용) | 이 브랜치가 `origin/main` 대비 `db/migrations`·`db/*.sql` 을 **실제로 건드렸을 때만**(2026-08-20, #693). 안 건드렸으면 `db/ 변경 없음 — 스킵` | push 중단 |

`migration-rehearsal` 은 merge-base 를 못 구하거나 diff 가 실패하면(얕은 clone, `origin/main`
없음) 스킵하지 않고 **전체 rehearsal 로 폴백**한다 — 속도보다 정확성이 기본값이다.
검사 목록·required 여부는 `deploy/gates.tsv` 가 정본이다.

### 나머지
- **한 번 병합된 파일명은 바꾸지 않는다.** 러너는 `tb_schema_migrations` 를 **파일명**으로
  대조한다. 이름을 바꾸면 이미 적용된 볼륨이 그 파일을 "처음 보는 것"으로 알고 한 번 더 돈다
  (위 번호 충돌들을 재정렬로 고치지 않은 이유가 이것이다). 그래서 멱등성이 중요하다.
- **멱등하게** 작성한다(`CREATE TABLE IF NOT EXISTS`, `INSERT IGNORE`, `ADD COLUMN` 은
  이미 있으면 실패하므로 `information_schema` 로 존재 확인 후 실행 — 기존 파일들 참고).
  러너는 성공 시 1회만 기록하지만, 안전을 위해 재실행해도 깨지지 않게 쓴다.

## 최상위 `db/*.sql` 과의 차이
`db/01~19*.sql` 은 **빈 볼륨 initdb 전용**이라 이미 데이터가 든 볼륨에는 적용되지 않는다.
그래서 스키마를 바꿀 땐 두 곳 모두 손댄다 — 최상위 파일(새 볼륨용)과 여기(기존 볼륨용).

### 명명규칙 rename 과 initdb — 최상위 `db/*.sql` 은 **옛 이름 그대로 둔다**

`20260726115611_pk_naming_unification.sql` 이 테이블·PK 를 새 이름(`tb_host.host_id`)으로 바꾼다.
그런데 **최상위 `db/*.sql` 은 여전히 옛 이름(`tb_hosts.id`)으로 테이블을 만든다.** 일부러 그렇다.

빈 볼륨의 실행 순서가 `initdb(db/*.sql)` → `migrate.sh(db/migrations/*.sql 사전순)` 이기 때문이다.
initdb 를 새 이름으로 바꾸면, 그 다음에 도는 **옛 마이그레이션들이 옛 이름을 찾다 죽는다.** 실측:

```
# 'initdb 가 최종 형태' 상태를 만들고 옛 마이그레이션을 사전순 적용 → 두 번째 파일에서 즉사
실패: 0002_changelog_suppression.sql
  → ERROR 1824 (HY000) at line 6: Failed to open the referenced table 'tb_scans'
```

`migrate.sh` 는 `set -e` 라 여기서 배포가 통째로 멈춘다. 옛 마이그레이션은 **고칠 수 없다** —
러너가 파일명으로 이력을 추적하므로 과거 파일을 고쳐도 이미 적용된 DB 엔 반영되지 않고,
빈 볼륨에서만 달라져 두 환경 스키마가 갈라진다.

→ 그래서 rename 은 **사슬의 맨 끝(=마이그레이션)에서 딱 한 번만** 한다. 그러면 빈 볼륨도
(initdb 옛 이름 → rename 이전 마이그레이션 전부 → rename), 기존 볼륨도(rename 만) **같은 최종
스키마**에 도달한다. 실제로 두 경로의 `information_schema` COLUMNS·STATISTICS·KEY_COLUMN_USAGE
를 대조해 diff 가 비는 것을 확인했다.

**최상위 `db/*.sql` 을 새 이름으로 "정리"하지 마라.** 빈 볼륨이 뜨지 않게 된다.
