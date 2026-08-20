# 설정 레퍼런스 — 환경변수 · 운영 설정

> 문서 기준: 2026-08-20.

**운영자가 코드 수정 없이 조정할 수 있는 값 전체**를 모아 둔다. 조정 경로는 둘이고 성격이 다르다.

| | 환경변수 | 운영 설정(`tb_setting`) |
|---|---|---|
| 바꾸는 곳 | `deploy/compose.yml` 앵커 · `deploy/.env.{dev,prod}` | 웹 **관리 → 설정**(`/settings.php`, admin 전용) |
| 반영 시점 | 컨테이너 재기동 | 즉시 |
| 성격 | 배포 환경 값(화면 크기·잠금 정책 등) | 조직마다 다른 **판정 기준**(SLA·컷라인) |

환경변수는 값이 없거나 형식이 틀리면 코드의 기본값을 쓰고, 허용 범위를 벗어난 숫자는 범위 안으로
잘라 쓴다(빈 문자열은 "미설정"과 같게 취급 — `vg_env()`).

**비밀값은 환경변수로 두지 않는다.** 배포 비밀값(DB 비번, admin 초기 비번)은
Docker Secrets(`secrets/*.txt`)로만 주입한다 → [`secrets/README.md`](../secrets/README.md).
에이전트 수집 토큰은 시크릿 파일이 아니라 **웹에서 발급**하고 DB 엔 해시만 남는다
(Export API 전용 토큰은 2026-08-13 폐지 — `export.php`·`sbom.php` 는 웹 로그인 세션으로 인증한다).

## 적용 위치

web·scheduler 컨테이너의 환경변수는 `deploy/compose.yml` 맨 위의 **`x-app-env` 앵커(`&app-env`)**
한 곳에 모여 있고, 두 서비스가 `environment: *app-env` 로 그것을 참조한다.
그래서 값을 추가할 때는 **서비스의 `environment:` 가 아니라 앵커에 넣는다** — 서비스 쪽에 직접
쓰면 앵커와 두 곳으로 갈라져 어긋난다.

```yaml
# deploy/compose.yml — 값을 새로 넣을 때의 두 가지 꼴(아래 UI_* 줄은 예시다.
#   지금 앵커에 실제로 있는 앱 설정값은 LOGIN_MAX_FAILS·LOGIN_LOCK_MINUTES 뿐이고,
#   나머지 UI_* 는 코드 기본값으로 돌고 있어 필요할 때만 앵커에 추가한다.)
x-app-env: &app-env
  DB_HOST: ${DB_HOST:-db}
  ...
  UI_PER_PAGE_DEFAULT: "10"                      # 고정값이면 앵커에 직접
  LOGIN_MAX_FAILS: ${LOGIN_MAX_FAILS:-5}         # 환경별로 다르면 .env 에서 받는다
```

**dev/prod 에서 값이 달라지거나 운영자가 자주 만지는 값**은 앵커에 `${VAR:-기본값}` 으로 두고
실제 값은 `deploy/.env.dev` / `deploy/.env.prod` 에 적는다. `LOGIN_MAX_FAILS` 가 이미 이 방식이라,
이 변수는 앵커를 건드릴 필요 없이 `.env` 한 줄만 추가하면 된다(템플릿에 주석으로 준비돼 있다).

```ini
# deploy/.env.dev  (또는 .env.prod — 둘 다 gitignore, .template 만 커밋)
LOGIN_MAX_FAILS=5
LOGIN_LOCK_MINUTES=15
```

## UI 목록·표시

읽는 곳: `server/src/ui_config.php`.

| 환경변수 | 기본값 | 허용 범위 | 용도 |
|---|---:|---|---|
| `UI_PER_PAGE_OPTIONS` | `10,20,40,60,100` | 각 항목 5~200 (범위 밖 항목은 버림) | 목록의 페이지 크기 선택지 |
| `UI_PER_PAGE_DEFAULT` | `10` | 선택지 중 하나 (아니면 선택지의 최솟값) | 기본 페이지 크기 |
| `UI_DASHBOARD_URGENT_LIMIT` | `6` | 3~30 | 대시보드 대응 우선순위 표시 건수 |
| `UI_DETAIL_PREVIEW_LIMIT` | `10` | 5~100 | 상세 화면 이력·프로세스 미리보기 건수 |
| `UI_TREND_LIMIT` | `50` | 10~500 | 상세 화면 추이 데이터 수 |
| `UI_FILTER_OPTION_LIMIT` | `300` | 50~2000 | 취약점 목록의 호스트 필터 선택지 최대 개수 (현재 선택된 호스트는 한도와 무관하게 항상 포함) |
| `UI_ADVISORY_ASSET_LIMIT` | `200` | 20~2000 | 보안 공지 화면 "영향 자산" 모달의 상세 행 상한 (초과분은 "외 N건") |

> **제거된 설정**: `UI_DETAIL_PER_PAGE_DEFAULT`(기본 `40`) — 자산 상세 목록도 이제
> `UI_PER_PAGE_DEFAULT` 를 그대로 쓴다(PR #681). 기존 `.env` 에 남아 있어도 무시된다.

## 보안·인증

읽는 곳: `server/src/auth.php`, `server/src/ui_config.php`(감사).

| 환경변수 | 기본값 | 허용 범위 | 용도 |
|---|---:|---|---|
| `LOGIN_MAX_FAILS` | `5` | 1 이상 정수 (검증 없음) | 연속 로그인 실패 이 횟수에 도달하면 계정 잠금 |
| `LOGIN_LOCK_MINUTES` | `15` | 정수(분) | 잠금 지속 시간 |
| `AUDIT_PAGE_VIEWS` | `1` | boolean (`1`/`true`/`on`/`yes`) | 인증된 HTML 페이지 열람 로그 기록 여부 |

`LOGIN_MAX_FAILS` 는 코드에서 범위 검사를 하지 않는다 — `0` 이하로 두면 **첫 실패에 바로 잠긴다.**

**세션 만료와 토큰 유효기간은 환경변수가 아니다.** 세션 만료는 조직 규정이라 DB 설정(아래
[운영 설정](#운영-설정-db--tb_setting))으로 뺐고, 나머지는 코드 상수다.

| 값 | 기본값 | 위치 | 비고 |
|---|---:|---|---|
| 세션 유휴 만료 | `1800`초(30분) | 설정 `session.idle_minutes` · 폴백 상수 `VG_SESSION_IDLE_SECONDS`(`server/src/auth.php`) | 마지막 활동 기준 |
| 세션 절대 만료 | `43200`초(12시간) | 설정 `session.absolute_minutes` · 폴백 상수 `VG_SESSION_ABSOLUTE_SECONDS`(같은 파일) | 유휴와 무관하게 로그인 시점 기준 |
| 에이전트 키 유효기간 선택지 | 무기한 / 30 / 90 / 365일 | `VG_TOKEN_EXPIRY_OPTIONS`(`server/src/tokenexpiry.php`) | 호스트별 수집 키. `0`=무기한 |
| 만료 임박 표시 | `7`일 | `VG_TOKEN_EXPIRY_SOON_DAYS`(같은 파일) | 목록 뱃지 표시용. 인증 판정과 무관해 설정으로 빼지 않았다 |

세션이 만료되면 `session_expire` 감사로그를 남기고 `tb_user.session_token` 을 지운다. 만료된 에이전트
키는 인증 실패로 처리되고 `agent_token_expired` 로 기록된다(자동 갱신 없음).

페이지 열람 로그에는 페이지명·메뉴 코드·검색 쿼리의 **키만** 저장하고 값은 저장하지 않는다.
공통 감사 모듈은 password/token/secret/csrf/authorization 계열 필드를 재귀적으로 마스킹한다.

## 수집·에이전트

읽는 곳: `server/src/agenttoken.php`.

| 환경변수 | 기본값 | 허용 범위 | 용도 |
|---|---:|---|---|
| `AGENT_NONCE_MAX_SKEW_SECONDS` | `600` (초) | 60 이상 (더 작게 줘도 60 으로 올림) | 에이전트 전송 재전송 방지 — 허용 시계 오차. 같은 값이 nonce 보관(만료) 기간이기도 하다 |

에이전트가 보낸 `X-Agent-Timestamp` 가 서버 시각과 이 값 이상 벌어지면 요청을 거부한다.
NTP 가 안 맞는 망에서 수집이 거부되면 이 값을 올린다(그만큼 재전송 방어 창도 넓어진다).

## 운영 설정 (DB · `tb_setting`)

읽는 곳: `server/src/setting.php`(`vg_setting_int()`), 정의 SSOT 는 `vg_setting_defs()`.
바꾸는 곳: 웹 **관리 → 설정**(`/settings.php`, admin 전용).

SLA 기준일은 업계 관행값이 아니라 **조직 내부 규정**이라 환경변수가 아닌 DB 설정으로 뺐다 —
코드를 고쳐야 바꿀 수 있으면 제품으로 쓸 수 없다(하드코딩 금지 원칙).

| 설정 키 | 기본값 | 허용 범위 | 용도 |
|---|---:|---|---|
| `compliance.sla_kev_days` | `15` | 1~365 | KEV(실제 악용 확인) 등재 취약점 조치 기한(일) |
| `compliance.sla_crit_days` | `30` | 1~365 | CRITICAL 취약점 조치 기한(일) |
| `compliance.sla_high_days` | `60` | 1~365 | HIGH 취약점 조치 기한(일) |
| `compliance.partial_max` | `5` | 1~1000 | 부분준수 상한(건). 위반 1~이 값이면 부분준수, 초과면 미준수 |
| `compliance.history_lookback_margin_days` | `14` | 0~365 | 최초 발견 시각 역산 구간의 **여유일**. 실제 구간 = 가장 긴 조치 기한 + 이 값 |
| `session.idle_minutes` | `30`분 | 5~720 | 마지막 활동 이후 자동 로그아웃까지의 시간(ISMS-P 2.6.3) |
| `session.absolute_minutes` | `720`분(12시간) | 30~1440 | 로그인 시점부터의 최대 세션 수명(유휴와 무관) |
| `account.stale_login_days` | `90`일 | 7~1095 | 미사용 계정 판정 기준일(ISMS-P 2.5.1·2.5.6) |

- **기본값은 폴백 상수다.** 설정 행이 없거나 테이블을 못 읽으면 `server/src/compliance.php` 의
  상수(`VG_COMPLIANCE_SLA_*` 등)를 그대로 쓴다 — 마이그레이션이 아직 안 든 DB 에서도 동작이 같아야
  하기 때문. 그래서 기본값을 `vg_setting_defs()` 에 다시 적지 않는다(같은 숫자를 두 곳에 두면 갈라진다).
- 범위를 벗어난 값은 **읽을 때도** 범위로 잘라 쓴다(DB 를 직접 고친 값이 판정을 망가뜨리지 않게).
- 역산 구간을 절대 일수가 아니라 "여유일"로 둔 이유: 조치 기한만 늘리고 구간이 그대로면 경과일이
  구간 길이에서 잘려 **위반이 아예 검출되지 않는다.**
- 화면(`compliance.php`)과 스케줄러의 스냅샷 적재가 같은 `vg_compliance_policy()` 를 쓴다 —
  한쪽만 상수를 쓰면 화면과 증적의 기준이 갈라진다.

- **세션 만료는 보안 통제라 min 이 하한선이다.** 5분 미만(사실상 로그인 불가)이나 무한 세션을
  저장할 수 없고, DB 를 직접 고쳐도 읽을 때 잘린다. 값이 없으면 더 짧은 쪽(기존 상수)으로 간다.
- `session.gc_maxlifetime` 은 설정을 읽지 않고 `session.absolute_minutes` 의 **상한**(1440분)으로
  고정한다 — 매 요청 include 시점에 DB 를 열지 않으면서도, 어떤 설정값에서든 PHP GC 가 우리
  만료 판정보다 먼저 세션을 지우지 않는다.

일부러 설정으로 빼지 않은 임계값도 있다 — 조직이 바꿀 값이 아니라고 봤다(YAGNI).

| 값 | 상수 | 왜 코드에 두나 |
|---|---|---|
| 시스템 계정 UID 상한 `999` | `VG_ACCOUNT_SYSTEM_UID_MAX`(`server/src/account_inventory.php`) | 리눅스 관례(`login.defs` 의 `SYS_UID_MAX`). 배포판이 정하는 값이지 조직 규정이 아니다 |
| nobody UID 하한 `65534` | `VG_ACCOUNT_NOBODY_UID_MIN`(같은 파일) | 위와 같음 |
| 만료 임박 표시 `7`일 | `VG_TOKEN_EXPIRY_SOON_DAYS`(`server/src/tokenexpiry.php`) | 목록 뱃지 색만 바꾸는 표시 기준. 인증 판정·차단과 무관하다 |

## 여기서 다루지 않는 것

- **비밀값** — `secrets/*.txt`(Docker Secrets). 환경변수가 아니다 → [`secrets/README.md`](../secrets/README.md).
- **DB 접속 정보**(`DB_HOST`/`DB_NAME`/`DB_USER`/`DB_PORT`) — compose 가 앵커에서 주입한다. 운영자가 직접 만질 값이 아니다.
- **컨테이너 인프라 값**(`WEB_PORT`·`DB_PORT`·`DB_DATA`·`MYSQL_*`·`PROD_DOMAIN`) — `deploy/.env.{dev,prod}.template` 참고.
- **에이전트 쪽 환경변수** — 이 표의 값은 전부 web·scheduler 컨테이너가 읽는 것이다. 수집 대상
  호스트에서 에이전트 자신이 읽는 값(속도 티어, `CPU_QUOTA`·`PACKAGING_TIMEOUT`·`MEM_MAX`,
  `/proc` 순회 상한 `PROC_SCAN_TIMEOUT`)은 여기가 아니라 [`agent/README.md`](../agent/README.md)
  가 정본이다. 조정 경로도 다르다 — 컨테이너 앵커가 아니라 그 호스트의 에이전트 설정이다.
