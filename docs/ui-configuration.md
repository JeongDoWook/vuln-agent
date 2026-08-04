# 설정 레퍼런스 — 환경변수

> 문서 기준: 2026-08-04.

UI 뿐 아니라 **운영자가 코드 수정 없이 조정할 수 있는 환경변수 전체**를 모아 둔다.
값이 없거나 형식이 틀리면 코드의 기본값을 쓰고, 허용 범위를 벗어난 숫자는 범위 안으로 잘라 쓴다
(빈 문자열은 "미설정"과 같게 취급 — `vg_env()`).

**비밀값은 환경변수로 두지 않는다.** 비밀번호·토큰(DB 비번, ingest 토큰, admin 초기 비번)은
Docker Secrets(`secrets/*.txt`)로만 주입한다 → [`secrets/README.md`](../secrets/README.md).

## 적용 위치

web·scheduler 컨테이너의 환경변수는 `deploy/compose.yml` 맨 위의 **`x-app-env` 앵커(`&app-env`)**
한 곳에 모여 있고, 두 서비스가 `environment: *app-env` 로 그것을 참조한다.
그래서 값을 추가할 때는 **서비스의 `environment:` 가 아니라 앵커에 넣는다** — 서비스 쪽에 직접
쓰면 앵커와 두 곳으로 갈라져 어긋난다.

```yaml
# deploy/compose.yml
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
| `UI_DASHBOARD_ACTIONABLE_STATUSES` | `EXTERNAL,LAN,LISTENING,RUNNING,LOADED` | 이 5종 중 일부 (그 밖의 값은 무시) | KEV 긴급 목록에 포함할 실제 사용 상태 |
| `UI_DETAIL_PREVIEW_LIMIT` | `10` | 5~100 | 상세 화면 이력·프로세스 미리보기 건수 |
| `UI_TREND_LIMIT` | `50` | 10~500 | 상세 화면 추이 데이터 수 |
| `UI_FILTER_OPTION_LIMIT` | `300` | 50~2000 | 취약점 목록의 호스트 필터 선택지 최대 개수 (현재 선택된 호스트는 한도와 무관하게 항상 포함) |

## 보안·인증

읽는 곳: `server/src/auth.php`, `server/src/ui_config.php`(감사).

| 환경변수 | 기본값 | 허용 범위 | 용도 |
|---|---:|---|---|
| `LOGIN_MAX_FAILS` | `5` | 1 이상 정수 (검증 없음) | 연속 로그인 실패 이 횟수에 도달하면 계정 잠금 |
| `LOGIN_LOCK_MINUTES` | `15` | 정수(분) | 잠금 지속 시간 |
| `AUDIT_PAGE_VIEWS` | `1` | boolean (`1`/`true`/`on`/`yes`) | 인증된 HTML 페이지 열람 로그 기록 여부 |

`LOGIN_MAX_FAILS` 는 코드에서 범위 검사를 하지 않는다 — `0` 이하로 두면 **첫 실패에 바로 잠긴다.**

페이지 열람 로그에는 페이지명·메뉴 코드·검색 쿼리의 **키만** 저장하고 값은 저장하지 않는다.
공통 감사 모듈은 password/token/secret/csrf/authorization 계열 필드를 재귀적으로 마스킹한다.

## 수집·에이전트

읽는 곳: `server/src/agenttoken.php`.

| 환경변수 | 기본값 | 허용 범위 | 용도 |
|---|---:|---|---|
| `AGENT_NONCE_MAX_SKEW_SECONDS` | `600` (초) | 60 이상 (더 작게 줘도 60 으로 올림) | 에이전트 전송 재전송 방지 — 허용 시계 오차. 같은 값이 nonce 보관(만료) 기간이기도 하다 |

에이전트가 보낸 `X-Agent-Timestamp` 가 서버 시각과 이 값 이상 벌어지면 요청을 거부한다.
NTP 가 안 맞는 망에서 수집이 거부되면 이 값을 올린다(그만큼 재전송 방어 창도 넓어진다).

## 여기서 다루지 않는 것

- **비밀값** — `secrets/*.txt`(Docker Secrets). 환경변수가 아니다 → [`secrets/README.md`](../secrets/README.md).
- **DB 접속 정보**(`DB_HOST`/`DB_NAME`/`DB_USER`/`DB_PORT`) — compose 가 앵커에서 주입한다. 운영자가 직접 만질 값이 아니다.
- **컨테이너 인프라 값**(`WEB_PORT`·`DB_PORT`·`DB_DATA`·`MYSQL_*`·`PROD_DOMAIN`) — `deploy/.env.{dev,prod}.template` 참고.
