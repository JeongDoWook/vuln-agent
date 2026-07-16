# vuln-agent — 개발 규칙 (항상 준수)

이 파일은 이 저장소에서 코드를 작성/수정하는 모든 작업에 **강제 적용**된다.
새 기능·리팩터·리뷰 전에 항상 아래 원칙에 비추어 판단한다.

## 먼저 읽을 것
이 파일은 **규칙**만 담는다. 이 프로젝트가 무엇이고 어떻게 얽혀 있는지는 여기 없다.
코드를 건드리기 전에 순서대로 읽는다 — 세션마다 자동으로 로드되는 건 이 파일뿐이라,
아래를 안 읽으면 구조를 처음부터 다시 추측하게 된다.

1. `CONTEXT.md` — 프로젝트 맥락·핵심 전략·현재 단계. **가장 먼저.**
2. `docs/dev/architecture.md` — 구조·규칙의 최종 기준.
3. 화면 흐름이 궁금하면 `server/public/process.html`(웹으로 `/process.html`).

## 핵심 원칙

### YAGNI (You Aren't Gonna Need It)
- **지금 필요한 것만** 만든다. "나중에 쓸지도 몰라서" 만들지 않는다.
- 커넥터/피드는 5종(kev/osv/nvd/kisa/epss)이 실제 대상. 가상의 소스를 위한 추상화는 실제 요구가 생길 때 추가.
- 설정 옵션·파라미터·확장점은 **실제 사용처가 있을 때만** 추가한다.

### KISS (Keep It Simple, Stupid)
- 가장 단순한 해법을 먼저. 프레임워크/추상 레이어를 새로 들이기 전에 순수 PHP/SQL로 되는지 본다.
- 알려진 스키마(고정 피드)는 하드코딩 매핑이 더 단순하면 그렇게 둔다. 범용 매핑은 범용이 필요할 때만.
- 함수 하나는 한 가지 일. 조기 최적화 금지.

### DRY (Don't Repeat Yourself)
- 반복되는 로직은 헬퍼로 뽑는다: `vg_h()`, `vg_pdo()`, `vg_secret()`, `vg_header/footer()`, `vg_upsert_*()`, compose `x-app-*` 앵커.
- 같은 상수/URL/쿼리를 두 곳 이상에 쓰면 한 곳으로 모은다.
- **단, 성급한 추상화 금지**(WET < 잘못된 추상화). 2회까지는 허용, 3회째에 추출.

### SOLID
- **S**RP: 파일/클래스/함수는 한 책임. 커넥터는 "fetch+매핑"만, 실행/로그/스케줄은 runner 가.
- **O**CP: 새 피드 추가 시 기존 커넥터 수정 없이 `VgFeedConnector` 구현 + `vg_feed_make()` 한 줄 등록.
- **L**SP: 모든 커넥터는 `run(PDO,$conn): {fetched,upserted}` 계약을 동일하게 지킨다.
- **I**SP: 인터페이스는 작게(`VgFeedConnector` 는 run() 하나). 안 쓰는 메서드 강요 금지.
- **D**IP: 상위 로직은 구체 커넥터가 아니라 인터페이스에 의존(`vg_feed_run` 은 `vg_feed_make` 로 추상화).

## 프로젝트 규약
- 비밀값은 코드/커밋 금지 → Docker Secrets(`secrets/*.txt`, gitignore).
- 커밋 메시지·주석·UI 는 한글. 각 단계는 "돌아가는 상태"로 커밋.
- 스키마 변경은 `db/migrations/` 에 파일 하나만 추가한다 — `deploy/migrate.sh` 가
  미적용분만 자동 적용(`compose_runner.sh up`·`update.sh` 가 호출). 수동 apply 금지, 멱등하게 작성.
  최상위 `db/*.sql` 은 빈 볼륨 initdb 전용이라 기존 볼륨엔 안 들어간다.
  워크트리에선 프로젝트명이 `vulnagent-dev-<워크트리이름>` 이다.
- **마이그레이션 파일명은 타임스탬프**: `$(date +%Y%m%d%H%M%S)_이름.sql`.
  연번(`0001`…)은 쓰지 않는다 — 동시에 작업하는 브랜치들이 같은 다음 번호를 집어 충돌한다
  (실제로 `0003` 과 `0014` 가 각각 두 개씩 생겼다). 타임스탬프는 조율 없이도 안 겹친다.
  기존 연번 파일은 그대로 둔다(사전순이라 옛 것이 먼저 돈다).
  **집행자는 `deploy/hooks/pre-push`** — 이 브랜치가 `db/migrations/` 에 **새로 만든** 파일의 이름이
  14자리 타임스탬프가 아니면 push 를 막는다(origin/main 에 이미 있는 파일은 안 본다).
- Windows git-bash 에서 컨테이너에 절대경로 전달 시 `MSYS_NO_PATHCONV=1` 접두.
- **파일은 책임대로 놓는다** — 새 파일을 만들기 전에 어디 속하는지 먼저 정한다.
  - `server/public/` — HTTP 로 노출되는 페이지·엔드포인트(`findings.php`, `ingest.php` …). 여기 둔 건 곧 URL 이다.
  - `server/src/` — 공용 라이브러리(`db.php`, `matcher.php`, `vercmp.php` …). 직접 URL 로 열리지 않는다.
  - `server/bin/` — CLI 로만 도는 것(`sync.php`, `scheduler.php`, `backfill_*.php`). 웹에서 부르지 않는다.
  - `db/migrations/` — 스키마 변경. `tests/` — 검증. `agent/` — 대상 서버에 설치되는 에이전트.
- **색·레이아웃은 `server/public/assets/app.css` 가 소유한다.** PHP 안에 `style="…"` 을 쓰지 않는다
  (폭 계산 `width:N%` 만 예외 — 게이지·미터). 클래스를 쓸 거면 app.css 에 정의가 **있는지 확인**한다 —
  예전에 `changes.php` 가 `.err` 로 오류를 감쌌는데 app.css 에 `.err` 가 없어서, 오류가 스타일 없는
  맨텍스트로 뜨는데도 아무도 못 알아챘다. `tests/ui_lint.sh` 가 이 둘을 기계로 잡는다.
- 변경 후 `./tests/smoke.sh <BASE>` 로 회귀 확인. PHP 는 `php -l`, 쉘은 `bash -n`.
  smoke 는 curl 만 치는 게 아니라 앞단에서 **`tests/ui_lint.sh`(죽은 CSS 클래스·인라인 style·잘리는 목록)와
  `tests/vercmp_test.php`(버전 비교 — 매처 오탐 1순위)** 를 먼저 돌린다. 이 둘은 서버 없이도 도는 정적/단위
  검사라, `server/src/vercmp.php` 나 화면을 건드렸다면 여기서 걸린다.
  vercmp 만 따로 돌리려면(호스트 php 는 7.2 라 8.x 문법을 오탐한다 — 컨테이너로 돌린다):
  `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/w" -w /w php:8.3-cli php tests/vercmp_test.php`
- **dev 에 `--build` 를 붙이지 않는다.** dev 는 `../server` 를 바인드 마운트하므로 PHP 변경은
  즉시 반영된다. 이미지는 모든 워크트리가 `vulnagent-app:dev` 태그 하나를 공유한다.
  `--build` 는 **`server/Dockerfile` 을 바꾼 브랜치에서만** 쓴다.
  (예전엔 워크트리마다 이미지를 따로 구워 504MB 태그가 47개까지 쌓였다.)
- **dev 는 "web+scheduler 는 워크트리별 독립, DB 는 공용 하나" 다.** 메인 트리에서 `dev up -d` 를
  하면 지금까지처럼 db+web+scheduler 전부가 프로젝트 `vulnagent-dev` 로 뜬다. 워크트리에서
  `dev up -d` 를 하면 그 워크트리 전용 프로젝트(`vulnagent-dev-<워크트리이름>`)로 **web+scheduler만**
  새로 뜨고 db 는 건드리지 않는다 — 메인 트리가 띄운 공용 db 컨테이너(`vulnagent-db-dev`)를 외부
  docker 네트워크(`vulnagent-dev-net`, `compose_runner.sh init`/dev 실행 시 없으면 자동 생성)로
  이름을 그대로 찾아간다. 컨테이너명에는 워크트리 접미사가 붙어(`vulnagent-web-dev-<이름>` 등)
  트리마다 고유하다 — 그래서 메인 트리·워크트리끼리, 워크트리끼리 서로 스택을 빼앗지 않는다
  (예전엔 프로젝트명이 `vulnagent-dev` 로 고정이라 워크트리에서 `dev up -d` 하면 스택이 그
  트리로 "옮겨가며" 다른 세션 작업을 계속 끊었다 — 컨테이너명이 애초에 안 겹치므로 이 문제가
  구조적으로 사라졌다). 전제: 워크트리 stack 이 뜨려면 **공용 db(메인 트리)가 먼저 떠 있어야 한다.**
  파일 구성: `deploy/compose.dev.yml`(web+scheduler, 모든 트리 공통) · `compose.dev-db.yml`(db,
  메인 트리 전용) · `compose.dev-net.yml`(공유 네트워크 선언, dev 전체 공통).
- **포트는 트리 속성, DB 는 여전히 스택 속성이다.** `WEB_PORT` 는 각 트리 자신의 `deploy/.env.dev`
  에서 읽는다 — 메인 트리는 8000(`init` 이 만듦), 워크트리는 `wt.sh add` 가 안 쓰는 포트를 골라
  그 워크트리 전용 `deploy/.env.dev`(gitignore, WEB_PORT 한 줄만)에 박아 둔다. 반면 `MYSQL_*`·
  `DB_DATA`·`DB_PORT` 등은 여전히 **메인 트리의 `deploy/.env.dev`** 하나만 쓴다(DB 는 공용이므로).
  `DB_DATA=../data/mysql` 은 상대경로라 compose 파일이 있는 트리 기준으로 풀리는데, db 는 항상
  메인 트리 프로젝트로만 뜨므로 이 값이 워크트리 경로로 새는 일은 없다(옛날엔 워크트리에서
  db 까지 띄우려다 `wt/<이름>/data/mysql` 을 파서 DB 가 통째로 바뀐 적이 있다 — 지금은 워크트리
  compose 대상에 db 서비스 자체가 없어서 이 사고가 재현 불가능하다).
- **그래도 스택은 서버 코드를 건드릴 때만 올린다.** 워크트리를 팠다고 반사적으로 `up -d` 하지 않는다.
  - `agent/**`·`docs/**`·`*.md` 만 바꿨다 → **스택 불필요.** `bash -n` + 실제 컨테이너 e2e 로 검증한다
    (스택을 띄워도 검사되는 게 없다).
  - `server/**`·`db/**`·`tests/**` 를 바꿨다 → 스모크를 돌린다. 이 트리 전용 컨테이너가 안 떠 있으면
    **워크트리 안에서는 에이전트가 자기 트리 스택을 스스로 올려도 된다**(`dev up -d`). 반면
    **메인 트리 스택과 공용 DB 는 여전히 사람만 건드린다**(`.claude/hooks/block-dev-stack.sh` 가
    메인 트리 대상 `dev up|down` 만 코드로 막는다).
    왜 좁혔나: 전부 막았더니 워커가 스모크 앞에서 멈춰 사람을 기다렸고, 워커 N 개면 개입도 N 번이라
    병렬 오케스트레이션이 사람 손에 병목이 됐다. 왜 안전한가: 워크트리 스택엔 db 가 아예 없고,
    프로젝트·컨테이너명이 트리마다 고유해 남을 못 건드리며, `up -d` 는 멱등이다(이미 떠 있으면 무동작).
- **스모크는 "이 트리 전용 컨테이너가 떠 있을 때"만 돈다.** `tests/smoke.sh` 와 pre-push 훅은
  컨테이너명(`vulnagent-web-dev-<워크트리>`, 메인 트리는 접미사 없음)이 이 트리에만 쓰이므로
  그 이름이 떠 있는지만 확인한다 — 안 떠 있으면 스모크는 **중단**(exit 2), 훅은 **건너뛴다**.
  중단됐을 때 워크트리 안이라면 에이전트가 자기 트리 스택을 올리고(`dev up -d`) 다시 돌리면 된다.
  일부러 다른 대상을 칠 때만 `VG_SMOKE_ANY=1`.
- **DB 가 공용이라는 뜻**: 어느 브랜치(어느 워크트리)에서 걸어도 `migrate.sh` 가 같은 DB
  컨테이너(`vulnagent-db-dev`, 트리와 무관하게 고정)에 미적용분만 얹는다 — 락도 그 컨테이너명
  기준이라 여러 워크트리가 동시에 `dev up -d` 해도 마이그레이션끼리 안전하게 직렬화된다.
  옛 브랜치 코드가 새 컬럼을 모를 수는 있어도 깨지진 않는다(컬럼이 남아 있는 건 무해).
- **dev DB 초기화는 `down -v` 로 안 된다.** 바인드마운트라서 compose 가 `-v` 로 안 지운다.
  비우려면 메인 트리에서 `dev down` → `rm -rf data/mysql` → `dev up -d`. (메인 트리의
  `data/mysql` 하나뿐이다 — 비우면 그 순간 모든 워크트리의 web/scheduler 도 빈 DB 를 본다.)
- **`git pull` 뒤에는 스택을 다시 올린다(`dev up -d`).** dev 는 `../server` 를 라이브 마운트하므로
  pull 하는 순간 **코드는 컨테이너 안에서 즉시 바뀌지만 DB 스키마는 안 따라온다.** 남이 머지한
  마이그레이션이 있으면 새 코드가 없는 컬럼을 찾아 500 이 난다(`Unknown column …`).
  `up -d` 가 `migrate.sh` 를 불러 미적용분만 적용한다 — 컨테이너는 그대로 두므로 싸다.

## 리뷰 체크
바꾸기 전에 자문한다:
1. 이거 지금 진짜 필요한가? (YAGNI)
2. 더 단순한 방법은? (KISS)
3. 이미 있는 헬퍼로 되나? (DRY)
4. 한 책임만 지는가, 기존 코드 수정 없이 확장되나? (SOLID)

## 작업 파이프라인
기능·수정 작업은 **`wt/<이름>/` 워크트리에서** 진행하고 PR 로 병합한다.

```bash
./deploy/wt.sh add feat/무엇       # wt/무엇 생성(origin/main 기점) + secrets 복사 + 전용 WEB_PORT 할당
cd wt/무엇

# server/·db/·tests/ 를 건드렸다면 스모크로 확인한다.
#   agent/·docs/·*.md 만 고친다면 이 줄을 건너뛴다(스택을 봐도 검사되는 게 없다).
# 이 워크트리 전용 컨테이너(vulnagent-web-dev-무엇)가 안 떠 있으면 스모크가 중단한다(exit 2).
#   그때는 이 트리 스택을 올린다 — 워크트리 안에선 에이전트가 스스로 쳐도 된다(메인 트리는 사람만).
./deploy/compose_runner.sh dev up -d   # 이 워크트리만의 web+scheduler (db 는 안 뜬다, 멱등)
./tests/smoke.sh http://localhost:<wt.sh add 가 알려준 포트>

# 구현 → 검증 게이트 → 커밋 → push → PR
./deploy/wt.sh rm 무엇             # 이 트리 스택 회수(떠 있으면) + 워크트리 제거 — 공용 DB 는 안 건드림
```

- **사용자가 "머지했어"·"다음 작업 진행해"처럼 병합 완료·다음 작업 신호를 주면, 새 작업을
  시작하기 전에 `./deploy/wt.sh sweep` 을 먼저 돌려 병합된 워크트리·브랜치를 한 번에 정리한다.**
  매번 `wt.sh rm <이름>` 을 손으로 치지 않아도, origin/main 에 병합된 것만 골라 지운다
  (미병합·미커밋 변경이 있는 워크트리는 안전하게 남긴다). 안 쌓이게 습관화한다.
- **메인 트리(`vuln-agent/`)에서 직접 작업하지 않는다.** 메인 트리는 `main` 에 두고 pull 용으로만 쓴다.
- 왜: 워크트리는 폴더마다 HEAD 를 따로 갖는다. 한 트리를 여러 세션이 공유하면 A 가 브랜치를 갈아탈 때
  B 의 커밋이 엉뚱한 브랜치에 얹히고 push 가 빈 push 가 된다(실제로 발생). git 은 같은 브랜치를
  두 워크트리에 체크아웃하는 걸 거부하므로 워크트리를 쓰면 이 사고가 구조적으로 불가능하다.
- 브랜치 이름은 `feat/`·`fix/`·`chore/` 접두사. 워크트리 폴더명은 브랜치의 마지막 조각.
- pre-push 훅은 **이 트리 전용 컨테이너가 떠 있을 때만** 스모크한다(컨테이너명이 워크트리마다
  고유하므로 존재 여부만 보면 된다). 안 떠 있으면 **건너뛴다** — 검사할 대상이 없으니 당연하다.
  `tests/smoke.sh` 도 같은 확인을 하고, 안 떠 있으면 **중단**한다(exit 2) — 워크트리 안이라면
  에이전트가 그때 자기 트리 스택을 올려도 된다.
  대상을 직접 지정하려면 `VG_SMOKE_BASE=http://localhost:PORT git push`(훅의 확인을 건너뛴다).
- 워크트리에서 `prod` 는 띄울 수 없다(compose_runner.sh 가 거부). 운영은 메인 트리에서만.

## 병렬 워커 오케스트레이터 — 메인은 조사·계획, 구현은 워커 (deploy/orchestrator)
이 repo 에서 **구현 작업**(기능·수정·리팩터)을 요청받으면, 메인 세션(이 창)은 **조사·계획만**
하고 실제 코드 수정은 직접 하지 않는다. `deploy/orchestrator/` 로 **워커 세션(새 창/탭)** 을 띄워
구현을 맡기고, 결과를 취합해 이 창에 보고한다. 워커 = 워크트리 = 브랜치 = PR.
**절차·파라미터·과거 사고 기록은 전부 `deploy/orchestrator/README.md`** — 매 세션 자동 로드되는
이 파일엔 원칙만 남긴다(무거워지면 세션이 처음부터 큰 컨텍스트를 안고 시작한다).

- 하위작업 1개 → `spawn-worker.ps1` 로 바로 스폰. **2개 이상**이면 인라인 조립 대신 스킬
  `orchestrator-plan`(지시문을 `.omc/tasks/<슬러그>.md` 로 작성만) → `orchestrator-spawn`
  (그 파일들을 일괄 스폰)을 쓴다.
- 워커가 완료(PR 생성)를 보고하면, 병합 확인 전에 스킬 `orchestrator-review` 로 자동 리뷰한다.
- 메인이 직접 해도 되는 것(위임 안 함): 조사·설명·질문답변, 한두 줄짜리 사소한 수정뿐.
  그 외 구현은 항상 워커에 위임한다. PR 병합 여부는 항상 사용자 확인 후 메인이 결정한다.

## 가드레일 (강제)
- **main 직접 commit/push 금지** — 항상 작업 브랜치 경유 후 PR 로 병합. (`.claude/hooks/block-main-push.sh` 가 차단)
  훅은 명령이 **실제로 향하는** 저장소를 보고 판단한다(cwd + 명령 안의 `cd`/`git -C`) — 다른 저장소면 통과.
- **검증 게이트**: `php -l` + `bash -n` + 마이그레이션 파일명 + `tests/smoke.sh` 통과 전 커밋/PR 금지. 상태 보고 시 실행한 검증 명령·결과를 증거로 첨부.
  집행자는 `deploy/hooks/pre-push` — **저장소가 들고 있다**(`core.hooksPath=deploy/hooks`,
  `compose_runner.sh init` 이 설치). 예전엔 `.git/hooks/` 에 있어서 git 이 추적하지 않았고,
  **새로 clone 하면 게이트가 아예 없었다.** 걸려 있는지는 `compose_runner.sh doctor` 로 확인한다.
- `--no-verify` 등 hook 우회 명령 금지. `.env`/`secrets/*.txt` 커밋 금지.
- **워크트리 안에서는 자기 트리 스택을 스스로 올려도 된다. 메인 트리 스택과 공용 DB 는 여전히
  사람만 건드린다.** 즉 `wt/<이름>/` 에서의 `./deploy/compose_runner.sh dev up -d`/`dev down` 은
  에이전트가 쳐도 되고, 메인 트리에서의 같은 명령은 금지다.
  왜 좁혔나: 전부 막았더니 `server/**` 를 고친 워커가 스모크 앞에서 멈춰 사람을 기다렸고, 워커 N 개면
  개입도 N 번이라 병렬 오케스트레이션이 사람 손에 병목이 됐다.
  왜 안전한가: 워크트리 컴포즈 대상엔 **db 서비스가 아예 없고**, 프로젝트명(`vulnagent-dev-<wt>`)·
  컨테이너명(`vulnagent-web-dev-<wt>`)이 트리마다 고유해 남의 트리를 건드릴 수 없으며, `up -d` 는
  멱등이라 이미 떠 있으면 재생성도 없다. 쌓이는 컨테이너는 `wt.sh rm`/`sweep` 이 워크트리를 지우기
  전에 그 트리 스택을 내려 회수한다.
  **문서뿐 아니라 `.claude/hooks/block-dev-stack.sh` 가 코드로도 막는다**(과거엔 문서만 있어서 여러
  세션이 무시하고 직접 쳤다) — 이제 그 훅이 막는 건 **메인 트리 대상 `dev up|down`** 이다.
- 관련 없는 파일 수정·요청 범위 초과 리팩터 금지. 읽지 않은 코드 기반 추정 금지.
- **여러 줄 명령에 PowerShell 백틱(`` ` ``) 줄바꿈을 쓰지 않는다.** 이 환경은 Bash 도구가
  git-bash(POSIX sh) 이고 PowerShell 은 별도 도구라, 한쪽 문법(백틱 줄바꿈은 PowerShell 전용)을
  다른 셸에 섞으면 인자가 깨진다 — 실제로 오케스트레이터 워커가 `php -l` 여러 파일을 확인하며
  백틱 연속 문법을 git-bash 로 실행해 `-l\`` 같은 깨진 인자가 되고 세션이 멈춘 적이 있다.
  여러 파일 검사·긴 명령은 한 줄로 쓰거나(`php -l a.php b.php c.php`), 셸에 맞는 연속 문법만
  쓴다(git-bash: 줄끝 `\`, PowerShell: 줄끝 `` ` `` — 단 뒤에 공백이 있으면 안 먹힌다). 도구
  호출 전에 지금 실행되는 게 Bash(git-bash)인지 PowerShell 인지부터 확인한다.

## 응답 스타일
- 한글, 결론 먼저, 2~5문장, 이모지 남발 금지. 불명확하면 1줄로 추론을 밝히고 진행하되, 되돌리기 어려운 작업은 먼저 확인.
- 질문은 묶어서 한 번에. 상태 보고엔 증거(파일경로·커밋해시·검증결과) 동반.
