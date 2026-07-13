# vuln-agent — 개발 규칙 (항상 준수)

이 파일은 이 저장소에서 코드를 작성/수정하는 모든 작업에 **강제 적용**된다.
새 기능·리팩터·리뷰 전에 항상 아래 원칙에 비추어 판단한다.

## 먼저 읽을 것
이 파일은 **규칙**만 담는다. 이 프로젝트가 무엇이고 어떻게 얽혀 있는지는 여기 없다.
코드를 건드리기 전에 순서대로 읽는다 — 세션마다 자동으로 로드되는 건 이 파일뿐이라,
아래를 안 읽으면 구조를 처음부터 다시 추측하게 된다.

1. `CONTEXT.md` — 프로젝트 맥락·핵심 전략·현재 단계. **가장 먼저.**
2. `docs/architecture.md` — 구조·규칙의 최종 기준.
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
- 작업이 끝난 워크트리는 `./deploy/wt.sh rm <이름>` 으로 정리한다 — 스택을 계속 띄워두면
  포트·메모리를 먹는다.
- **`git pull` 뒤에는 스택을 다시 올린다(`dev up -d`).** dev 는 `../server` 를 라이브 마운트하므로
  pull 하는 순간 **코드는 컨테이너 안에서 즉시 바뀌지만 DB 스키마는 안 따라온다.** 남이 머지한
  마이그레이션이 있으면 새 코드가 없는 컬럼을 찾아 500 이 난다(`Unknown column …`).
  `up -d` 가 `migrate.sh` 를 불러 미적용분만 적용한다 — 컨테이너는 그대로 두므로 싸다.
- **dev DB 초기화는 `down -v` 로 안 된다.** 메인 dev 의 DB 는 named volume 이 아니라
  `.env.dev` 의 `DB_DATA=../data/mysql` **바인드마운트**라서 compose 가 `-v` 로 안 지운다.
  비우려면 `dev down` → `rm -rf data/mysql` → `dev up -d`.
  (워크트리 스택은 named volume 이라 이 문제가 없다 — `wt.sh rm` 이 볼륨째 지운다.)

## 리뷰 체크
바꾸기 전에 자문한다:
1. 이거 지금 진짜 필요한가? (YAGNI)
2. 더 단순한 방법은? (KISS)
3. 이미 있는 헬퍼로 되나? (DRY)
4. 한 책임만 지는가, 기존 코드 수정 없이 확장되나? (SOLID)

## 작업 파이프라인
기능·수정 작업은 **`wt/<이름>/` 워크트리에서** 진행하고 PR 로 병합한다.

```bash
./deploy/wt.sh add feat/무엇       # wt/무엇 생성(origin/main 기점) + secrets/.env 복사 + 빈 포트 할당
cd wt/무엇
./deploy/compose_runner.sh dev up -d   # 이 워크트리 전용 스택
./tests/smoke.sh http://localhost:<할당된포트>
# 구현 → 검증 게이트 → 커밋 → push → PR
./deploy/wt.sh rm 무엇             # 병합 후 정리(스택 down -v + 워크트리 제거)
```

- **메인 트리(`vuln-agent/`)에서 직접 작업하지 않는다.** 메인 트리는 `main` 에 두고 pull 용으로만 쓴다.
- 왜: 워크트리는 폴더마다 HEAD 를 따로 갖는다. 한 트리를 여러 세션이 공유하면 A 가 브랜치를 갈아탈 때
  B 의 커밋이 엉뚱한 브랜치에 얹히고 push 가 빈 push 가 된다(실제로 발생). git 은 같은 브랜치를
  두 워크트리에 체크아웃하는 걸 거부하므로 워크트리를 쓰면 이 사고가 구조적으로 불가능하다.
- 브랜치 이름은 `feat/`·`fix/`·`chore/` 접두사. 워크트리 폴더명은 브랜치의 마지막 조각.
- pre-push 훅은 **이 트리의 `deploy/.env.dev` 에서 `WEB_PORT` 를 읽어 자기 스택**을 친다.
  자기 스택이 안 떠 있으면 스모크를 **건너뛴다**(다른 스택으로 대신 검사하지 않는다 —
  그건 남의 코드를 검사해 초록불을 주는 셈이라 거짓이 된다).
  대상을 직접 지정하려면 `VG_SMOKE_BASE=http://localhost:<포트> git push`.
- 워크트리에서 `prod` 는 띄울 수 없다(compose_runner.sh 가 거부). 운영은 메인 트리에서만.

## 가드레일 (강제)
- **main 직접 commit/push 금지** — 항상 작업 브랜치 경유 후 PR 로 병합. (`.claude/hooks/block-main-push.sh` 가 차단)
- **검증 게이트**: `php -l` + `bash -n` + `tests/smoke.sh` 통과 전 커밋/PR 금지. 상태 보고 시 실행한 검증 명령·결과를 증거로 첨부.
  집행자는 `deploy/hooks/pre-push` — **저장소가 들고 있다**(`core.hooksPath=deploy/hooks`,
  `compose_runner.sh init` 이 설치). 예전엔 `.git/hooks/` 에 있어서 git 이 추적하지 않았고,
  **새로 clone 하면 게이트가 아예 없었다.** 걸려 있는지는 `compose_runner.sh doctor` 로 확인한다.
- `--no-verify` 등 hook 우회 명령 금지. `.env`/`secrets/*.txt` 커밋 금지.
- 관련 없는 파일 수정·요청 범위 초과 리팩터 금지. 읽지 않은 코드 기반 추정 금지.

## 응답 스타일
- 한글, 결론 먼저, 2~5문장, 이모지 남발 금지. 불명확하면 1줄로 추론을 밝히고 진행하되, 되돌리기 어려운 작업은 먼저 확인.
- 질문은 묶어서 한 번에. 상태 보고엔 증거(파일경로·커밋해시·검증결과) 동반.
