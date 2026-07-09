# vuln-agent — 개발 규칙 (항상 준수)

이 파일은 이 저장소에서 코드를 작성/수정하는 모든 작업에 **강제 적용**된다.
새 기능·리팩터·리뷰 전에 항상 아래 원칙에 비추어 판단한다.

## 핵심 원칙

### YAGNI (You Aren't Gonna Need It)
- **지금 필요한 것만** 만든다. "나중에 쓸지도 몰라서" 만들지 않는다.
- 커넥터/피드는 4종(kev/osv/nvd/kisa)이 실제 대상. 가상의 소스를 위한 추상화는 실제 요구가 생길 때 추가.
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
- 스키마 변경 후 dev 볼륨 유지하려면 `docker compose -p vulnagent-dev exec -T db sh -c 'mysql...' < db/0X.sql` 로 수동 적용(initdb 는 빈 볼륨만 실행).
- Windows git-bash 에서 컨테이너에 절대경로 전달 시 `MSYS_NO_PATHCONV=1` 접두.
- 변경 후 `./tests/smoke.sh` 로 회귀 확인. PHP 는 `php -l`, 쉘은 `bash -n`.

## 리뷰 체크
바꾸기 전에 자문한다:
1. 이거 지금 진짜 필요한가? (YAGNI)
2. 더 단순한 방법은? (KISS)
3. 이미 있는 헬퍼로 되나? (DRY)
4. 한 책임만 지는가, 기존 코드 수정 없이 확장되나? (SOLID)

## 작업 파이프라인
기능·수정 작업은 main 에서 브랜치를 따서 진행하고 PR 로 병합한다.
- 흐름: `git switch -c <브랜치>` → 구현 → 검증 게이트 → 커밋 → push → PR.
- 브랜치 이름은 `feat/`·`fix/`·`chore/` 접두사를 쓴다.

## 가드레일 (강제)
- **main 직접 commit/push 금지** — 항상 작업 브랜치 경유 후 PR 로 병합. (`.claude/hooks/block-main-push.sh` 가 차단)
- **검증 게이트**: `php -l` + `bash -n` + `tests/smoke.sh` 통과 전 커밋/PR 금지. 상태 보고 시 실행한 검증 명령·결과를 증거로 첨부.
- `--no-verify` 등 hook 우회 명령 금지. `.env`/`secrets/*.txt` 커밋 금지.
- 관련 없는 파일 수정·요청 범위 초과 리팩터 금지. 읽지 않은 코드 기반 추정 금지.

## 응답 스타일
- 한글, 결론 먼저, 2~5문장, 이모지 남발 금지. 불명확하면 1줄로 추론을 밝히고 진행하되, 되돌리기 어려운 작업은 먼저 확인.
- 질문은 묶어서 한 번에. 상태 보고엔 증거(파일경로·커밋해시·검증결과) 동반.
