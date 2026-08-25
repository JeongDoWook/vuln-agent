## 무엇을 · 왜

<!-- 이 PR이 무엇을 바꾸는지, 왜 필요한지 짧게 -->

## 검증

<!-- 실제로 돌린 것만 체크한다. -->

- [ ] `php -l` / `bash -n` 통과
- [ ] `./tests/ui_lint.sh` 통과 (화면·CSS 를 건드렸다면)
- [ ] `./tests/smoke.sh <BASE>` 통과 (`server/`·`db/`·`tests/` 를 건드렸다면)
- [ ] `db/migrations/`에 새 파일을 추가했다면 파일명이 `YYYYMMDDHHMMSS_이름.sql` 형식

## 관련 이슈

<!-- 있으면: Closes #123 -->
