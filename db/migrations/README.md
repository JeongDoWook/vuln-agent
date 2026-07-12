# db/migrations — 자동 적용 마이그레이션

`deploy/migrate.sh` 가 여기 있는 `NNNN_이름.sql` 을 **번호 순서로**, **아직 안 든 것만**
적용하고 `tb_schema_migrations` 에 기록한다. `compose_runner.sh up` 과 `update.sh` 가
자동 호출하므로, 스키마를 바꾸려면 여기에 파일 하나만 추가하면 된다(수동 apply 불필요).

## 규칙
- 파일명: `0002_무엇.sql`, `0003_...` — 4자리 번호로 정렬 순서 보장.
- **멱등하게** 작성한다(`CREATE TABLE IF NOT EXISTS`, `INSERT IGNORE`, `ADD COLUMN` 은
  이미 있으면 실패하므로 주의). 러너는 성공 시 1회만 기록하지만, 안전을 위해 재실행해도
  깨지지 않게 쓴다.
- 최상위 `db/*.sql` 은 **빈 볼륨 initdb 전용**(기본 스키마). 증분 변경은 여기에 둔다.

## 왜 `db/_migrations/` 와 분리했나
`db/_migrations/` 10개는 과거에 손으로 적용했고 일부는 재실행 시 에러난다(예: `ADD INDEX`).
러너가 그걸 다시 돌리지 않도록 신규 폴더를 나눴다. `_migrations/` 는 역사 기록으로 남겨둔다.
