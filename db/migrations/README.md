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

## 최상위 `db/*.sql` 과의 차이
`db/01~13*.sql` 은 **빈 볼륨 initdb 전용**이라 이미 데이터가 든 볼륨에는 적용되지 않는다.
그래서 스키마를 바꿀 땐 두 곳 모두 손댄다 — 최상위 파일(새 볼륨용)과 여기(기존 볼륨용).
