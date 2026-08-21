-- tb_host.host_uuid — 예측 가능한 v1 UUID 를 CSPRNG 기반 v4 로 교체한다.
--   왜: 앞선 20260821160831_host_uuid.sql 이 MySQL 의 UUID() 를 썼는데 이건 **버전1**이다
--   (시간 + clock_seq + node). dev 백필 실측에서 뒤 두 그룹 `907a-4261f8289c19` 가 전 행 동일,
--   앞 그룹은 시간순으로 근접 증가했다 — uuid 하나를 알면 나머지는 앞 몇 자리만 바꿔 찍어보면
--   되는 수준이라, "순번 PK 를 감춰 남의 자산을 못 찍어보게 한다" 는 이 컬럼의 목적이 무력화된다.
--   RANDOM_BYTES()(8.0.17+)는 SSL 라이브러리의 CSPRNG 다 — RAND() 는 섞지 않는다(PRNG 다).
--   v4 형식: 13번째 hex 를 '4'(버전), 17번째 hex 를 8|9|a|b(변형)로 고정한다.
--
--   왜 앞 파일을 고치지 않고 새 파일인가: 20260821160831 은 이미 적용된 상태(tb_schema_migrations
--   에 기록)라 그 파일을 고쳐도 dev 에는 반영되지 않는다 — 운영만 새 내용으로 도는 갈라짐이 생긴다.
--   빈 볼륨에서는 두 파일이 순서대로 돌아 v1 값이 한 번도 밖으로 나가지 않는다(1번 파일이 백필할
--   행 자체가 없고, 새 행이 들어오기 전에 이 파일이 DEFAULT 를 바꾼다).
--   멱등: DEFAULT 는 information_schema 로 현재 식을 확인한 뒤에만 ALTER, 재백필은 v4 가 아닌
--   행만 고른다. DROP 은 없다.
SET NAMES utf8mb4;

-- 생성식은 **한 곳에서만** 정의한다 — 재백필(UPDATE)과 새 행 기본값(DEFAULT)이 갈라지면
--   "옛 행과 새 행의 형식이 다르다" 가 조용히 생긴다. 문자열로 한 번 만들어 둘 다에 쓴다.
--   HEX(RANDOM_BYTES(2)) 는 4자라 앞 한 자를 버리고 뒤 3자만 쓴다(버전·변형 자리를 우리가 채운다).
SET @v4 := 'LOWER(CONCAT(
        HEX(RANDOM_BYTES(4)), ''-'',
        HEX(RANDOM_BYTES(2)), ''-'',
        ''4'', SUBSTR(HEX(RANDOM_BYTES(2)), 2), ''-'',
        SUBSTR(''89ab'', 1 + (CONV(SUBSTR(HEX(RANDOM_BYTES(1)), 1, 1), 16, 10) & 3), 1),
        SUBSTR(HEX(RANDOM_BYTES(2)), 2), ''-'',
        HEX(RANDOM_BYTES(6))))';

-- 1) 새 행 기본값을 v4 로. 컬럼이 없으면(1번 파일 전) 아무것도 하지 않는다 —
--    파일명 순서상 그럴 일은 없지만, 조건을 두어야 두 번 돌려도 안전하다.
--    DEFAULT 를 먼저 바꾼다: 재백필 도중 들어오는 삽입도 v4 로 받게 한다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_host'
             AND COLUMN_NAME  = 'host_uuid'
             AND UPPER(COALESCE(COLUMN_DEFAULT, '')) NOT LIKE '%RANDOM_BYTES%');
SET @s := IF(@c = 1,
             CONCAT('ALTER TABLE tb_host MODIFY COLUMN host_uuid CHAR(36) NOT NULL DEFAULT (', @v4, ')'),
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 2) 이미 v1 로 채워진 행을 다시 발급. **v4 가 아닌 행만** 고른다 — 무조건 전체를 갈아치우면
--    이미 밖으로 나간 uuid 까지 바뀐다(지금은 dev 뿐이라 실질 피해가 없지만, 운영에 얹힐 때
--    같은 파일이 그대로 돈다). 조건을 'v1' 이 아니라 '4가 아닌 것' 으로 두면 다른 경로로 들어온
--    옛 형식도 함께 걷힌다. UUID 는 행마다 평가되므로 한 문장으로 행마다 다른 값이 들어간다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_host'
             AND COLUMN_NAME  = 'host_uuid');
SET @s := IF(@c = 1,
             CONCAT('UPDATE tb_host SET host_uuid = ', @v4, " WHERE SUBSTRING(host_uuid, 15, 1) <> '4'"),
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
