-- tb_host.host_uuid — 외부 노출 전용 식별자.
--   왜: 외부 AI 보고서 API 에 자산을 순번 PK(host_id)로 넘기고 있었고, 외부 소비자가 UUID 를
--   요구했다. 화면 URL(host.php?id=7)에도 순번이 그대로 드러난다.
--   PK 는 교체하지 않는다 — host_id 를 참조하는 FK 가 17개이고 PHP 361곳이 이 값을 쓴다.
--   InnoDB 는 PK 가 클러스터드 인덱스라 랜덤 UUID 를 PK 로 두면 삽입이 흩어지고 모든 세컨더리
--   인덱스에 36바이트가 복제된다. 내부 조인·FK·쿼리는 전부 host_id 그대로 두고, host_uuid 는
--   **바깥으로 나가는 자리**(외부 API payload, 화면 진입 URL)에서만 쓴다.
--   멱등: information_schema 로 존재 확인 후에만 ALTER. DROP 은 없다 — 컬럼 추가라
--   이 컬럼을 모르는 옛 브랜치 코드도 그대로 돈다(공용 dev DB 안전).
SET NAMES utf8mb4;

-- 1) 컬럼 추가. 일단 NULL 허용으로 — 기존 행을 백필한 뒤에 NOT NULL 로 조인다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_host'
             AND COLUMN_NAME  = 'host_uuid');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_host ADD COLUMN host_uuid CHAR(36) NULL AFTER host_id',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 2) 기존 행 백필. UUID() 는 행마다 평가되므로 한 문장으로 행마다 다른 값이 들어간다.
UPDATE tb_host SET host_uuid = UUID() WHERE host_uuid IS NULL;

-- 3) NOT NULL + 새 행 자동 채움(DEFAULT (UUID()) 는 MySQL 8.0.13+ 의 표현식 디폴트다 —
--    dev·운영 모두 8.0.46 임을 SELECT VERSION() 으로 확인했다). 삽입부가 uuid 를 안 넣어도
--    DB 가 채우므로 누락 경로가 남지 않는다.
SET @n := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_host'
             AND COLUMN_NAME  = 'host_uuid'
             AND IS_NULLABLE  = 'YES');
SET @s := IF(@n = 1,
             'ALTER TABLE tb_host MODIFY COLUMN host_uuid CHAR(36) NOT NULL DEFAULT (UUID())',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 4) 유니크 — 외부에 주는 식별자라 중복은 곧 다른 자산을 가리키는 사고다.
SET @i := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME   = 'tb_host'
             AND INDEX_NAME   = 'uq_host_uuid');
SET @s := IF(@i = 0,
             'ALTER TABLE tb_host ADD UNIQUE KEY uq_host_uuid (host_uuid)',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
