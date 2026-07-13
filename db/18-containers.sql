-- 컨테이너 내부 인벤토리 — 호스트 스캔에서 빠져 통째로 미탐이던 영역.
--   에이전트가 컨테이너 rootfs(/proc/<pid>/root)의 패키지 DB 를 직접 읽어 보낸다.
--   컨테이너는 호스트와 **OS 가 다를 수 있다**(호스트 Rocky + 컨테이너 Debian). 그래서
--   생태계 판정을 호스트 기준으로 하면 안 되고, 컨테이너별 os_id/os_version 이 필요하다.
--   빈 볼륨은 이 파일(initdb), 기존 볼륨은 db/migrations/0014_containers.sql.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_containers (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id      BIGINT UNSIGNED NOT NULL,
  cid          VARCHAR(128) NOT NULL,       -- 컨테이너 이름. CLI 가 없으면 ns-<namespace 번호>
  name         VARCHAR(255) NULL,
  image        VARCHAR(255) NULL,
  os_id        VARCHAR(64)  NULL,           -- debian | ubuntu | alpine | rocky …
  os_version   VARCHAR(64)  NULL,
  manager      VARCHAR(16)  NULL,           -- dpkg | apk | rpm (빈 값 = 패키지 DB 를 못 읽음)
  pkg_count    INT NOT NULL DEFAULT 0,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_container (scan_id, cid),
  KEY idx_container_scan (scan_id),
  INDEX idx_container_is_deleted (is_deleted),
  CONSTRAINT fk_container_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 이 패키지/취약점이 어느 컨테이너 것인지. **0 = 호스트 자신**.
--   NULL 이 아니라 0 을 쓰는 이유: MySQL 유니크 키는 NULL 을 중복 허용한다. tb_findings 의
--   유니크 키에 container_id 가 들어가야 하는데(호스트와 컨테이너에 같은 패키지가 있으면
--   서로 덮어쓴다), NULL 이면 호스트 finding 이 중복 삽입된다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_packages' AND COLUMN_NAME = 'container_id');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_packages ADD COLUMN container_id BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER scan_id',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_findings' AND COLUMN_NAME = 'container_id');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_findings ADD COLUMN container_id BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER scan_id',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 유니크 키에 container_id 를 포함시킨다. 예전 키는 (scan_id, cve_id, package_name) 이라
-- 호스트의 openssl 과 컨테이너의 openssl 이 같은 CVE 로 충돌해 서로 덮어썼다.
SET @k := (SELECT COUNT(*) FROM information_schema.STATISTICS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_findings'
             AND INDEX_NAME = 'uq_find' AND COLUMN_NAME = 'container_id');
SET @s := IF(@k = 0, 'ALTER TABLE tb_findings DROP INDEX uq_find', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s := IF(@k = 0,
             'ALTER TABLE tb_findings ADD UNIQUE KEY uq_find (scan_id, container_id, cve_id, package_name)',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
