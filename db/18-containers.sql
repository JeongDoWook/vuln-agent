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

-- 이 패키지/취약점이 어느 컨테이너 것인지(`container_id`)는 **01-schema.sql · 02-matcher.sql 이
-- 처음부터 최종 형태로 정의한다.** 여기서 나중에 ALTER 로 얹지 않는다. **0 = 호스트 자신**이며,
-- NULL 이 아니라 0 을 쓰는 이유는 MySQL 유니크 키가 NULL 중복을 허용하기 때문이다(NULL 이면
-- 호스트 finding 이 중복 삽입된다). 기존 볼륨은 db/migrations/0014_containers.sql 이 얹는다.
--
-- 왜 여기서 걷어냈나(실측): 예전엔 이 파일이 `tb_findings` 의 uq_find 를 DROP 후 재생성했는데,
-- 나중에 20260718000026_drop_idx_find_scan.sql 이 initdb 에서도 idx_find_scan 을 없애면서
-- uq_find 가 fk_find_scan 이 쓰는 **유일한** 인덱스가 됐다. 그래서 빈 볼륨 initdb 가
--   ERROR 1553 (HY000) at line 53: Cannot drop index 'uq_find': needed in a foreign key constraint
-- 로 죽어 **DB 컨테이너가 아예 뜨지 않았다**(mysql:8.0 entrypoint 는 initdb 실패 시 exit 1).
-- 기존 볼륨은 0014 를 idx_find_scan 이 살아 있던 시절에 이미 적용해 무사했기에 안 드러났다.
