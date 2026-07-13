-- 변경 추적 — "바뀔 때만 스냅샷".
--   지금까지는 수집할 때마다 패키지 전량을 새 스캔으로 다시 저장했다. 대부분은 직전과
--   똑같은 내용이라 낭비다(실측: 호스트 1대 160패키지 × 매시간 = 월 11만 행).
--   → 수집 내용의 해시가 직전과 같으면 새 스캔을 만들지 않고 수집시각만 갱신한다.
--     그러면 스캔 목록 자체가 "변경 시점" 목록이 된다.
--   → 달라졌을 때만 무엇이 바뀌었는지 tb_pkg_changes 에 남긴다.
--   빈 볼륨은 이 파일(initdb), 기존 볼륨은 db/migrations/0013_change_tracking.sql.
SET NAMES utf8mb4;

-- 스캔 내용 해시 (패키지·언어패키지·OS/커널·노출·재시작필요). PID 는 넣지 않는다 —
-- 재부팅·재시작마다 바뀌어서 넣으면 매번 "변경됨"이 되어 스냅샷을 매번 찍게 된다.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'content_hash');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN content_hash CHAR(64) NULL AFTER package_family',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

CREATE TABLE IF NOT EXISTS tb_pkg_changes (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id      BIGINT UNSIGNED NOT NULL,
  scan_id      BIGINT UNSIGNED NOT NULL,     -- 변화가 확인된 스캔
  manager      VARCHAR(16)  NULL,            -- rpm | dpkg | pip | npm | gem | composer
  package_name VARCHAR(255) NOT NULL,
  change_type  VARCHAR(16)  NOT NULL,        -- installed | removed | upgraded | downgraded
  old_version  VARCHAR(255) NULL,
  new_version  VARCHAR(255) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted   TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at   DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_pkgchg (scan_id, manager, package_name),
  KEY idx_pkgchg_host (host_id, id),
  KEY idx_pkgchg_scan (scan_id),
  INDEX idx_pkgchg_is_deleted (is_deleted),
  CONSTRAINT fk_pkgchg_host FOREIGN KEY (host_id) REFERENCES tb_hosts(id) ON DELETE CASCADE,
  CONSTRAINT fk_pkgchg_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
