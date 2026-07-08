-- vuln-agent 실행 프로세스 인벤토리 — "설치만 vs 실행중 vs 사용중" 정밀 구분
--   에이전트 runtime.processes(포트 없어도 실행 중이면 잡음) 를 저장.
--   매처가 tb_exposures(포트) + tb_processes(실행/로드) 를 합쳐 런타임 상태를 판정.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_processes (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id     BIGINT UNSIGNED NOT NULL,
  pid         INT NULL,
  comm        VARCHAR(255) NULL,
  username    VARCHAR(64)  NULL,
  exe_pkg     VARCHAR(255) NULL,        -- 프로세스 바이너리의 소속 패키지(=실행중)
  loaded_pkgs TEXT NULL,                -- 로드한 .so 소속 패키지(쉼표) (=사용중)
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted  TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at  DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_proc_scan (scan_id),
  KEY idx_proc_exe (exe_pkg),
  INDEX idx_processes_is_deleted (is_deleted),
  CONSTRAINT fk_proc_scan FOREIGN KEY (scan_id) REFERENCES tb_scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 각 finding 의 런타임 상태(가장 강한 신호): EXTERNAL/LISTENING/RUNNING/LOADED/INSTALLED
-- (MySQL 8 은 ADD COLUMN IF NOT EXISTS 미지원 → 초기화 시 1회 실행 전제)
ALTER TABLE tb_findings
  ADD COLUMN runtime_status VARCHAR(16) NULL AFTER exposure_scope;
