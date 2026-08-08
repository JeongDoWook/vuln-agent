-- 미조치 사유 + 승인자 — **최소 필드만**.
--   배경: 억제(tb_suppressed_findings)는 매처의 자동 판정이고, 이 표는 **사람이 남기는 메모**다.
--   "이 취약점은 왜 지금 고치지 않는가"와 "그 판단을 누가 언제 했는가"만 붙든다.
--   결재선·상태 전이·담당자·기한은 의도적으로 두지 않는다 — 본격 조치 워크플로는
--   export.php(읽기 API)로 외부 시스템에 넘기는 것이 이 제품의 포지셔닝이다.
SET NAMES utf8mb4;

-- 스캔마다 새로 발급되는 surrogate PK(tb_container.container_id, tb_finding.finding_id)로는
--   스캔 간 비교가 안 된다(server/public/finding_history.php 머리주석). 그래서 스캔이 바뀌어도
--   같은 대상을 가리키는 **자연키**(호스트 + 컨테이너 '이름' + CVE + 패키지명)로만 묶는다.
--   cid 는 컨테이너 이름이고, 호스트 자신은 '' 로 정규화한다(NULL 은 UNIQUE 에서 중복을 못 막는다).
CREATE TABLE IF NOT EXISTS tb_remediation_note (
  remediation_note_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  host_id     BIGINT UNSIGNED NOT NULL,
  cid         VARCHAR(255) NOT NULL DEFAULT '',   -- 컨테이너 이름. '' = 호스트 자신
  cve_id      VARCHAR(32)  NOT NULL,
  package     VARCHAR(255) NOT NULL,
  reason      TEXT         NOT NULL,              -- 미조치 사유(사람이 쓴 문장)
  approved_by BIGINT UNSIGNED NULL,               -- tb_user.user_id (FK 미설정 — 감사 관련 테이블 관례)
  approved_at DATETIME     NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted  TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at  DATETIME NULL,
  -- 한 조합에 메모 하나. 철회는 소프트삭제라 같은 조합이 다시 저장될 수 있어야 하므로
  --   UNIQUE 는 그대로 두고 저장은 ON DUPLICATE KEY UPDATE 로 되살린다.
  UNIQUE KEY uq_remediation_note (host_id, cve_id, package, cid),
  KEY idx_remediation_note_host (host_id, is_deleted),
  CONSTRAINT fk_remediation_note_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
