-- 탐지 결과의 **조치 상태** — 상태 하나와 메모 한 줄만.
--   배경: 20260730120000_drop_remediation_workflow.sql 이 tb_remediation_cases·tb_sla_policies 를
--   지우면서 담당자·결재선·기한·예외만료까지 통째로 사라졌다. 이번에 되살리는 것은
--   **상태뿐**이다 — 담당자 배정·결재선·재점검 확인은 만들지 않는다(YAGNI).
--   "왜 지금 안 고치는가"(사유 + 승인자)는 이미 tb_remediation_note 가 갖고 있고, 이 표는
--   "지금 어디까지 왔는가"만 갖는다. 둘을 한 표로 합치지 않는 이유: 사유는 사람이 쓰는
--   문서고 상태는 목록의 필터 축이라 수명·갱신 빈도가 다르다.
SET NAMES utf8mb4;

-- 키는 tb_remediation_note 와 **같은 자연키**다: (host_id, 컨테이너 이름, cve_id, 패키지명).
--   tb_finding.finding_id·tb_container.container_id 는 스캔마다 새로 발급되는 surrogate PK 라
--   스캔이 바뀌면 같은 대상을 못 가리킨다(server/public/finding_history.php 머리주석).
--   컨테이너 이름은 호스트 자신을 '' 로 정규화한다 — NULL 은 UNIQUE 에서 중복을 못 막는다.
-- 행이 없는 조합은 OPEN(미조치)으로 읽는다. 탐지 결과 전건(3.8만)에 행을 만들지 않는다.
CREATE TABLE IF NOT EXISTS tb_finding_status (
  finding_status_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id           BIGINT UNSIGNED NOT NULL,
  container_ref     VARCHAR(255) NOT NULL DEFAULT '',   -- 컨테이너 이름. '' = 호스트 자신
  cve_id            VARCHAR(32)  NOT NULL,
  package_name      VARCHAR(255) NOT NULL,
  -- OPEN(미조치) · IN_PROGRESS(조치중) · DONE(완료) · EXCEPTED(예외). 라벨은 DB 에 두지 않는다 —
  --   server/src/format.php 의 vg_finding_status_labels() 가 정본이다.
  status            VARCHAR(20)  NOT NULL DEFAULT 'OPEN',
  note              VARCHAR(1000) NULL,
  updated_user_id   BIGINT UNSIGNED NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (finding_status_id),
  -- 한 조합에 상태 하나. 저장은 ON DUPLICATE KEY UPDATE 로 덮어쓴다.
  UNIQUE KEY uq_finding_status (host_id, container_ref, cve_id, package_name),
  -- 목록의 조치 상태 필터가 타는 인덱스.
  KEY idx_finding_status_status (status),
  CONSTRAINT fk_finding_status_host FOREIGN KEY (host_id)
    REFERENCES tb_host(host_id) ON DELETE CASCADE,
  CONSTRAINT fk_finding_status_user FOREIGN KEY (updated_user_id)
    REFERENCES tb_user(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
