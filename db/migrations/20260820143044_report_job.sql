-- AI 보고서 작업(job) 추적 — 외부 보고서 API(작업큐)에 맡긴 일의 우리 쪽 대장(臺帳).
--
--   보고서 본문을 만드는 것은 외부 FastAPI + 워커다(POST /jobs/ 로 만들고 GET /jobs/{id}
--   로 상태를 본다). 그 API 는 자기 큐만 알 뿐 "누가 언제 무엇을 시켰나" 를 우리 화면에
--   돌려주지 못하고, 인증도 없다. 그래서 요청 사실·요청자·마지막으로 본 상태를 여기에
--   남긴다 — 이 표가 있어야 호스트 상세가 새로고침 뒤에도 진행 중인 job 을 이어서 보이고,
--   과거 이력을 목록으로 그린다.
--
--   외부가 정본, 이 표는 그 사본이다. status/result 는 폴링할 때마다 덮어쓴다.
--   status 문자열은 외부 어휘를 그대로 담는다 — 실측된 값이 'SUCCESS' 하나뿐이라
--   우리가 어휘를 정의할 근거가 없다. "완료로 볼 값 / 실패로 볼 값" 의 판단은
--   server/src/report_job.php 상수 한 곳이 갖고, 모르는 값은 진행 중으로 읽는다.
--
--   is_deleted 를 두지 않는다 — 이 표에는 삭제 경로가 없다(사람이 지우는 화면이 없고,
--   tb_finding_status 와 같은 판단이다). 호스트가 하드 삭제되면 FK CASCADE 로 함께 지워진다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_report_job (
  report_job_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id         BIGINT UNSIGNED NOT NULL,
  -- 외부 API 의 job id. 우리 PK 와 다른 값이라 따로 갖는다(외부는 자기 순번으로 발급한다).
  external_job_id BIGINT UNSIGNED NOT NULL,
  status          VARCHAR(32)  NOT NULL DEFAULT 'PENDING' COMMENT '외부 API 가 준 상태 문자열 원문',
  -- 지금은 "Job 4 completed" 같은 더미 문자열이고, 나중에 AI 본문이 들어온다.
  --   형식이 정해지지 않았으므로 화면은 plain text 로만 그린다(vg_h 이스케이프).
  result          MEDIUMTEXT   NULL,
  error_message   VARCHAR(1000) NULL COMMENT '외부 API 의 error_message. 우리 내부 예외 원문은 넣지 않는다',
  requested_user_id BIGINT UNSIGNED NULL COMMENT '생성을 누른 사람. 계정이 지워져도 이력은 남긴다',
  external_created_at  DATETIME NULL,
  external_finished_at DATETIME NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (report_job_id),
  -- 호스트 상세의 "이 자산의 보고서 이력(최신순)" 이 타는 인덱스. AUTO_INCREMENT PK 라
  --   report_job_id 역순이 곧 생성 최신순이고, 같은 값으로 정렬까지 인덱스가 덮는다.
  KEY idx_report_job_host (host_id, report_job_id),
  CONSTRAINT fk_report_job_host FOREIGN KEY (host_id)
    REFERENCES tb_host(host_id) ON DELETE CASCADE,
  CONSTRAINT fk_report_job_user FOREIGN KEY (requested_user_id)
    REFERENCES tb_user(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
