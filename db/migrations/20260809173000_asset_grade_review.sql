-- C/S/O 수동 확정에 사용하는 구조화 검토 메타데이터.
-- 정보공개법 제9조 해당 호는 판단 근거 중 하나이며, 법률이 C/S/O 등급 자체를 정의한다는 뜻이 아니다.
-- 호스트당 최신 검토 1행만 보관하고, 기존 tb_host.grade_reason 은 호환성을 위해 그대로 둔다.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_asset_grade_review (
  host_id BIGINT UNSIGNED NOT NULL,
  article9_item ENUM('1','2','3','4','5','6','7','8','NONE') NULL
    COMMENT '정보공개법 제9조 해당 호, NONE은 검토 결과 해당 없음',
  article9_reference VARCHAR(255) NULL COMMENT '조문·내부 해석 등 짧은 참조',
  business_category VARCHAR(100) NULL,
  data_category VARCHAR(100) NULL,
  owning_department VARCHAR(120) NULL,
  external_publication_state ENUM('PUBLIC','PARTIAL','NOT_PUBLIC') NULL,
  review_reference VARCHAR(255) NULL COMMENT '검토 문서·티켓 식별자 또는 위치(문서 내용 저장 금지)',
  next_review_date DATE NULL,
  is_stale TINYINT(1) NOT NULL DEFAULT 0 COMMENT '일괄 등급 변경 뒤 호스트별 재검토 필요 여부',
  review_version BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '동시 수정 충돌 검출용 버전',
  reviewed_by BIGINT UNSIGNED NULL,
  reviewed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (host_id),
  KEY idx_asset_grade_review_next (next_review_date),
  CONSTRAINT fk_asset_grade_review_host FOREIGN KEY (host_id)
    REFERENCES tb_host(host_id) ON DELETE CASCADE,
  CONSTRAINT fk_asset_grade_review_user FOREIGN KEY (reviewed_by)
    REFERENCES tb_user(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
