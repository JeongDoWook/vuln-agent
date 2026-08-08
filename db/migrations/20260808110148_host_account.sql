-- 계정 인벤토리 — 호스트의 "실제 계정 목록"을 스캔별로 보관한다.
--   지금까지 이 제품은 계정 "설정 정책"(login.defs·PAM·sshd)만 봤고 계정 자체는 안 봤다.
--   그래서 ISMS-P 2.5.1(사용자 계정 관리)·2.5.2(공용 계정)·2.5.5(특수 권한)·2.5.6(권한 검토)와
--   N2SF AC 계정관리 통제가 전부 공백이었다. 이 테이블이 그 근거 데이터다.
--
--   **패스워드 해시는 저장하지 않는다.** 에이전트도 보내지 않는다(정책 필드와 잠금 여부만).
--
--   NULL 의 의미가 중요하다 — 이 제품은 "판정 불가(NA)"를 "정상(PASS)"으로 위장하지 않는다.
--     is_locked / pw_* / expire_date : NULL = /etc/shadow 를 못 읽음(비-root 실행) → NA
--     is_sudoer                      : NULL = sudoers·sudo 그룹을 못 읽음 → NA
--     never_logged_in                : NULL = lastlog 미수집 → NA, 1 = 한 번도 로그인 없음
--
--   scan_id 를 남겨 두면 나중에 스냅샷 diff(전회 대비 계정 증감)가 가능하다 — 이번 범위 밖.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS tb_host_account (
  host_account_id  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id          BIGINT UNSIGNED NOT NULL,
  scan_id          BIGINT UNSIGNED NOT NULL,
  username         VARCHAR(64)  NOT NULL,
  uid              INT NULL,
  gid              INT NULL,
  shell            VARCHAR(128) NULL,
  home             VARCHAR(255) NULL,
  is_locked        TINYINT(1) NULL,           -- 1=잠김(해시가 !/* 로 시작), NULL=shadow 미수집
  is_sudoer        TINYINT(1) NULL,           -- 1=sudo 권한 보유, NULL=sudoers·그룹 미수집
  is_system        TINYINT(1) NOT NULL DEFAULT 0,  -- UID 임계값 미만 = 시스템 계정
  pw_last_change   DATE NULL,
  pw_min_days      INT NULL,
  pw_max_days      INT NULL,
  pw_warn_days     INT NULL,
  pw_inactive_days INT NULL,
  expire_date      DATE NULL,
  last_login_at    DATETIME NULL,             -- 에이전트 자기신고(lastlog) — 서버 수신시각은 received_at
  never_logged_in  TINYINT(1) NULL,
  collected_at     DATETIME NULL,             -- 에이전트가 신고한 수집 시각
  received_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,   -- 중앙이 실제로 받은 시각
  created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted       TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at       DATETIME NULL,
  PRIMARY KEY (host_account_id),
  UNIQUE KEY uq_host_account (scan_id, username),
  KEY idx_host_account_host (host_id, username),
  CONSTRAINT fk_host_account_host FOREIGN KEY (host_id) REFERENCES tb_host(host_id) ON DELETE CASCADE,
  CONSTRAINT fk_host_account_scan FOREIGN KEY (scan_id) REFERENCES tb_scan(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
