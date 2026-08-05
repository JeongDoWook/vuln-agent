-- SCA 라이선스 식별·관리 v1 — tb_package 에 license 컬럼 추가 + 라이선스 전용 사전집계 테이블 신설.
--   tb_package 는 db/01-schema.sql 의 tb_packages 가 20260726115611_pk_naming_unification.sql 로
--   리네임된 실제 테이블명이다(01-schema.sql 표기는 initdb 전용이라 기존 볼륨엔 반영되지 않는다).
--   멱등: information_schema 가드로 두 번 돌아도 안전하다(pk_naming_unification.sql 과 같은 패턴).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_package' AND COLUMN_NAME = 'license');
SET @s := IF(@c = 0, 'ALTER TABLE tb_package ADD COLUMN license VARCHAR(255) NULL AFTER vendor', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 언어 패키지(pip/npm/gem/composer/maven/nuget/cargo/go) 라이선스 위험도 사전집계.
--   tb_package_summary(OSV CVE 카탈로그 집계)와 같은 패턴 — OSV 커넥터 실행 시 갱신한다.
--   packages.php 40초 사고(무인덱스 재집계) 재발을 막으려고 화면은 이 요약만 읽고
--   tb_package 에 직접 라이선스 필터/KPI 쿼리를 걸지 않는다.
CREATE TABLE IF NOT EXISTS tb_package_license_summary (
  manager    VARCHAR(16)  NOT NULL,
  name       VARCHAR(255) NOT NULL,
  license    VARCHAR(255) NOT NULL,
  risk       VARCHAR(16)  NOT NULL DEFAULT 'unknown',  -- permissive | copyleft | unknown
  pkg_count  INT UNSIGNED NOT NULL DEFAULT 0,          -- 최신 스캔 기준 이 (매니저,이름,라이선스) 설치 건수
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (manager, name, license),
  KEY idx_plsum_risk (risk)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
