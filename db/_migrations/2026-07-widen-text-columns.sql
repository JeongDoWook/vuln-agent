-- vuln-agent : 긴 텍스트 컬럼 확장 (설명·KEV 노트)
-- ─────────────────────────────────────────────────────────────────────────
-- 운영 실측(2026-07-09):
--   tb_cves.summary        컬럼은 TEXT 인데 코드가 2,000자에서 잘랐다 → 2,817건 손상
--   tb_kev_catalog.note    컬럼이 VARCHAR(255) 라 250자에서 잘렸다   → 1건 손상
--
-- 코드 상한은 VG_TEXT_MAX(60,000자)로 통일했다(feeds.php). 그 값을 담으려면
-- TEXT(65,535 "바이트")로는 부족하다 — 한글이 섞이면 글자당 최대 3~4바이트다.
-- 그래서 summary 는 MEDIUMTEXT(16MB), note 는 TEXT 로 넓힌다.
--
-- summary 는 인덱스가 없다. note 도 없다. 확장 비용은 없다.
--
-- 이미 잘려 저장된 2,817건의 설명은 이 마이그레이션으로 복구되지 않는다.
-- NVD 전체 백필을 한 번 더 돌리면 vg_upsert_cve 의 COALESCE 갱신으로 채워진다.
--   docker compose -p vulnagent exec -T web php /var/www/html/bin/backfill_nvd.php
--
-- 적용(dev):
--   docker compose -p vulnagent-dev exec -T db sh -c \
--     'mysql -uroot -p$(cat /run/secrets/mysql_root_password) vulnagent' \
--     < db/_migrations/2026-07-widen-text-columns.sql
-- 적용(프로덕션): -p vulnagent 로 동일 실행.
-- ─────────────────────────────────────────────────────────────────────────
SET NAMES utf8mb4;

ALTER TABLE tb_cves        MODIFY COLUMN summary MEDIUMTEXT NULL;
ALTER TABLE tb_kev_catalog MODIFY COLUMN note    TEXT NULL;
