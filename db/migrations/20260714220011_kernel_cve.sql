-- 리눅스 커널은 **배포판이 아니라 업스트림(kernel.org)이 판정한다.**
--
--   문제: 커널 패키지는 배포판 버전 체계 밖에 있는 경우가 많다. 라즈베리파이 OS 의 커널은
--   `linux-image-6.18.34+rpt-rpi-2712` (origin: Raspberry Pi Foundation) 라서 데비안 트래커에도,
--   배포판 조치안(EVR)에도 없다. 매처는 서드파티 저장소 패키지를 "자동 판정 불가" 로 두므로
--   (버전 억제·트래커 억제를 모두 막는다 — 그렇게 안 하면 진짜 취약점을 숨긴다) 커널 CVE 가
--   통째로 남았다. 실측(raspberrypi5-00): LOW 2,069건 중 **702건이 커널 하나**였고, 그 중엔
--   커널 6.18 에 CVE-2004-0230(2004년 TCP 이슈) 같은 것도 섞여 있었다.
--
--   해답: 커널의 **정본 판정자는 kernel.org CNA** 다. 2024년부터 커널 팀이 직접 CVE 를 발행하고,
--   레코드마다 "어느 stable 시리즈의 어느 버전에서 고쳤는가" 를 준다.
--     {"version":"6.1.78","lessThanOrEqual":"6.1.*","status":"unaffected"}   ← 6.1.y 는 6.1.78 에서 수정
--     {"version":"6.5","status":"affected"}                                   ← 6.5 부터 취약(그 전은 무관)
--   uname 으로 잡은 **구동 커널의 업스트림 버전**(6.18.34)을 이 데이터와 대조하면, 배포판이
--   무엇이든(라즈베리·우분투 HWE·자체 빌드) 커널만은 정확히 판정된다.
--
--   억제 방향으로만 쓴다: 같은 스트림의 수정 버전 이상이면 "이미 포함됨". 배포판 백포트는
--   업스트림보다 **먼저** 고쳐질 수 있는데(6.12.43-1 에 6.12.50 의 수정을 백포트), 그 경우
--   우리는 억제하지 않고 남긴다 — 그쪽은 트래커/OVAL 이 이미 답한다. 보수적인 방향이다.
SET NAMES utf8mb4;

-- CVE 한 건의 업스트림 판정 축(메인라인 기준).
CREATE TABLE IF NOT EXISTS tb_kernel_cves (
  cve_id             VARCHAR(32) NOT NULL,
  introduced_version VARCHAR(32) NULL,   -- 이 메인라인 버전부터 취약(그 전 버전은 해당 없음)
  mainline_fixed     VARCHAR(32) NULL,   -- 메인라인 수정 버전(lessThanOrEqual: '*')
  created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (cve_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- stable 시리즈별 수정 버전. 구동 커널이 6.18.x 면 stream='6.18' 행만 본다.
CREATE TABLE IF NOT EXISTS tb_kernel_cve_fixes (
  cve_id        VARCHAR(32) NOT NULL,
  stream        VARCHAR(16) NOT NULL,   -- '6.1', '5.15' …
  fixed_version VARCHAR(32) NOT NULL,   -- '6.1.78'
  PRIMARY KEY (cve_id, stream)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 커넥터 등록. 스냅샷 tarball 하나(약 20MB)로 전체 레코드를 받는다 — 하루 한 번이면 충분하다.
INSERT INTO tb_feed_connectors (name, connector_type, connection_json, schedule_json, enabled, last_status)
SELECT '리눅스 커널 CNA(kernel.org)', 'kcve',
       JSON_OBJECT(),
       JSON_OBJECT('mode','interval','interval_minutes',1440), 1, 'never'
 WHERE NOT EXISTS (SELECT 1 FROM tb_feed_connectors WHERE connector_type = 'kcve');
