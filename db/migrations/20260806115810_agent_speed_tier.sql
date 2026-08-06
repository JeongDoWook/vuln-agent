-- 호스트별 에이전트 CPU 제한·JSON 조립 타임아웃을 4단계로 중앙 통제.
--   배경: ubuntu(fqdn='ubuntu') 호스트는 함대에서 dpkg 패키지 수가 가장 많아(2,237개)
--   collect_exposure() 의 파일→패키지 조회가 누적되면서 기본 CPU 10% 제한에 눌려
--   exposure 단계만 20분 넘게 걸리고, 그 뒤 PACKAGING_TIMEOUT=120초 워치독에 걸려
--   '지금 실행'을 몇 번을 눌러도 매번 실패했다. 호스트 사양 차이가 커서(SBC vs 데스크톱)
--   호스트별로 CPU%·조립타임아웃을 다르게 줄 수 있어야 한다. 4단계 → 값 매핑은 고정
--   4종이라 PHP(agent-poll.php) 쪽에 상수로 하드코딩한다(기존 고정 5종 피드 매핑과 동일 원칙).
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_host' AND COLUMN_NAME = 'agent_speed_tier');
SET @s := IF(@c = 0,
  "ALTER TABLE tb_host ADD COLUMN agent_speed_tier ENUM('very_fast','fast','normal','slow') NOT NULL DEFAULT 'normal'",
  'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 백필: 이번 조사로 원인이 확인된 ubuntu 호스트만 'fast'로 올린다.
--   라즈베리파이 5대는 저전력 SBC이고 실제 운영 워크로드(vuln-agent 자체 포함)를 함께 돌고
--   있어 CPU% 를 올리면 다른 서비스에 영향을 줄 수 있으므로 이번엔 건드리지 않고 'normal'
--   기본값을 유지한다(실측 근거 없이 올리지 않는다는 판단).
UPDATE tb_host SET agent_speed_tier = 'fast' WHERE fqdn = 'ubuntu' AND is_deleted = 0;
