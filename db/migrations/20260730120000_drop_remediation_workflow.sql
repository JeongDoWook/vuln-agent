-- 제품 범위를 취약점 탐지와 판정 근거 제공에 집중한다.
-- 담당자·상태·예외·내부 SLA를 추적하던 업무 워크플로 데이터는 더 이상 보존하지 않는다.
DROP TABLE IF EXISTS tb_remediation_case;
DROP TABLE IF EXISTS tb_remediation_cases;
DROP TABLE IF EXISTS tb_sla_policy;
DROP TABLE IF EXISTS tb_sla_policies;

DELETE FROM tb_role_permission WHERE menu_code = 'remediations';
