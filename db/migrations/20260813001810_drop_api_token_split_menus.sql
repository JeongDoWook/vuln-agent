-- API 토큰 인증 폐지 + 권한 메뉴코드 분할.
--   1) tb_api_token 삭제 — export.php·sbom.php 는 웹 로그인 세션 인증으로 전환했고
--      결과를 가져가는 외부 시스템은 DB 를 직접 조회하기로 해서 토큰 체계가 필요 없어졌다.
--      발급 화면(api-tokens.php)·검증 헬퍼(src/apitoken.php)도 함께 삭제했다.
--   2) 메뉴코드 'apitokens' 권한 행 정리 — vg_menus() 에서 사라진 코드다.
--   3) findings 하나가 사이드바 링크 6개(탐지 결과·컴플라이언스·카탈로그 4종)를 열던 것을
--      findings/compliance/catalog 로 쪼갰다. 기존 배포본에서 operator/user 가 보던 화면을
--      업데이트 순간 잃지 않도록, 기존 findings 행의 allowed 값을 새 코드에 그대로 복제한다.
-- 전부 멱등: DROP/DELETE 는 그 자체로, 복제는 INSERT IGNORE + UNIQUE(role, menu_code) 로.

DROP TABLE IF EXISTS tb_api_token;

DELETE FROM tb_role_permission WHERE menu_code = 'apitokens';

-- 파생 테이블로 한 번 감싼다 — INSERT ... SELECT 가 대상 테이블을 직접 읽지 않게 한다.
INSERT IGNORE INTO tb_role_permission (role, menu_code, allowed)
SELECT f.role, 'compliance', f.allowed
  FROM (SELECT role, allowed FROM tb_role_permission
         WHERE menu_code = 'findings' AND is_deleted = 0) f;

INSERT IGNORE INTO tb_role_permission (role, menu_code, allowed)
SELECT f.role, 'catalog', f.allowed
  FROM (SELECT role, allowed FROM tb_role_permission
         WHERE menu_code = 'findings' AND is_deleted = 0) f;
