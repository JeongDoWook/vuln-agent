-- 죽은 메뉴코드 'remediations' 권한 행 삭제.
--   remediations.php 는 vg_require_menu('findings') 로 가드하고 nav.php 도 perm=findings 라,
--   이 행들은 vg_can() 조회에 한 번도 안 걸린다(별도 메뉴로 만들려다 접은 흔적 —
--   20260724010000_precision_platform.sql 시드). 조치 관리는 packages·vendor·compliance 와
--   같이 취약점 메뉴 권한을 재사용하는 게 현재 설계다.
--   메뉴코드 정본은 vg_menus()(server/src/auth.php) 이고 거기에도 없다.
-- DELETE 는 그 자체로 멱등.
DELETE FROM tb_role_permission WHERE menu_code = 'remediations';
