-- 커널 재부팅 판정 — 커널을 패치해도 **재부팅 전까지는 옛 커널이 돌고 있다.**
--   지금 매처는 설치된 최신 커널 버전으로 "이미 패치됨" 처리해 커널 CVE 를 억제한다.
--   실제로는 취약한 커널이 실행 중이므로 미탐이다(4단계의 "재시작 필요"와 같은 문제, 커널판).
--   에이전트는 running_kernel/installed_kernels 를 예전부터 보냈는데 서버가 버리고 있었다.
--   멱등: information_schema 확인 후에만 ADD COLUMN.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'running_kernel');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN running_kernel VARCHAR(255) NULL AFTER kernel',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'kernel_latest');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN kernel_latest VARCHAR(255) NULL AFTER running_kernel',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_scans' AND COLUMN_NAME = 'kernel_reboot_needed');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_scans ADD COLUMN kernel_reboot_needed TINYINT(1) NOT NULL DEFAULT 0 AFTER kernel_latest',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
