SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tb_hosts'
             AND COLUMN_NAME = 'perimeter_firewalled');
SET @s := IF(@c = 0,
             'ALTER TABLE tb_hosts ADD COLUMN perimeter_firewalled TINYINT(1) NOT NULL DEFAULT 0 AFTER os_version',
             'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

CREATE TABLE IF NOT EXISTS tb_host_ext_ports (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id BIGINT UNSIGNED NOT NULL,
  port INT UNSIGNED NOT NULL,
  proto VARCHAR(16) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_host_ext_port (host_id, port, proto),
  INDEX idx_host_ext_ports_is_deleted (is_deleted),
  CONSTRAINT fk_host_ext_ports_host FOREIGN KEY (host_id) REFERENCES tb_hosts(id) ON DELETE CASCADE,
  CONSTRAINT chk_host_ext_ports_port CHECK (port BETWEEN 1 AND 65535)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
