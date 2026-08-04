ALTER TABLE tb_agent_command
  ADD COLUMN cancel_requested_at DATETIME NULL AFTER heartbeat_at,
  ADD COLUMN cancelled_at DATETIME NULL AFTER cancel_requested_at;
